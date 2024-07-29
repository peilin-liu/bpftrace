#!/usr/bin/env python
# coding: utf-8

import os
import sys
from socket import htons, ntohs, htonl, ntohl, inet_ntop, inet_pton, AF_INET, AF_INET6
from bcc import BPF
import ctypes as ct
from struct import pack
import argparse
from datetime import datetime
import signal

bpf_prog='''
#include <uapi/linux/tcp.h>
#include <net/inet_sock.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct connect_evt_t {
    u64 pid;
    u32 saddr;
    u32 daddr;
	u16	sport;
	u16	dport;
    u32 live_time;
    u32 idle_time;
    char comm_name[64];
};

struct conn_active_status{
    __u64 start:56; //ms
    __u8  res1:8;
    __u64 last_active:56; //ms
    __u8  res2:8;
};
BPF_HASH(conn_active_map, u64, struct conn_active_status);

BPF_PERF_OUTPUT(connection_evt);

#define member_address(source_struct, source_member)            \
    ({                                                          \
        void* __ret;                                            \
        __ret = (void*) (((char*)source_struct) + offsetof(typeof(*source_struct), source_member)); \
        __ret;                                                  \
    })

#define member_read(destination, source_struct, source_member)  \
  do{                                                           \
    bpf_probe_read(                                             \
      destination,                                              \
      sizeof(source_struct->source_member),                     \
      member_address(source_struct, source_member)              \
    );                                                          \
  } while(0);

int kretp_inet_csk_accept(struct pt_regs *ctx){
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    if (!newsk){
        return 0;
    }

    struct inet_sock *inet = inet_sk(newsk);
    struct ipv6_pinfo	*pinet6;
    member_read(&pinet6, inet, pinet6);
    if (pinet6){
        return 0;
    }
    __be32 local_addr; __be16 local_port;
    member_read(&local_addr, inet, inet_saddr);
    member_read(&local_port, inet, inet_sport);

    if(PORT_FILTER != local_port){
        return 0;
    }

    //get remote
    struct sock_common sock_comm;
    member_read(&sock_comm, newsk, __sk_common);

    struct conn_active_status conn_active_s = {};
    conn_active_s.last_active = bpf_ktime_get_ns()/1000/1000;
    conn_active_s.start = conn_active_s.last_active;
    conn_active_map.update((u64*)&newsk, &conn_active_s);

    bpf_trace_printk("inet_csk_accept, accept new socket, %u:%d at port %d\\n",
        sock_comm.skc_daddr, sock_comm.skc_dport, local_port);
    return 0;
}

int tp_sock_inet_sock_set_state(struct tracepoint__sock__inet_sock_set_state *args){
    struct sock* sk = (struct sock *)args->skaddr;
    __u32 saddr = *(__u32*)args->saddr;
    __u32 daddr = *(__u32*)args->daddr;
    __u16 sport = bpf_htons(args->sport);
    __u16 dport = bpf_htons(args->dport);

    if (args->protocol != IPPROTO_TCP) { return 0;}

    if (args->family != AF_INET) { return 0;} //only ipv4

    if (args->newstate != TCP_CLOSE
        && args->newstate != TCP_TIME_WAIT
        && args->newstate != TCP_CLOSE_WAIT) 
    { 
        return 0;
    }
    
    struct conn_active_status * conn_active_s = (struct conn_active_status*)conn_active_map.lookup((u64*)&sk);
    if(!conn_active_s) { return 0;}
    conn_active_map.delete((u64*)&sk);

    if(args->newstate == TCP_CLOSE_WAIT){
        return 0;
    }
    
    __u64 now = bpf_ktime_get_ns()/1000/1000;
    __u64 idle_time = now - conn_active_s->last_active;
    __u64 live_time = now - conn_active_s->start;
    if ( idle_time > (MIN_IDLE_TIME) || live_time < 10) { return 0; }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32; 
    struct connect_evt_t evt = {};
    
    evt.pid = pid;
    evt.saddr = saddr; evt.sport = sport;
    evt.daddr = daddr; evt.dport = dport;
    evt.live_time = live_time;
    evt.idle_time = idle_time;

    bpf_get_current_comm(&evt.comm_name, sizeof(evt.comm_name));
    connection_evt.perf_submit((void*)args, &evt, sizeof(evt));
    bpf_trace_printk("on connect keepalive error, idle_time %ld < MIN_IDLE_TIME(ms), sport %d, newstate %d\\n",
        idle_time, args->saddr, args->newstate);
    return 0;
}

static inline int update_sk_rw_time(struct sock *sk, int rw_flag){
    struct conn_active_status * conn_active_s = (struct conn_active_status*)conn_active_map.lookup((u64*)&sk);
    if(!conn_active_s) { return 0;} 
    conn_active_s->last_active = bpf_ktime_get_ns()/1000/1000;
    bpf_trace_printk("update_sk_rw_time, %p, rw_flag %d\\n",
        sk, rw_flag); 
    return 0;
}

int kp_tcp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int event_flags, int *addr_len){
    return update_sk_rw_time(sk, 0);
}

int kp_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size){
    return update_sk_rw_time(sk, 1);
}

'''
class ConnectionEvt(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("live_time", ct.c_uint32),
        ("idle_time", ct.c_uint32),
        ("comm_name", ct.c_char * 64),
    ]


def event_handler(cpu, data, size):
    event = ct.cast(data, ct.POINTER(ConnectionEvt)).contents
    now = datetime.now()
    formatted_datetime = now.strftime("%D %H:%M:%S.%f")[:-3]

    saddr = inet_ntop(AF_INET, pack("=I", event.saddr))
    daddr = inet_ntop(AF_INET, pack("=I", event.daddr))

    flow = "%s:%s -> %s:%s" % (daddr, ntohs(event.dport), saddr, ntohs(event.sport))
    print(
        "%-23s %-42s %-13.1f %-13.1f %-24s" 
        % (
            formatted_datetime,
            flow,
            event.idle_time/1000.0,
            event.live_time/1000.0,
            event.comm_name
        )
    )


def attch_all_probe():
    b.attach_kretprobe(event="inet_csk_accept", fn_name="kretp_inet_csk_accept")
    b.attach_tracepoint(
        tp="sock:inet_sock_set_state", fn_name="tp_sock_inet_sock_set_state"
    )

    b.attach_kprobe(event="tcp_recvmsg", fn_name="kp_tcp_recvmsg")
    b.attach_kprobe(event="tcp_sendmsg", fn_name="kp_tcp_sendmsg")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", dest="port", type=int, required=True, default=0)
    parser.add_argument("--min_idle", dest="min_idle", type=int, required=True, default=0)
    args = parser.parse_args()

    if args.port <= 0:
        print('port error: %d' % args.port)
        exit(1)

    if args.min_idle <= 0:
        print('min_idle error: %d' % args.min_idle)
        exit(1)

    bpf_text = bpf_prog.replace("PORT_FILTER", str(htons(args.port)))
    bpf_text = bpf_text.replace("MIN_IDLE_TIME", str(args.min_idle * 1000))

    b = BPF(text=bpf_text)
    b["connection_evt"].open_perf_buffer(event_handler)
    attch_all_probe()
    

    def do_clean():
        b.cleanup()
        os._exit(0)

    def signal_handler(signum, frame):
        do_clean()

    signal.signal(signal.SIGTERM, signal_handler)
    print(
        "%-23s %-42s %-13s %-13s %-24s"
        % (
            "TIMESTAMP",
            "SOCKINFO",
            "IDLE_TIME",
            "LIVE_TIME",
            "COMMON_NAME"
        )
    )

    while 1:
        try:
            b.perf_buffer_poll(10)
        except KeyboardInterrupt:
            do_clean()