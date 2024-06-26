#!/usr/bin/env python
# coding: utf-8

import os
import sys
from socket import htons, ntohs, htonl, inet_ntop, inet_pton, AF_INET, AF_INET6
from bcc import BPF
import ctypes as ct
from struct import pack
import argparse
from datetime import datetime

IFNAMSIZ = 16  # uapi/linux/if.h
XT_TABLE_MAXNAMELEN = 32  # uapi/linux/netfilter/x_tables.h

# uapi/linux/netfilter.h
NF_VERDICT_NAME = [
    'DROP',
    'ACCEPT',
    'STOLEN',
    'QUEUE',
    'REPEAT',
    'STOP',
]

# uapi/linux/netfilter.h
# net/ipv4/netfilter/ip_tables.c
HOOKNAMES = [
    "PREROUTING",
    "INPUT",
    "FORWARD",
    "OUTPUT",
    "POSTROUTING",
]

ROUTE_EVT_IF = 1<<0
ROUTE_EVT_IPTABLE = 1<<1
ROUTE_EVT_NAT = 1<<2
ROUTE_EVT_CONNECT = 1<<3
ROUTE_EVT_READ = 1<<4
ROUTE_EVT_WRITE = 1<<5

class PkgEvtUnion(ct.Union):
    _fields_ = [
        ("tablename",   ct.c_char * XT_TABLE_MAXNAMELEN),
        ("data",        ct.c_uint32 * 8),
    ]

class PkgEvt(ct.Structure):
    _fields_ = [
        # Content event_flags
        ("event_flags",  ct.c_uint32),
        # Routing information
        ("ifname",  ct.c_char * IFNAMSIZ),
        ("netns",   ct.c_ulonglong),

        # Packet type (IPv4 or IPv6) and address
        ("ip_version",  ct.c_ulonglong),
        ("saddr",       ct.c_ulonglong),
        ("daddr",       ct.c_ulonglong),
        ("sport",       ct.c_ushort),
        ("dport",       ct.c_ushort),
        ("tcp_flags",   ct.c_ushort),
        ("ip_payload_len", ct.c_ushort),
        ("tcp_payload_len",ct.c_ushort),
        ("pid",         ct.c_ulonglong),
        ("tgid",        ct.c_ulonglong),

        # Iptables trace
        ("hook",        ct.c_ulonglong),
        ("verdict",     ct.c_ulonglong),
        ("data_union",   PkgEvtUnion),
        ("comm_name",   ct.c_char * 64),
    ]


def _get(lst, index, default):
    '''
    Get element at index in l or return the default
    '''
    if index < len(lst):
        return lst[index]
    return default

fin = 1<<8
syn = 1<<9
rst = 1<<10
ack = 1<<12
flags_list = {fin:'fin', syn:'syn', rst:'rst', ack:'ack'}

def format_tcp_flags(flags):
    flag_list = [value for key, value in flags_list.items() if (key & flags)]
    return '|'.join(flag_list)



def event_error_handler(event, formatted_datetime):
    if not event.event_flags & (ROUTE_EVT_CONNECT|ROUTE_EVT_READ|ROUTE_EVT_WRITE):
        return

    daddr = inet_ntop(AF_INET, pack("=I", event.daddr))
    data_len = "%s:%s" % (event.ip_payload_len, event.tcp_payload_len)
    info = "ret:%-4d, time %.1f" % (event.data_union.data[0], event.data_union.data[1]/1000)
    if event.event_flags & ROUTE_EVT_CONNECT:
        flow = "%s:%s -> %s:%s" % ('localip', 'connect', daddr, ntohs(event.dport))
        print("[%-20s] %-16s %-42s %-34s %-2d %-12s %-10s %-64s" % (formatted_datetime, event.ifname, flow, \
            info, event.event_flags, format_tcp_flags(event.tcp_flags), data_len, event.comm_name))
    elif event.event_flags & ROUTE_EVT_READ:
        flow = "%s:%s -> %s:%s" % ('localip', 'read', daddr, ntohs(event.dport))
        print("[%-20s] %-16s %-42s %-34s %-2d %-12s %-10s %-64s" % (formatted_datetime, event.ifname, flow, \
            info, event.event_flags, format_tcp_flags(event.tcp_flags), data_len, event.comm_name))
    elif event.event_flags & ROUTE_EVT_WRITE:
        flow = "%s:%s -> %s:%s" % ('localip', 'write', daddr, ntohs(event.dport))
        print("[%-20s] %-16s %-42s %-34s %-2d %-12s %-10s %-64s" % (formatted_datetime, event.ifname, flow,
            iptables, event.event_flags, format_tcp_flags(event.tcp_flags), data_len, event.comm_name))
        

def event_handler(cpu, data, size):
    # Decode event
    event = ct.cast(data, ct.POINTER(PkgEvt)).contents
    now = datetime.now()
    formatted_datetime = now.strftime("%D %H:%M:%S.%f")[:-3]
    event_error_handler(event, formatted_datetime)

    # Make sure this is an interface event
    if event.event_flags & ROUTE_EVT_IF != ROUTE_EVT_IF:
        #print("event_handler event_flags=%s skip" % event.event_flags)
        return

    # Decode address
    if event.ip_version == 4:
        saddr = inet_ntop(AF_INET, pack("=I", event.saddr))
        daddr = inet_ntop(AF_INET, pack("=I", event.daddr))
    elif event.ip_version == 6:
        saddr = inet_ntop(AF_INET6, event.saddr)
        daddr = inet_ntop(AF_INET6, event.daddr)
    else:
        print("event_handler ip_version=%s skip" % event.ip_version)
        return

    # Decode flow
    flow = "%s:%s -> %s:%s" % (saddr, ntohs(event.sport), daddr, ntohs(event.dport))

    # Optionally decode iptables events
    iptables = ""
    unknow = "~UNK~"
    if event.event_flags & ROUTE_EVT_IPTABLE == ROUTE_EVT_IPTABLE or \
            event.event_flags & ROUTE_EVT_NAT == ROUTE_EVT_NAT:
        verdict = _get(NF_VERDICT_NAME, event.verdict, unknow)
        hook = _get(HOOKNAMES, event.hook, unknow)
        if hook == unknow:
            print("unknow hook %s %d" % (event.data_union.tablename, event.hook))
        iptables = "%s.%s:%s" % (event.data_union.tablename, hook, verdict)
    else:
        iptables = "                                  "
    data_len = "%s:%s" % (event.ip_payload_len, event.tcp_payload_len)
    # Print event
    print("[%-20s] %-16s %-42s %-34s %-2d %-12s %-10s %-64s" % (formatted_datetime, event.ifname, flow, \
        iptables, event.event_flags, format_tcp_flags(event.tcp_flags), data_len, event.comm_name))

def attch_all_probe(enable_ipv6=False):
    b.attach_kprobe(event='ipt_do_table', fn_name='kp_ipt_do_table')
    b.attach_kretprobe(event='ipt_do_table', fn_name='kretp_ipt_do_table')

    if enable_ipv6:
        b.attach_kprobe(event='ip6t_do_table', fn_name='kp_ip6t_do_table')
        b.attach_kretprobe(event='ip6t_do_table', fn_name='kretp_ip6t_do_table')       

    b.attach_kprobe(event='nf_nat_ipv4_out', fn_name='kp_nf_nat_ipv4_out')
    b.attach_kretprobe(event='nf_nat_ipv4_out', fn_name='kretp_nf_nat_ipv4_out')

    #b.attach_kprobe(event='nf_nat_ipv4_in', fn_name='kp_nf_nat_ipv4_in')
    #b.attach_kretprobe(event='nf_nat_ipv4_in', fn_name='kretp_nf_nat_ipv4_in')

    #b.attach_kprobe(event='ip_forward', fn_name='kp_ip_forward')
    #b.attach_kretprobe(event='ip_forward', fn_name='kretp_ip_forward')

    b.attach_kprobe(event='tcp_connect', fn_name='kp_tcp_connect')

    #b.attach_kprobe(event='__sys_connect', fn_name='kp___sys_connect')
    b.attach_kretprobe(event='__sys_connect', fn_name='kretp___sys_connect')

    b.attach_kprobe(event='tcp_recvmsg', fn_name='kp_tcp_recvmsg')
    b.attach_kretprobe(event='tcp_recvmsg', fn_name='kretp_tcp_recvmsg')

    #b.attach_kprobe(event='tcp_retransmit_skb', fn_name='kp_tcp_retransmit_skb')
    #b.attach_kretprobe(event='tcp_retransmit_skb', fn_name='kretp_tcp_retransmit_skb')

    b.attach_tracepoint(tp='net:netif_rx', fn_name='tp_net_netif_rx')
    b.attach_tracepoint(tp='net:net_dev_queue', fn_name='tp_net_net_dev_queue')
    b.attach_tracepoint(tp='net:napi_gro_receive_entry', fn_name='tp_net_napi_gro_receive_entry')
    b.attach_tracepoint(tp='net:netif_receive_skb_entry', fn_name='tp_net_netif_receive_skb_entry')
    b.attach_tracepoint(tp='sock:inet_sock_set_state', fn_name='tp_sock_inet_sock_set_state')
    b.attach_tracepoint(tp='tcp:tcp_destroy_sock', fn_name='tp_tcp_tcp_destroy_sock')

if __name__ == "__main__":
    # Get arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--container_ip', dest='container_ip', type=str, required=True, default='')
    parser.add_argument('--cgroup_path', dest='cgroup_path', type=str, required=False, default=None) #这个特性,4.9上的支持不好
    parser.add_argument('--pid',  dest='pid',  type=int, required=False, default=-1)
    parser.add_argument('--host', dest='host', type=str, required=False, default='')
    parser.add_argument('--port', dest='port', type=int, required=False, default=-1)
    parser.add_argument('--probe_ipv6', dest='probe_ipv6', type=int, required=False, default=0)
    parser.add_argument('--debug', dest='debug', type=int, required=False, default=0)

    args = parser.parse_args()

    bpf_filters = {}

    if 3== sys.version_info.major:
        container_ip = int.from_bytes(inet_pton(AF_INET, args.container_ip), byteorder='big')
    else:
        container_ip = int(inet_pton(AF_INET, args.container_ip).encode('hex'), 16)

    if container_ip <= 0:
        print("invalid container_ip %s", args.container_ip)
        exit(-1)
    container_ip_filter = """%d""" % (htonl(container_ip))
    bpf_filters.update({"CONTAINER_FILTER": container_ip_filter})

    cgroup_map_def = ""
    cgroup_map_name = None
    if args.cgroup_path is not None:
        cgroup_map_name = "__cgroup_filter"
        cgroup_map_def = "BPF_CGROUP_ARRAY(%s, 1);\n" % cgroup_map_name
    bpf_filters.update({"BPF_CGROUP_ARRAY_DEF": cgroup_map_def})

    if args.pid < 0:
        pid_filter = """"""
    else:
        pid_filter = """if (pid != %d) { \
                bpf_trace_printk("skip pid %%d, %%s", pid, func_name); \
                return; } """ % (args.pid)
    bpf_filters.update({"PROCESS_FILTER": pid_filter})

    if len(args.host) <= 0:
        host_filter = """0"""
    else:
        if 3== sys.version_info.major:
            args.host = int.from_bytes(inet_pton(AF_INET, args.host), byteorder='big') 
        else:
            args.host = int(inet_pton(AF_INET, args.host).encode('hex'), 16)
        host_filter = """%d""" % (htonl(args.host))
    bpf_filters.update({"HOST_FILTER": host_filter})

    if args.port <= 0:
        port_filter = """0"""
    else:
        port_filter = """%d""" % (htons(args.port))
    bpf_filters.update({"PORT_FILTER": port_filter})

    bpf_text = ""
    command_path = './trace_tcp_pkt.c'
    with open(command_path) as bpf_file:
        bpf_text = bpf_file.read()
        bpf_file.close

    if len(bpf_text) <= 1:
        print("load bpf command %s failed" % (command_path))
        os._exit(-1)

    for filter_name, filter_command in bpf_filters.items():
        bpf_text = bpf_text.replace(filter_name, filter_command)

    cflags = ["-Wno-macro-redefined", "-Wno-tautological-compare", "-Wno-implicit-function-declaration", "-DCONFIG_NET_NS"]
    if args.probe_ipv6 == "enable":
        print("enable ipv6: %s" % args.probe_ipv6)
        cflags.append("-DPROBE_IPV6")

    if args.cgroup_path:
        cflags.append("-DENABLE_CGROUP_CHECK")
    if args.debug:
        cflags.append("-DDEBUGLOG")
    # Build probe and open event buffer
    b = BPF(text=bpf_text, cflags=cflags, debug=0)

    if args.cgroup_path:
        cgroup_array = b.get_table(cgroup_map_name)
        cgroup_array[0] = args.cgroup_path

    attch_all_probe(args.probe_ipv6 == "enable")
    #b.load_funcs(BPF.CGROUP_SKB)
    b["route_evt"].open_perf_buffer(event_handler)

    print("%-23s %-16s %-42s %-34s %2s %-10s %-10s %-13s" % ('TIMESTAMP', 'INTERFACE', 'ADDRESSES', 'IPTABLES', 'OP', 'TCP_FLAGS', 'SIZE(IP:TCP)', 'COMMON_NAME'))

    while 1:
        try:
            b.perf_buffer_poll(10)
        except KeyboardInterrupt:
            b.cleanup()
            os._exit(0)
