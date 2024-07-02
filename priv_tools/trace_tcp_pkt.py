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
import signal
from collections import deque

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

log_file_o = None

class Evt(object):
    ROUTE_EVT_IF_RX     = (1<<0)
    ROUTE_EVT_IF_NAPI_R = (1<<1)
    ROUTE_EVT_IF_SKB_R  = (1<<2)
    ROUTE_EVT_IF_DEV_W  = (1<<3)
    ROUTE_EVT_IPTABLE   = (1<<4)
    ROUTE_EVT_NAT_IN    = (1<<5)
    ROUTE_EVT_NAT_OUT   = (1<<6)
    ROUTE_EVT_CONNECT   = (1<<7)
    ROUTE_EVT_ACCEPT    = (1<<8)
    ROUTE_EVT_READ      = (1<<9)
    ROUTE_EVT_WRITE     = (1<<10)
    
    
    ROUTE_D_OUT = (1<<23)
    
    e_maps  = {
        ROUTE_EVT_IF_RX:        'IF_RX',
        ROUTE_EVT_IF_NAPI_R:    'NAPI_R',
        ROUTE_EVT_IF_SKB_R:     'SKB_R',
        ROUTE_EVT_IF_DEV_W:     'DEV_W',
        ROUTE_EVT_IPTABLE:      'D_IPT',
        ROUTE_EVT_NAT_IN:       'NAT_I',
        ROUTE_EVT_NAT_OUT:      'NAT_O',
        ROUTE_EVT_CONNECT:      'CONN',
        ROUTE_EVT_ACCEPT:       'ACCEPT',
        ROUTE_EVT_READ:         'U_R',
        ROUTE_EVT_WRITE:        'U_W',
    }   

class PkgEvtUnion(ct.Union):
    _fields_ = [
        ("tablename",   ct.c_char * XT_TABLE_MAXNAMELEN),
        ("data",        ct.c_uint32 * 8),
    ]

class PkgEvt(ct.Structure):
    _fields_ = [
        # Content event_flags
        ("event_flags",  ct.c_uint32),
        ("pid",         ct.c_ulonglong),
        ("tgid",        ct.c_ulonglong),
        # Routing information
        ("ifname",  ct.c_char * IFNAMSIZ),
        ("netns",   ct.c_ulonglong),

        # Packet type (IPv4 or IPv6) and address
        ("saddr",       ct.c_ulonglong),
        ("daddr",       ct.c_ulonglong),
        ("sport",       ct.c_ushort),
        ("dport",       ct.c_ushort),
        ("tcp_flags",   ct.c_ushort),
        ("ip_payload_len", ct.c_ushort),
        ("tcp_payload_len",ct.c_ushort),
        ("ip_version",   ct.c_ubyte),
        ("res1",         ct.c_ubyte),

        # Iptables trace
        ("hook",        ct.c_uint32),
        ("verdict",     ct.c_int32),
        ("data_union",   PkgEvtUnion),
        ("comm_name",   ct.c_char * 64),
    ]

class EvtCacheLru(object):
    def __init__(self, max_size):
        self.max_size = max_size if max_size else 100
        self.queue = deque([])

    def push(self, evt):
        if len(self.queue) > self.max_size:
            self.queue.popleft()
        self.queue.append(evt)

    def traverse(self, vistor):
        for evt in self.queue:
           vistor(evt)

    def clean(self):
        self.queue.clear()

evt_lru = None

def _get(lst, index, default):
    '''
    Get element at index in l or return the default
    '''
    if index < len(lst):
        return lst[index]
    return default

def write_info(info):
    if log_file_o:
        if evt_lru:
            evt_lru.push('%s\n' % info)
        else:
            log_file_o.write('%s\n' % info)
    else:
        print(info)

fin = 1<<8
syn = 1<<9
rst = 1<<10
ack = 1<<12
flags_list = {fin:'fin', syn:'syn', rst:'rst', ack:'ack'}

def format_tcp_flags(flags):
    flag_list = [value for key, value in flags_list.items() if (key & flags)]
    return '|'.join(flag_list)


def event_error_handler(event, formatted_datetime):
    if not event.event_flags & (Evt.ROUTE_EVT_CONNECT|Evt.ROUTE_EVT_READ|Evt.ROUTE_EVT_WRITE):
        return False
    
    if 115 == event.data_union.data[0]:
        return True # skip this error
    
    event_flags = event.event_flags
    event_flags = event_flags & ~Evt.ROUTE_D_OUT

    daddr = inet_ntop(AF_INET, pack("=I", event.daddr))
    data_len = "%s:%s" % (event.ip_payload_len, event.tcp_payload_len)
    local_info = ntohs(event.sport) if event.sport else 'localip'
    info = "ret:%-4d, time %.1f" % (event.data_union.data[0], event.data_union.data[1]/1000)
    if event_flags & Evt.ROUTE_EVT_CONNECT:
        flow = "%s:%s -> %s:%s" % (local_info, 'connect', daddr, ntohs(event.dport))
    elif event_flags & Evt.ROUTE_EVT_READ:
        flow = "%s:%s -> %s:%s" % (local_info, 'read', daddr, ntohs(event.dport))
    elif event_flags & Evt.ROUTE_EVT_WRITE:
        flow = "%s:%s -> %s:%s" % (local_info, 'write', daddr, ntohs(event.dport))
        
    write_info("[%-20s] %-16s %-42s %-34s %-6s %-12s %-10s %-24s" % (formatted_datetime, event.ifname, flow,
        info, Evt.e_maps[event.event_flags], format_tcp_flags(event.tcp_flags), data_len, event.comm_name))
    
    if evt_lru:
        evt_lru.traverse(lambda info: log_file_o.write(info))
        evt_lru.clean()
    
    return True

def event_handler(cpu, data, size):
    # Decode event
    event = ct.cast(data, ct.POINTER(PkgEvt)).contents
    event_flags = event.event_flags
    event_flags = event_flags & ~Evt.ROUTE_D_OUT
    
    now = datetime.now()
    formatted_datetime = now.strftime("%D %H:%M:%S.%f")[:-3]
    if event_error_handler(event, formatted_datetime):
        return

    # Make sure this is an interface event
    if Evt.e_maps.get(event_flags) is None:
        print("event_handler event_flags=%s skip" % event_flags)
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
    if event_flags & Evt.ROUTE_EVT_IPTABLE or \
            event_flags & Evt.ROUTE_EVT_NAT_IN or \
            event_flags & Evt.ROUTE_EVT_NAT_OUT :
        verdict = _get(NF_VERDICT_NAME, event.verdict, unknow)
        hook = _get(HOOKNAMES, event.hook, unknow)
        if hook == unknow:
            print("unknow hook %s %d" % (event.data_union.tablename, event.hook))
        iptables = "%s.%s:%s" % (event.data_union.tablename, hook, verdict)
    else:
        iptables = "                                  "
    data_len = "%s:%s" % (event.ip_payload_len, event.tcp_payload_len)
    # Print event
    write_info("[%-20s] %-16s %-42s %-34s %-6s %-12s %-10s %-24s" % (formatted_datetime, event.ifname, flow, \
        iptables, Evt.e_maps[event_flags], format_tcp_flags(event.tcp_flags), data_len, event.comm_name))

def attch_all_probe(enable_ipv6=False):
    b.attach_kprobe(event='ipt_do_table', fn_name='kp_ipt_do_table')
    b.attach_kretprobe(event='ipt_do_table', fn_name='kretp_ipt_do_table')

    if enable_ipv6:
        b.attach_kprobe(event='ip6t_do_table', fn_name='kp_ip6t_do_table')
        b.attach_kretprobe(event='ip6t_do_table', fn_name='kretp_ip6t_do_table')       

    b.attach_kprobe(event='nf_nat_ipv4_out', fn_name='kp_nf_nat_ipv4_out')
    b.attach_kretprobe(event='nf_nat_ipv4_out', fn_name='kretp_nf_nat_ipv4_out')

    b.attach_kprobe(event='nf_nat_ipv4_in', fn_name='kp_nf_nat_ipv4_in')
    b.attach_kretprobe(event='nf_nat_ipv4_in', fn_name='kretp_nf_nat_ipv4_in')

    #b.attach_kprobe(event='ip_forward', fn_name='kp_ip_forward')
    #b.attach_kretprobe(event='ip_forward', fn_name='kretp_ip_forward')

    b.attach_kprobe(event='tcp_connect', fn_name='kp_tcp_connect')

    #b.attach_kprobe(event='__sys_connect', fn_name='kp___sys_connect')
    b.attach_kretprobe(event='__sys_connect', fn_name='kretp___sys_connect')
    
    b.attach_kprobe(event='tcp_connect', fn_name='kp_tcp_connect')
    b.attach_kretprobe(event='tcp_connect', fn_name='kp_tcp_connect')

    #b.attach_kprobe(event='inet_csk_accept', fn_name='kp_inet_csk_accept')
    b.attach_kretprobe(event='inet_csk_accept', fn_name='kretp_inet_csk_accept')

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
    parser.add_argument('--only_err', dest='only_err', type=int, required=False, default=0)
    parser.add_argument('--debug', dest='debug', type=int, required=False, default=0)
    parser.add_argument('--w', dest='w', type=str, required=False, default=None)

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
    b["route_evt"].open_perf_buffer(event_handler)

    if args.w:
        log_file_o = open(args.w, 'a+')

    if args.only_err:
        evt_lru = EvtCacheLru(10240)

    write_info("%-23s %-16s %-42s %-34s %-6s %-10s %-10s %-13s" % ('TIMESTAMP', 'INTERFACE', 'ADDRESSES', 'IPTABLES', 'EVENT', 'TCP_FLAGS', 'SIZE(IP:TCP)', 'COMMON_NAME'))

    def signal_handler(signum, frame):
        b.cleanup()
        if log_file_o:
            log_file_o.flush()
        os._exit(0)
    
    signal.signal(signal.SIGTERM, signal_handler)

    while 1:
        try:
            b.perf_buffer_poll(10)
        except KeyboardInterrupt:
            b.cleanup()
            if log_file_o:
                log_file_o.flush()
            os._exit(0)
