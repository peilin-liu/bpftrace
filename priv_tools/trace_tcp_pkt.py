#!/usr/bin/env python
# coding: utf-8

import os
from socket import htons, ntohs, htonl, inet_ntop, inet_pton, AF_INET, AF_INET6
from bcc import BPF
import ctypes as ct
from struct import pack
import argparse

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

ROUTE_EVT_IF = 1
ROUTE_EVT_IPTABLE = 2


class PkgEvt(ct.Structure):
    _fields_ = [
        # Content flags
        ("flags",   ct.c_ulonglong),

        # Routing information
        ("ifname",  ct.c_char * IFNAMSIZ),
        ("netns",   ct.c_ulonglong),

        # Packet type (IPv4 or IPv6) and address
        ("ip_version",  ct.c_ulonglong),
        ("saddr",       ct.c_ulonglong),
        ("daddr",       ct.c_ulonglong),
        ("sport",       ct.c_ushort),
        ("dport",       ct.c_ushort),
        ("pid",         ct.c_ulonglong),
        ("tgid",        ct.c_ulonglong),

        # Iptables trace
        ("hook",        ct.c_ulonglong),
        ("verdict",     ct.c_ulonglong),
        ("tablename",   ct.c_char * XT_TABLE_MAXNAMELEN),
        ("comm_name",   ct.c_char * 64),
    ]


def _get(lst, index, default):
    '''
    Get element at index in l or return the default
    '''
    if index < len(lst):
        return lst[index]
    return default


def event_handler(cpu, data, size):
    # Decode event
    event = ct.cast(data, ct.POINTER(PkgEvt)).contents

    # Make sure this is an interface event
    if event.flags & ROUTE_EVT_IF != ROUTE_EVT_IF:
        print("event_handler flags=%s skip", event.flags)
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
    if event.flags & ROUTE_EVT_IPTABLE == ROUTE_EVT_IPTABLE:
        verdict = _get(NF_VERDICT_NAME, event.verdict, unknow)
        hook = _get(HOOKNAMES, event.hook, unknow)
        iptables = " %-12s.%12s:%6s" % (event.tablename, hook, verdict)
    else:
        iptables = "                                  "

    # Print event
    print("[%-12s] %9s:%-9s %-16s %-42s %-34s %-64s" % (event.netns, event.pid, event.tgid, event.ifname, flow, iptables, event.comm_name))


if __name__ == "__main__":
    # Get arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--container_ip', dest='container_ip', type=str, required=True, default='')
    parser.add_argument('--cgroup_path', dest='cgroup_path', type=str, required=False, default=None)
    parser.add_argument('--pid',  dest='pid',  type=int, required=False, default=-1)
    parser.add_argument('--host', dest='host', type=str, required=False, default='')
    parser.add_argument('--port', dest='port', type=int, required=False, default=-1)
    parser.add_argument('--probe_ipv6', dest='probe_ipv6', type=str, required=False, default="enable")

    args = parser.parse_args()

    bpf_filters = {}

    container_ip = int(inet_pton(AF_INET, args.container_ip).encode('hex'), 16)
    if container_ip <= 0:
        print("invalid container_ip %s", args.container_ip)
        exit(-1)
    container_ip_filter = """%d""" % (htonl(container_ip))
    bpf_filters.update({"CONTAINER_FILTER": container_ip_filter})

    cgroup_map_def = ""
    cgroup_map_name = None
    if args.cgroup_path is not None:
        cgroup_map_name = "__cgroup"
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

    # Build probe and open event buffer
    b = BPF(text=bpf_text, cflags=cflags)

    if args.cgroup_path:
        cgroup_array = self.bpf.get_table(cgroup_map_name)
        cgroup_array[0] = self.args.cgroup_path

    #b.load_funcs(BPF.CGROUP_SKB)
    b["route_evt"].open_perf_buffer(event_handler)

    print("%-14s %-19s %-16s %-42s %-34s %-13s" % ('NETWORK NS', 'PID', 'INTERFACE', 'ADDRESSES', 'IPTABLES', 'COMMON_NAME'))

    while 1:
        try:
            b.perf_buffer_poll(10)
        except KeyboardInterrupt:
            b.cleanup()
            os._exit(0)
