#!/usr/bin/env python
# coding: utf-8

import sys
from socket import inet_ntop, AF_INET, AF_INET6
from bcc import BPF
import ctypes as ct
import subprocess
from struct import pack

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

PING_PID = "-1"

ROUTE_EVT_IF = 1
ROUTE_EVT_IPTABLE = 2

bpf_text = """
#include <bcc/proto.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/icmpv6.h>
#include <net/inet_sock.h>
#include <linux/netfilter/x_tables.h>

#define ROUTE_EVT_IF 1
#define ROUTE_EVT_IPTABLE 2

// Event structure
struct route_evt_t {
    /* Content flags */
    u64 flags;

    /* Routing information */
    char ifname[IFNAMSIZ];
    u64 netns;

    /* Packet type (IPv4 or IPv6) and address */
    u64 ip_version; // familiy (IPv4 or IPv6)
    u64 saddr[2];   // Source address. IPv4: store in saddr[0]
    u64 daddr[2];   // Dest   address. IPv4: store in daddr[0]
    u64 tgid;
    u64 pid;

    /* Iptables trace */
    u64 hook;
    u64 verdict;
    char tablename[XT_TABLE_MAXNAMELEN];
    char comm_name[64];
};
BPF_PERF_OUTPUT(route_evt);

// Arg stash structure
struct ipt_do_table_args
{
    struct sk_buff *skb;
    const struct nf_hook_state *state;
    struct xt_table *table;
};
BPF_HASH(cur_ipt_do_table_args, u32, struct ipt_do_table_args);

#define MAC_HEADER_SIZE 14;
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
  } while(0)

/**
  * Common tracepoint handler. Detect IPv4/IPv6 ICMP echo request and replies and
  * emit event with address, interface and namespace.
  */
static inline int do_trace_skb(struct route_evt_t *evt, void *ctx, struct sk_buff *skb)
{
    // Prepare event for userland
    evt->flags |= ROUTE_EVT_IF;

    // Compute MAC header address
    char* head;
    u16 mac_header;
    u16 network_header;

    member_read(&head,       skb, head);
    member_read(&mac_header, skb, mac_header);
    member_read(&network_header, skb, network_header);

    if(network_header == 0) {
        network_header = mac_header + MAC_HEADER_SIZE;
    }

    // Compute IP Header address
    char *ip_header_address = head + network_header;

    // Abstract IPv4 / IPv6
    u8 l4proto;

    // Load IP protocol version
    bpf_probe_read(&evt->ip_version, sizeof(u8), ip_header_address);
    evt->ip_version = evt->ip_version >> 4 & 0xf;

    // Filter IP packets
    if (evt->ip_version == 4) {
        // Load IP Header
        struct iphdr iphdr;
        bpf_probe_read(&iphdr, sizeof(iphdr), ip_header_address);

        // Load protocol and address
        l4proto      = iphdr.protocol;
        evt->saddr[0] = iphdr.saddr;
        evt->daddr[0] = iphdr.daddr;
    } else if (evt->ip_version == 6) {
        // Assume no option header --> fixed size header
        struct ipv6hdr* ipv6hdr = (struct ipv6hdr*)ip_header_address;

        // Load protocol and address
        bpf_probe_read(&l4proto,  sizeof(ipv6hdr->nexthdr),  (char*)ipv6hdr + offsetof(struct ipv6hdr, nexthdr));
        bpf_probe_read(evt->saddr, sizeof(ipv6hdr->saddr),   (char*)ipv6hdr + offsetof(struct ipv6hdr, saddr));
        bpf_probe_read(evt->daddr, sizeof(ipv6hdr->daddr),   (char*)ipv6hdr + offsetof(struct ipv6hdr, daddr));
    } else {
        return 0;
    }

    // Get device pointer, we'll need it to get the name and network namespace
    struct net_device *dev;
    member_read(&dev, skb, dev);

    // Load interface name
    bpf_probe_read(&evt->ifname, IFNAMSIZ, dev->name);

#ifdef CONFIG_NET_NS
    struct net* net;

    // Get netns id. The code below is equivalent to: evt->netns = dev->nd_net.net->ns.inum
    possible_net_t *skc_net = &dev->nd_net;
    member_read(&net, skc_net, net);
    struct ns_common* ns = member_address(net, ns);
    member_read(&evt->netns, ns, inum);
#endif

    return 0;
}

static inline int do_trace(void *ctx, struct sk_buff *skb)
{
    //check target
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 k_pid = pid_tgid & 0xFFFFFFFF;
    u32 pid = pid_tgid >> 32;
    char func_name[64] = "do_trace";
    PROCESS_FILTER

    // Prepare event for userland
    struct route_evt_t evt = {.pid = pid, .tgid  = k_pid, };
    bpf_get_current_comm(evt.comm_name, sizeof(evt.comm_name));

    // Process packet
    int ret = do_trace_skb(&evt, ctx, skb);

    // Send event
    route_evt.perf_submit(ctx, &evt, sizeof(evt));

    // Return
    return ret;
}

/**
 * Attach to Kernel Interface Tracepoints
 */

TRACEPOINT_PROBE(net, netif_rx)
{
    return do_trace(args, (struct sk_buff *)args->skbaddr);
}

TRACEPOINT_PROBE(net, net_dev_queue)
{
    return do_trace(args, (struct sk_buff *)args->skbaddr);
}

TRACEPOINT_PROBE(net, napi_gro_receive_entry)
{
    return do_trace(args, (struct sk_buff *)args->skbaddr);
}

TRACEPOINT_PROBE(net, netif_receive_skb_entry)
{
    return do_trace(args, (struct sk_buff *)args->skbaddr);
}

/**
 * Common iptables functions
 */

static inline int __ipt_do_table_in(struct pt_regs *ctx, struct sk_buff *skb, const struct nf_hook_state *state, struct xt_table *table)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 k_pid = pid_tgid & 0xFFFFFFFF;
    u32 pid = pid_tgid >> 32;
    char func_name[64] = "__ipt_do_table_in";
    PROCESS_FILTER

    // stash the arguments for use in retprobe
    struct ipt_do_table_args args = {
        .skb = skb,
        .state = state,
        .table = table,
    };
    cur_ipt_do_table_args.update(&pid, &args);
    return 0;
};

static inline int __ipt_do_table_out(struct pt_regs * ctx)
{
    // Load arguments
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 k_pid = pid_tgid & 0xFFFFFFFF;
    u32 pid = pid_tgid >> 32;
    char func_name[64] = "__ipt_do_table_out";
    PROCESS_FILTER

    struct ipt_do_table_args *args;
    args = cur_ipt_do_table_args.lookup(&pid);
    if (args == 0)
    {
        return 0; // missed entry
    }
    cur_ipt_do_table_args.delete(&pid);

    // Prepare event for userland
    struct route_evt_t evt = {
        .flags = ROUTE_EVT_IPTABLE,
        .pid  = pid,
        .tgid  = k_pid,
    };
    bpf_get_current_comm(evt.comm_name, sizeof(evt.comm_name));

    // Load packet information
    struct sk_buff *skb = args->skb;
    do_trace_skb(&evt, ctx, skb);

    // Store the hook
    const struct nf_hook_state *state = args->state;
    member_read(&evt.hook, state, hook);

    // Store the table name
    struct xt_table *table = args->table;
    member_read(&evt.tablename, table, name);

    // Store the verdict
    int ret = PT_REGS_RC(ctx);
    evt.verdict = ret;

    // Send event
    route_evt.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

/**
 * Attach to Kernel iptables main function
 */

int kprobe__ipt_do_table(struct pt_regs *ctx, struct sk_buff *skb, const struct nf_hook_state *state, struct xt_table *table)
{
    return __ipt_do_table_in(ctx, skb, state, table);
};

int kretprobe__ipt_do_table(struct pt_regs *ctx)
{
    return __ipt_do_table_out(ctx);
}

int kprobe__ip6t_do_table(struct pt_regs *ctx, struct sk_buff *skb, const struct nf_hook_state *state, struct xt_table *table)
{
    return __ipt_do_table_in(ctx, skb, state, table);
};

int kretprobe__ip6t_do_table(struct pt_regs *ctx)
{
    return __ipt_do_table_out(ctx);
}
"""


class PkgEvt(ct.Structure):
    _fields_ = [
        # Content flags
        ("flags",   ct.c_ulonglong),

        # Routing information
        ("ifname",  ct.c_char * IFNAMSIZ),
        ("netns",   ct.c_ulonglong),

        # Packet type (IPv4 or IPv6) and address
        ("ip_version",  ct.c_ulonglong),
        ("saddr",       ct.c_ulonglong * 2),
        ("daddr",       ct.c_ulonglong * 2),
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


def event_printer(cpu, data, size):
    # Decode event
    event = ct.cast(data, ct.POINTER(PkgEvt)).contents

    # Make sure this is an interface event
    if event.flags & ROUTE_EVT_IF != ROUTE_EVT_IF:
        print("event_printer flags=%s skip", event.flags)
        return

    # Decode address
    if event.ip_version == 4:
        saddr = inet_ntop(AF_INET, pack("=I", event.saddr[0]))
        daddr = inet_ntop(AF_INET, pack("=I", event.daddr[0]))
    elif event.ip_version == 6:
        saddr = inet_ntop(AF_INET6, event.saddr)
        daddr = inet_ntop(AF_INET6, event.daddr)
    else:
        print("event_printer ip_version=%s skip" % event.ip_version)
        return

    # Decode flow
    # direction = "request"
    flow = "%s -> %s" % (saddr, daddr)
    # if saddr.find("119.97.189.76") == -1 and daddr.find("119.97.189.76") == -1:
    #    return

    # Optionally decode iptables events
    iptables = ""
    if event.flags & ROUTE_EVT_IPTABLE == ROUTE_EVT_IPTABLE:
        verdict = _get(NF_VERDICT_NAME, event.verdict, "~UNK~")
        hook = _get(HOOKNAMES, event.hook, "~UNK~")
        iptables = " %-12s.%12s:%6s" % (event.tablename, hook, verdict)
    else:
        iptables = "                                  "

    # Print event
    print("[%12s] %10s:%-10s %-10s %-34s %-34s   %-64s" % (event.netns, event.pid, event.tgid, event.ifname, flow, iptables, event.comm_name))


if __name__ == "__main__":
    # Get arguments
    if len(sys.argv) == 1:
        TARGET_PID = -1
    elif len(sys.argv) == 2:
        TARGET_PID = int(sys.argv[1])

    if TARGET_PID < 0:
        pid_filter = """"""
    else:
        pid_filter = """if (pid == %d) \
            { \
                // bpf_trace_printk("skip pid %%d, %%s", pid, func_name); \
                return; \
            } """ % TARGET_PID

    print("try to use pid filter %s" % (pid_filter))
    bpf_text = bpf_text.replace("PROCESS_FILTER", pid_filter)
    # Build probe and open event buffer
    b = BPF(text=bpf_text, cflags=["-Wno-macro-redefined"])
    b["route_evt"].open_perf_buffer(event_printer)

    print("%14s %14s %16s %-34s %s  %13s" % ('NETWORK NS', 'PID', 'INTERFACE', 'ADDRESSES', 'IPTABLES', 'COMMON_NAME'))

    while 1:
        try:
            b.perf_buffer_poll(10)
        except KeyboardInterrupt:
            exit()
