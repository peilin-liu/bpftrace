#include <bcc/proto.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <net/inet_sock.h>
#include <linux/netfilter/x_tables.h>

#define ROUTE_EVT_IF 1
#define ROUTE_EVT_IPTABLE 2
#define TRUE 1
#define FALSE 0
// Event structure
struct route_evt_t {
    /* Content flags */
    u64 flags;

    /* Routing information */
    char ifname[IFNAMSIZ];
    u64 netns;

    /* Packet type (IPv4 or IPv6) and address */
    u64 ip_version; // familiy (IPv4 or IPv6)
    __be64 saddr;
    __be64 daddr;
	u16	sport;
	u16	dport;
    u64 pid;
    u64 tgid;


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

static inline int filter_host_port(__be64 saddr, __be64	daddr,
                                   __be16 sport, __be16 dport)
{
    __be16 filter_port = PORT_FILTER;
    __be64 filter_host = HOST_FILTER;

    if(filter_host > 0 && filter_port > 0) {
        if((filter_host == saddr && filter_port == sport) 
            || (filter_host == daddr && filter_port == dport) ){
            return TRUE;
        }
    } else if (filter_host <= 0 && filter_port > 0) {
        if (sport == filter_port || dport == filter_port){
            return TRUE;
        }
    } else if (filter_host > 0 && filter_port <= 0) {
        if ( saddr == filter_host || daddr == filter_host){
            return TRUE;
        }
    } else {
        return TRUE;
    }
    
    return FALSE;
}

static inline int parse_skb_tcp_info(struct route_evt_t *evt, void *ctx, struct sk_buff *skb){
    char* head;
    char* data;
    u16 mac_len;
    u16 mac_header;
    u16 network_header;
    u16 transport_header;

    struct tcphdr * tcp_header = 0;
    char *ip_header_address = 0;

    member_read(&head, skb, head);
    member_read(&data, skb, data);
    member_read(&mac_len, skb, mac_len);
    member_read(&mac_header, skb, mac_header);
    member_read(&network_header, skb, network_header);
    member_read(&transport_header, skb, transport_header);

    if(network_header == 0 && mac_header != (typeof(skb->mac_header))~0U) { //mac was set
        ip_header_address = data;
    } else if (network_header != 0) {
        ip_header_address = head + network_header;
    } else {
        bpf_trace_printk("parse_skb_tcp_info, can get layer2 data, network_header %d, transport_header %d\n", network_header, transport_header);
        return FALSE;
    }

    // Abstract IPv4 / IPv6
    u8 l4proto;

    // Load IP protocol version
    bpf_probe_read(&evt->ip_version, sizeof(u8), ip_header_address);
    evt->ip_version = evt->ip_version >> 4 & 0xf;

    // Filter IP packets
    if (evt->ip_version == 4) {
        struct iphdr iphdr;
        bpf_probe_read(&iphdr, sizeof(iphdr), ip_header_address);

        // Load protocol and address
        l4proto      = iphdr.protocol;
        evt->saddr = iphdr.saddr;
        evt->daddr = iphdr.daddr;
        tcp_header = (struct tcphdr *)(ip_header_address + 20);
    } else if (evt->ip_version == 6) {
        struct ipv6hdr* ipv6hdr = (struct ipv6hdr*)ip_header_address;

        // Load protocol and address
        bpf_probe_read(&l4proto,  sizeof(ipv6hdr->nexthdr),  (char*)ipv6hdr + offsetof(struct ipv6hdr, nexthdr));
        bpf_probe_read(&evt->saddr, sizeof(ipv6hdr->saddr),   (char*)ipv6hdr + offsetof(struct ipv6hdr, saddr));
        bpf_probe_read(&evt->daddr, sizeof(ipv6hdr->daddr),   (char*)ipv6hdr + offsetof(struct ipv6hdr, daddr));
        tcp_header = (struct tcphdr *)(ip_header_address + 40);
    } else {
        return FALSE;
    }

    if (l4proto != IPPROTO_TCP) {
        return FALSE;
    }
    
    // Filter TCP packets
    __be16	sport, dport;
    member_read(&sport, tcp_header, source);
    member_read(&dport, tcp_header, dest);
    
    if(!filter_host_port((__be64)evt->saddr, (__be64)evt->daddr, sport, dport)){
        __be32 saddr = (__be32)evt->saddr;
        __be32 daddr = (__be32)evt->daddr;
        /*
        bpf_trace_printk("parse_skb_tcp skip, saddr %d.%d", ((char*)(&saddr))[0]&0xFF,  ((char*)(&saddr))[1]&0xFF);
        bpf_trace_printk("%d.%d\n", ((char*)(&saddr))[2]&0xFF,  ((char*)(&saddr))[3]&0xFF);
        bpf_trace_printk("parse_skb_tcp skip, daddr %d.%d", ((char*)(&daddr))[0]&0xFF,  ((char*)(&daddr))[1]&0xFF);
        bpf_trace_printk("%d.%d\n", ((char*)(&daddr))[2]&0xFF,  ((char*)(&daddr))[3]&0xFF);
        */
        bpf_trace_printk("parse_skb_tcp_info skip, sport %d, dport %d\n", bpf_ntohs(sport), bpf_ntohs(dport));
        return FALSE;
    }
    evt->sport = sport; evt->dport = dport;
    return TRUE;
}

/**
  * Common tracepoint handler. Detect TCP over IPv4/IPv6 request and replies
  * emit event with address,port interface and namespace.
  */
static inline int do_trace_skb(struct route_evt_t *evt, void *ctx, struct sk_buff *skb)
{
    // Prepare event for userland
    evt->flags |= ROUTE_EVT_IF;

    if(!parse_skb_tcp_info(evt, ctx, skb)){
        return FALSE;
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

    return TRUE;
}

static inline int do_trace(void *ctx, struct sk_buff *skb)
{
    //check target
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 k_pid = pid_tgid & 0xFFFFFFFF;
    u32 pid = pid_tgid >> 32;
    //char func_name[16] = "do_trace"; //debug key, don't remove it
    PROCESS_FILTER

    // Prepare event for userland
    struct route_evt_t evt = {.pid = pid, .tgid  = k_pid, };
    bpf_get_current_comm(evt.comm_name, sizeof(evt.comm_name));

    // Process packet
    if (!do_trace_skb(&evt, ctx, skb)){
        return 0;
    }

    // Send event
    route_evt.perf_submit(ctx, &evt, sizeof(evt));

    // Return
    return 0;
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
    //char func_name[18] = "__ipt_do_table_in"; //debug key, don't remove it
    PROCESS_FILTER

    // Prepare event for userland
    struct route_evt_t evt = {
        .flags = ROUTE_EVT_IPTABLE,
        .pid  = pid,
        .tgid  = k_pid,
    };
    
    if(!parse_skb_tcp_info(&evt, ctx, skb)){
        return 0;
    }

    bpf_get_current_comm(evt.comm_name, sizeof(evt.comm_name));

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
    //char func_name[19] = "__ipt_do_table_out"; //debug key, don't remove it
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
    if(!do_trace_skb(&evt, ctx, skb)){
        return 0;
    }

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

#ifdef PROBE_IPV6
int kprobe__ip6t_do_table(struct pt_regs *ctx, struct sk_buff *skb, const struct nf_hook_state *state, struct xt_table *table)
{
    return __ipt_do_table_in(ctx, skb, state, table);
};

int kretprobe__ip6t_do_table(struct pt_regs *ctx)
{
    return __ipt_do_table_out(ctx);
}
#endif