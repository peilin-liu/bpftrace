#include <bcc/proto.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <net/inet_sock.h>
#include <net/sock.h>
#include <linux/netfilter/x_tables.h>

#define ROUTE_EVT_IF 1
#define ROUTE_EVT_IPTABLE 2
#define ROUTE_EVT_NAT 4
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


typedef union  {
    u32 addr_port[2];
    u64 conn_key;
} addr_port;

// Arg stash structure
struct ipt_do_table_args
{
    const struct nf_hook_state *state;
    struct xt_table *table;
};

struct ipt_do_nat_args
{
    const struct nf_hook_state *state;
    addr_port src;
    addr_port dst;
};

BPF_HASH(cur_ipt_do_table_args, u64, struct ipt_do_table_args);
BPF_HASH(cur_ipt_do_nat_args, u64, struct ipt_do_nat_args);
BPF_HASH(conn_nat_map, addr_port, addr_port);

BPF_CGROUP_ARRAY_DEF

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

static inline int filter_useless_addr_port(addr, port){
    switch (addr) {
        case 16777343:
            return FALSE;
        default:
            break;
    }

    switch (port) {
        case 51325:
        case 20480:
        case 18293:
        case 17781:
        case 5632:
            return FALSE;
        default:
            break;
    }

    return TRUE;
}

static inline int filter_host_port(__be64 saddr, __be64	daddr,
                                   __be16 sport, __be16 dport)
{
    __be16 filter_port = PORT_FILTER;
    __be64 filter_host = HOST_FILTER;
    addr_port src;
    addr_port dst;

    src.addr_port[0]=saddr; src.addr_port[1]=sport;
    dst.addr_port[0]=daddr; dst.addr_port[1]=dport;

    addr_port* s_a_p = (addr_port*)conn_nat_map.lookup(&src);
    addr_port* d_a_p = (addr_port*)conn_nat_map.lookup(&dst);
    
    if(!conn_nat_map.lookup(&src) && !conn_nat_map.lookup(&dst)){
        return FALSE;
    }

    if(s_a_p){
        //bpf_trace_printk("filter_host_port, found src %ld:%d\n", saddr, sport);
    }

    if(d_a_p){
        //bpf_trace_printk("filter_host_port, found dst %ld:%d\n", daddr, dport);
    }

    if(filter_host > 0 && filter_port > 0) {
        if((filter_host == saddr && filter_port == sport) 
            || (filter_host == daddr && filter_port == dport) ){
            //bpf_trace_printk("filter_host_port 1, src %ld:%d\n", saddr, sport);
            //bpf_trace_printk("filter_host_port 1, dst %ld:%d\n", daddr, dport);
            return TRUE;
        }
    } else if (filter_host <= 0 && filter_port > 0) {
        if (sport == filter_port || dport == filter_port){             
            //bpf_trace_printk("filter_host_port 2, src %ld:%d\n", saddr, sport);
            //bpf_trace_printk("filter_host_port 2, dst %ld:%d\n", daddr, dport);
            return TRUE;}
    } else if (filter_host > 0 && filter_port <= 0) {
        if ( saddr == filter_host || daddr == filter_host){             
            //bpf_trace_printk("filter_host_port 3, src %ld:%d\n", saddr, sport);
            //bpf_trace_printk("filter_host_port 3, dst %ld:%d\n", daddr, dport);
            return TRUE;} 
    } 
    else if(!filter_useless_addr_port(saddr, sport)){ return FALSE;}
    else if(!filter_useless_addr_port(daddr, dport)){ return FALSE;}
    else {              
            //bpf_trace_printk("filter_host_port 4, src %ld:%d\n", saddr, sport);
            //bpf_trace_printk("filter_host_port 4, dst %ld:%d\n", daddr, dport);
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
    struct sock* sock_s = 0;
    char *ip_header_address = 0;

    member_read(&head, skb, head);
    member_read(&data, skb, data);
    member_read(&mac_len, skb, mac_len);
    member_read(&mac_header, skb, mac_header);
    member_read(&network_header, skb, network_header);
    member_read(&transport_header, skb, transport_header);
    member_read(&sock_s, skb, sk);

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
    
    // Load TCP packets info
    member_read(&evt->sport, tcp_header, source);
    member_read(&evt->dport, tcp_header, dest);

    return TRUE;
}

static inline int filter_skb_tcp_info(struct route_evt_t *evt, void *ctx, struct sk_buff *skb){
    
    if(!parse_skb_tcp_info(evt, ctx, skb)){ return FALSE;}
    
    if(!filter_host_port((__be64)evt->saddr, (__be64)evt->daddr, evt->sport, evt->dport)){
        return FALSE;
    }
    
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

    if(!filter_skb_tcp_info(evt, ctx, skb)){
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

static inline int insert_tcp_conn_trace(__u32 saddr, __u16 sport, __u32 nat_saddr, __u16 nat_sport){
    addr_port src_a_p; src_a_p.addr_port[0]= saddr;  src_a_p.addr_port[1] = sport;
    addr_port nat_a_p; nat_a_p.addr_port[0]= nat_saddr;  nat_a_p.addr_port[1] = nat_sport;

    addr_port* old_a_p = (addr_port*)conn_nat_map.lookup(&src_a_p);
    if(!old_a_p || old_a_p->conn_key == 0){
        conn_nat_map.update(&src_a_p, &nat_a_p);
        bpf_trace_printk("iptables nat ret record nat src addr %ld:%d\n", src_a_p.addr_port[0],
                            src_a_p.addr_port[1]);
    }

    if(nat_a_p.conn_key != 0){
        old_a_p = conn_nat_map.lookup(&nat_a_p);
        if(!old_a_p ){
            addr_port zero_a_p;
            zero_a_p.conn_key = 0;
            conn_nat_map.update(&nat_a_p, &zero_a_p);
            bpf_trace_printk("iptables nat ret record zero nat src addr %ld:%d\n", nat_a_p.addr_port[0],
                                nat_a_p.addr_port[1]);
        }
    }

    return 0;
}

static inline addr_port* clean_nat_node(addr_port* cur_node){
    addr_port* next_node = (addr_port*)conn_nat_map.lookup(cur_node);
    if(!next_node) { return 0; }
    bpf_trace_printk("iptables nat ret delete nat src addr %ld->%d\n", 
                    cur_node->addr_port[0], cur_node->addr_port[1]);
    addr_port temp_a_p = *next_node;
    conn_nat_map.delete(cur_node);
    *cur_node = temp_a_p; //for next
    return next_node;
}

static inline int clean_tcp_conn_trace(__u32 saddr, __u16 sport){
    addr_port cur_node = {};
    cur_node.addr_port[0] = saddr; cur_node.addr_port[1] = sport;

    if(!clean_nat_node(&cur_node)) { return 0;}
    if(!clean_nat_node(&cur_node)) { return 0;}
    if(!clean_nat_node(&cur_node)) { return 0;}
    if(!clean_nat_node(&cur_node)) { return 0;}
    if(!clean_nat_node(&cur_node)) { return 0;}
    if(!clean_nat_node(&cur_node)) { return 0;}
    if(!clean_nat_node(&cur_node)) { return 0;}
    if(!clean_nat_node(&cur_node)) { return 0;}
    if(!clean_nat_node(&cur_node)) { return 0;}
    if(!clean_nat_node(&cur_node)) { return 0;}
    if(!clean_nat_node(&cur_node)) { return 0;}
    if(!clean_nat_node(&cur_node)) { return 0;}
    if(!clean_nat_node(&cur_node)) { return 0;}
    if(!clean_nat_node(&cur_node)) { return 0;}
    if(!clean_nat_node(&cur_node)) { return 0;}
    if(!clean_nat_node(&cur_node)) { return 0;}

    return 0;
}

static inline int do_trace_state(struct sock *sk, int protocol, int newstate, int family, __u32 saddr, __u16 sport){
    sport = bpf_htons(sport);
    if (protocol != IPPROTO_TCP) {
        return 0;
    }

    if (newstate != TCP_CLOSE && newstate != TCP_CLOSE_WAIT) {
        return 0;
    }

    if (family != AF_INET){
        return 0;
    }

    bpf_trace_printk("inet_sock_set_state sock addr %p, saddr %ld:%d\n", sk, saddr, sport);
    return clean_tcp_conn_trace(saddr, sport); 
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

TRACEPOINT_PROBE(sock, inet_sock_set_state){

    return do_trace_state((struct sock *)args->skaddr, args->protocol, args->newstate, args->family,
                    *(__u32*)args->saddr, args->sport);
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

    if(!do_trace_skb(&evt, ctx, skb)){
        return 0;
    }
    
    // stash the arguments for use in retprobe
    struct ipt_do_table_args args = {
        .state = state,
        .table = table,
    };
    cur_ipt_do_table_args.update((u64*)(&skb), &args);

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

    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct ipt_do_table_args *args;
    args = cur_ipt_do_table_args.lookup((u64*)&skb);
    if (args == 0)
    {
        return 0; // missed entry
    }
    cur_ipt_do_table_args.delete((u64*)&skb);

    // Prepare event for userland
    struct route_evt_t evt = {
        .flags = ROUTE_EVT_IPTABLE,
        .pid  = pid,
        .tgid  = k_pid,
    };
    
    // Load packet information
    if(!do_trace_skb(&evt, ctx, skb)){
        return 0;
    }

    bpf_get_current_comm(evt.comm_name, sizeof(evt.comm_name));

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

int kprobe__nf_nat_ipv4_fn(struct pt_regs *ctx, void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 k_pid = pid_tgid & 0xFFFFFFFF;
    u32 pid = pid_tgid >> 32;

    struct route_evt_t evt = {
        .flags = ROUTE_EVT_NAT,
        .pid  = pid,
        .tgid  = k_pid,
    };

    if(!filter_skb_tcp_info(&evt, ctx, skb)){
        return 0;
    }
    
    bpf_get_current_comm(evt.comm_name, sizeof(evt.comm_name));
    member_read(&evt.hook, state, hook);

    // stash the arguments for use in retprobe
    struct ipt_do_nat_args args = {
        .state = state,
    };

    args.src.addr_port[0] = evt.saddr; args.src.addr_port[1] = evt.sport;
    args.dst.addr_port[0] = evt.daddr; args.dst.addr_port[1] = evt.dport;
    cur_ipt_do_nat_args.update((u64*)(&skb), &args);

    return 0;
} 

int kretprobe__nf_nat_ipv4_fn(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 k_pid = pid_tgid & 0xFFFFFFFF;
    u32 pid = pid_tgid >> 32;

    struct ipt_do_nat_args *args = (struct ipt_do_nat_args*)cur_ipt_do_nat_args.lookup((u64*)&skb);
    if (args == 0)
    {
        return 0; // missed entry
    }
    cur_ipt_do_nat_args.delete((u64*)&skb);

    struct route_evt_t evt = {
        .flags = ROUTE_EVT_NAT,
        .pid  = pid,
        .tgid  = k_pid,
    };

    if(!parse_skb_tcp_info(&evt, ctx, skb)) { return 0;}
    
    if(evt.saddr != args->src.addr_port[0] || evt.sport != args->src.addr_port[1]){
        return insert_tcp_conn_trace(args->src.addr_port[0], args->src.addr_port[1], evt.saddr, evt.sport);
    }

    return 0;
}

int kprobe____sys_connect(struct pt_regs *ctx, 
                    int fd, struct sockaddr *uservaddr, int addrlen)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if(4294968515 != cgroup_id) { return 0;}
    bpf_trace_printk("sys_connect, fd %d, cgroup_id %ld, addrlen %d\n",
                fd, cgroup_id, addrlen);
    return 0;
}

int kretprobe____sys_connect(struct pt_regs *ctx){
    int retval = PT_REGS_RC(ctx);
    //bpf_trace_printk("sys_connect, fd %ld, retval %d exit\n",
    //            PT_REGS_PARM1(ctx), retval);
    return 0;
}