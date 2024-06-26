#include <bcc/proto.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <net/inet_sock.h>
#include <net/sock.h>
#include <linux/netfilter/x_tables.h>

#ifndef DEBUGLOG
#define bpf_trace_printk(...) 
#endif

#define ROUTE_EVT_IF (1<<0)
#define ROUTE_EVT_IPTABLE (1<<1)
#define ROUTE_EVT_NAT (1<<2)
#define ROUTE_EVT_CONNECT (1<<3)
#define ROUTE_EVT_READ (1<<4)
#define ROUTE_EVT_WRITE (1<<5)

#define TRUE 1
#define FALSE 0
// Event structure
struct route_evt_t {
    /* Content event_flags */
    u32 event_flags;
    /* Routing information */
    char ifname[IFNAMSIZ];
    u64 netns;

    /* Packet type (IPv4 or IPv6) and address */
    u64 ip_version; // familiy (IPv4 or IPv6)
    __be64 saddr;
    __be64 daddr;
	u16	sport;
	u16	dport;
    u16 tcp_flags;
    u16 ip_payload_len;
    u16 tcp_payload_len;
    u64 pid;
    u64 tgid;


    /* Iptables trace */
    u64 hook;
    u64 verdict;
    union 
    {
        char tablename[XT_TABLE_MAXNAMELEN];
        u32 data[8];
    };
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
    struct sk_buff *skb;
    const struct nf_hook_state *state;
    addr_port src;
    addr_port dst;
};

struct conn_status_args
{
    __u32 addr;
    __u16 port;
    __u64 start;
};

BPF_HASH(cur_ipt_do_table_args, u64, struct ipt_do_table_args);
BPF_HASH(cur_ipt_do_nat_args, u64, struct ipt_do_nat_args);
BPF_HASH(conn_nat_map, addr_port, addr_port);
BPF_HASH(conn_status_map, u64, struct conn_status_args);
BPF_HASH(conn_rw_map, u64, struct conn_status_args);
BPF_HASH(conn_active_map, u64, u64);

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
/*
    switch (port) {
        case 51325: //32200
        case 18293: //30023
        case 17781: //30021
        case 5632:  //22
            return FALSE;
        default:
            break;
    }
*/
    return TRUE;
}

static inline int filter_connect_dst(__be64	daddr, __be16 dport){
    if(HOST_FILTER > 0 && daddr != HOST_FILTER){
        return FALSE;
    } else if (PORT_FILTER > 0 && dport != PORT_FILTER) {
        return FALSE;
    }

    return TRUE;
}

static inline int filter_host_port(__be64 saddr, __be64	daddr,
                                   __be16 sport, __be16 dport)
{    
    addr_port src;
    addr_port dst;

    src.addr_port[0]=saddr; src.addr_port[1]=sport;
    dst.addr_port[0]=daddr; dst.addr_port[1]=dport;
    
    if(!conn_nat_map.lookup(&src) && !conn_nat_map.lookup(&dst) && 
        daddr != CONTAINER_FILTER && saddr != CONTAINER_FILTER) {
        return FALSE;
    }

    if(HOST_FILTER > 0 && PORT_FILTER > 0) {
        if((HOST_FILTER == saddr && PORT_FILTER == sport) 
            || (HOST_FILTER == daddr && PORT_FILTER == dport) ){
            return TRUE;
        }
    } else if (HOST_FILTER <= 0 && PORT_FILTER > 0) {
        if (sport == PORT_FILTER || dport == PORT_FILTER){             
            return TRUE;}
    } else if (HOST_FILTER > 0 && PORT_FILTER <= 0) {
        if ( saddr == HOST_FILTER || daddr == HOST_FILTER){             
            return TRUE;} 
    } 
    else if(!filter_useless_addr_port(saddr, sport)){ return FALSE;}
    else if(!filter_useless_addr_port(daddr, dport)){ return FALSE;}
    else {              
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
        return 1;
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
        evt->ip_payload_len = bpf_ntohs(iphdr.tot_len) - (iphdr.ihl << 2);
        tcp_header = (struct tcphdr *)(ip_header_address + (iphdr.ihl << 2));
    } else if (evt->ip_version == 6) {
        struct ipv6hdr* ipv6hdr = (struct ipv6hdr*)ip_header_address;

        // Load protocol and address
        bpf_probe_read(&l4proto,  sizeof(ipv6hdr->nexthdr),  (char*)ipv6hdr + offsetof(struct ipv6hdr, nexthdr));
        bpf_probe_read(&evt->saddr, sizeof(ipv6hdr->saddr),   (char*)ipv6hdr + offsetof(struct ipv6hdr, saddr));
        bpf_probe_read(&evt->daddr, sizeof(ipv6hdr->daddr),   (char*)ipv6hdr + offsetof(struct ipv6hdr, daddr));
        bpf_probe_read(&evt->ip_payload_len, sizeof(ipv6hdr->payload_len),   (char*)ipv6hdr + offsetof(struct ipv6hdr, payload_len));
        evt->ip_payload_len = bpf_ntohs(evt->ip_payload_len);
        tcp_header = (struct tcphdr *)(ip_header_address + 40);
    } else {
        return 2;
    }

    if (l4proto != IPPROTO_TCP) {
        return 3;
    }
    
    // Load TCP packets info
    member_read(&evt->sport, tcp_header, source);
    member_read(&evt->dport, tcp_header, dest);
    bpf_probe_read(&evt->tcp_flags, 2, (char*)tcp_header + 12);
    evt->tcp_payload_len = evt->ip_payload_len - ((evt->tcp_flags&0x00F0) >> 2);

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

static inline int filter_skb_tcp_info(struct route_evt_t *evt, void *ctx, struct sk_buff *skb){
    
    int err = parse_skb_tcp_info(evt, ctx, skb);
    if(err){ 
        return FALSE;
    }
    
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
    evt->event_flags |= ROUTE_EVT_IF;

    if(!filter_skb_tcp_info(evt, ctx, skb)){
        return FALSE;
    }

    return TRUE;
}

static inline int do_force_trace_skb(struct route_evt_t *evt, void *ctx, struct sk_buff *skb)
{
    // Prepare event for userland
    evt->event_flags |= ROUTE_EVT_IF;

    int err = parse_skb_tcp_info(evt, ctx, skb);
    if(err){ 
        //bpf_trace_printk("do_force_trace_skb, parse_skb_tcp_info err %d, %ld:%d\n", err, evt->sport, evt->dport);
        return FALSE;
    }

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
        bpf_trace_printk("iptables nat ret record nat src addr %u:%d\n", src_a_p.addr_port[0], src_a_p.addr_port[1]);
    }

    if(nat_a_p.conn_key != 0){
        old_a_p = conn_nat_map.lookup(&nat_a_p);
        if(!old_a_p ){
            addr_port zero_a_p;
            zero_a_p.conn_key = 0;
            conn_nat_map.update(&nat_a_p, &zero_a_p);
            bpf_trace_printk("iptables nat ret record zero nat src addr %u:%d\n", nat_a_p.addr_port[0], nat_a_p.addr_port[1]);
        }
    }

    return 0;
}

static inline addr_port* clean_nat_node(addr_port* cur_node){
    addr_port* next_node = (addr_port*)conn_nat_map.lookup(cur_node);
    if(!next_node) { return 0; }
    
    bpf_trace_printk("iptables nat ret delete nat src addr %u->%d\n", cur_node->addr_port[0], cur_node->addr_port[1]);
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

    return clean_tcp_conn_trace(saddr, sport); 
}

/**
 * Attach to Kernel Interface Tracepoints
 */

int tp_net_netif_rx(struct tracepoint__net__netif_rx *args)
{
    return do_trace(args, (struct sk_buff *)args->skbaddr);
}

int tp_net_net_dev_queue(struct tracepoint__net__net_dev_queue *args)
{
    return do_trace(args, (struct sk_buff *)args->skbaddr);
}

int tp_net_napi_gro_receive_entry(struct tracepoint__net__napi_gro_receive_entry *args)
{
    return do_trace(args, (struct sk_buff *)args->skbaddr);
}

int tp_net_netif_receive_skb_entry(struct tracepoint__net__netif_receive_skb_entry *args)
{
    return do_trace(args, (struct sk_buff *)args->skbaddr);
}

int tp_sock_inet_sock_set_state(struct tracepoint__sock__inet_sock_set_state *args){

    return do_trace_state((struct sock *)args->skaddr, args->protocol, args->newstate, args->family,
                    *(__u32*)args->saddr, args->sport);
}

int tp_tcp_tcp_destroy_sock(struct tracepoint__tcp__tcp_destroy_sock *args){
    addr_port a_p; a_p.addr_port[0] = *(int*)args->daddr; a_p.addr_port[1] = bpf_ntohs(args->dport);
    //a_p.addr_port[0] = bpf_ntohl(a_p.addr_port[0]); 
    if(conn_active_map.lookup((u64*)&a_p)){
        bpf_trace_printk("tp_tcp_tcp_destroy_sock, destroy sockt %ld, %u:%d\n", a_p.conn_key, a_p.addr_port[0], a_p.addr_port[1]);
        conn_active_map.delete((u64*)&a_p);
    }

    return 0;
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
        .event_flags = ROUTE_EVT_IPTABLE,
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
    cur_ipt_do_table_args.update(&pid_tgid, &args);

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

    struct sk_buff *skb = (struct sk_buff *)ctx->bx; //magic code, don't modify it
    struct ipt_do_table_args *args;
    args = cur_ipt_do_table_args.lookup(&pid_tgid);
    if (args == 0)
    {
        return 0; // missed entry
    }
    cur_ipt_do_table_args.delete(&pid_tgid);

    // Prepare event for userland
    struct route_evt_t evt = {
        .event_flags = ROUTE_EVT_IPTABLE,
        .pid  = pid,
        .tgid  = k_pid,
    };    
    // Load packet information
    if (!do_force_trace_skb(&evt, ctx, skb)) {
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

int kp_ipt_do_table(struct pt_regs *ctx, struct sk_buff *skb, const struct nf_hook_state *state, struct xt_table *table)
{
    return __ipt_do_table_in(ctx, skb, state, table);
};

int kretp_ipt_do_table(struct pt_regs *ctx)
{
    return __ipt_do_table_out(ctx);
}

#ifdef PROBE_IPV6
int kp_ip6t_do_table(struct pt_regs *ctx, struct sk_buff *skb, const struct nf_hook_state *state, struct xt_table *table)
{
    return __ipt_do_table_in(ctx, skb, state, table);
};

int kretp_ip6t_do_table(struct pt_regs *ctx)
{
    return __ipt_do_table_out(ctx);
}
#endif

static inline int store_nf_nat_ipv4_args(struct pt_regs *ctx, void *priv, struct sk_buff *skb, const struct nf_hook_state *state, char* logkey){
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 k_pid = pid_tgid & 0xFFFFFFFF;
    u32 pid = pid_tgid >> 32;

    struct route_evt_t evt = {
        .event_flags = ROUTE_EVT_NAT,
        .pid  = pid,
        .tgid  = k_pid,
    };

    if(!filter_skb_tcp_info(&evt, ctx, skb)){
        return 0;
    }
    u64 sk_p;
    member_read(&sk_p, skb, sk);

    // stash the arguments for use in retprobe
    struct ipt_do_nat_args args = {
        .state = state,
        .skb = skb
    };

    args.src.addr_port[0] = evt.saddr; args.src.addr_port[1] = evt.sport;
    args.dst.addr_port[0] = evt.daddr; args.dst.addr_port[1] = evt.dport;

    if (!conn_active_map.lookup((u64*)&args.dst)){
        bpf_trace_printk("store_nf_nat_ipv4_args, cant't found sk %u:%d, action %s\n", args.dst.addr_port[0], args.dst.addr_port[1], logkey);
        return 0;
    }

    cur_ipt_do_nat_args.update(&pid_tgid, &args);

    return 0;   
}

int kp_nf_nat_ipv4_in(struct pt_regs *ctx, void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    char p[] = "natin";
    return store_nf_nat_ipv4_args(ctx, priv, skb, state, p);
} 

int kp_nf_nat_ipv4_out(struct pt_regs *ctx, void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    char p[] = "natout";
    return store_nf_nat_ipv4_args(ctx, priv, skb, state, p);
} 

int kp_ip_forward(struct pt_regs *ctx, struct sk_buff *skb) {
    char p[] = "foward";
    return store_nf_nat_ipv4_args(ctx, (void*)0, skb, (void*)0, p);
}

int kretp_nf_nat_ipv4_out(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 k_pid = pid_tgid & 0xFFFFFFFF;
    u32 pid = pid_tgid >> 32;

    struct ipt_do_nat_args *args = (struct ipt_do_nat_args*)cur_ipt_do_nat_args.lookup(&pid_tgid);
    if (args == 0)
    {
        return 0; // missed entry
    }
    cur_ipt_do_nat_args.delete(&pid_tgid);
    struct sk_buff *skb = args->skb;
    struct route_evt_t evt = {
        .event_flags = ROUTE_EVT_NAT,
        .pid  = pid,
        .tgid  = k_pid,
    };

    if (!do_force_trace_skb(&evt, ctx, skb)) {
        return 0;
    }

    int ret = PT_REGS_RC(ctx);
    if (evt.saddr != args->src.addr_port[0] || evt.sport != args->src.addr_port[1]){
        insert_tcp_conn_trace(args->src.addr_port[0], args->src.addr_port[1], evt.saddr, evt.sport);
        
        evt.daddr = evt.saddr; evt.dport = evt.sport;
        evt.saddr = args->src.addr_port[0];  evt.sport = args->src.addr_port[1];
        sprintf(evt.tablename, "%s", "snatlog");
    } else if (ret != NF_DROP) {
        return 0;
    }
    
    evt.verdict = ret;
    const struct nf_hook_state *state = args->state;
    member_read(&evt.hook, state, hook);

    bpf_get_current_comm(evt.comm_name, sizeof(evt.comm_name));

    route_evt.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

int kretp_nf_nat_ipv4_in(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 k_pid = pid_tgid & 0xFFFFFFFF;
    u32 pid = pid_tgid >> 32;

    struct ipt_do_nat_args *args = (struct ipt_do_nat_args*)cur_ipt_do_nat_args.lookup(&pid_tgid);
    if (args == 0)
    {
        return 0; // missed entry
    }
    cur_ipt_do_nat_args.delete(&pid_tgid);
    struct sk_buff *skb = args->skb;
    struct route_evt_t evt = {
        .event_flags = ROUTE_EVT_NAT,
        .pid  = pid,
        .tgid  = k_pid,
    };

    if (!do_force_trace_skb(&evt, ctx, skb)) {
        return 0;
    }

    sprintf(evt.tablename, "%s", "dnatlog");
    int ret = PT_REGS_RC(ctx);
    evt.verdict = ret;
    const struct nf_hook_state *state = args->state;
    member_read(&evt.hook, state, hook);

    bpf_get_current_comm(evt.comm_name, sizeof(evt.comm_name));

    route_evt.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

int kretp_ip_forward(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 k_pid = pid_tgid & 0xFFFFFFFF;
    u32 pid = pid_tgid >> 32;

    struct ipt_do_nat_args *args = (struct ipt_do_nat_args*)cur_ipt_do_nat_args.lookup(&pid_tgid);
    if (args == 0)
    {
        return 0; // missed entry
    }
    cur_ipt_do_nat_args.delete(&pid_tgid);
    struct sk_buff *skb = args->skb;
    struct route_evt_t evt = {
        .event_flags = ROUTE_EVT_NAT,
        .pid  = pid,
        .tgid  = k_pid,
    };

    if (!do_force_trace_skb(&evt, ctx, skb)) {
        return 0;
    }

    // TODO
    return 0;
}

int kp_tcp_connect(struct pt_regs *ctx, struct sock *sk) {

#ifdef ENABLE_CGROUP_CHECK
    if (__cgroup_filter.check_current_task(0) <= 0) {
        int key = 0;
        bpf_trace_printk("tcp_connect, hit cgroup %ld\n",
            bpf_map_lookup_elem(&__cgroup_filter, &key));
        return 0;
    }
#endif

    struct inet_sock *inet = inet_sk(sk);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 k_pid = pid_tgid & 0xFFFFFFFF;
    u32 pid = pid_tgid >> 32;

    struct route_evt_t evt = {
        .event_flags = ROUTE_EVT_CONNECT,
        .pid  = pid,
        .tgid  = k_pid,
    };

    member_read(&evt.saddr, inet, inet_saddr);
    member_read(&evt.sport, inet, inet_sport);

    if(evt.saddr != CONTAINER_FILTER){
        return 0;
    }

    if(!conn_status_map.lookup(&pid_tgid)){
        struct sock_common sock_comm;
        member_read(&sock_comm, sk, __sk_common);
        struct conn_status_args status = {};
        status.addr = sock_comm.skc_daddr;
        status.port = sock_comm.skc_dport;
        status.start = bpf_ktime_get_ns();

        if(!filter_connect_dst(sock_comm.skc_daddr, sock_comm.skc_dport)){
            return 0;
        }

        insert_tcp_conn_trace(evt.saddr, evt.sport, 0, 0);
        conn_status_map.update(&pid_tgid, &status);
        u64 flag = 0;
        
        addr_port a_p; a_p.addr_port[0] = sock_comm.skc_daddr;  a_p.addr_port[1] = sock_comm.skc_dport;
        conn_active_map.update((u64*)&a_p, &flag);
        bpf_trace_printk("tcp_connect, insert sockt %ld, %u:%d\n", a_p.conn_key, a_p.addr_port[0], a_p.addr_port[1]);
    }
    
    return 0;
}

int kp___sys_connect(struct pt_regs *ctx, 
                    int fd, struct sockaddr *uservaddr, int addrlen)
{
    return 0;
}

int kretp___sys_connect(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 k_pid = pid_tgid & 0xFFFFFFFF;
    u32 pid = pid_tgid >> 32;

    struct conn_status_args* status = (struct conn_status_args*)conn_status_map.lookup(&pid_tgid);
    if(!status) { return 0;}
    conn_status_map.delete(&pid_tgid);

    int retval = PT_REGS_RC(ctx);
    if(!retval){
        return 0; 
    }

    struct route_evt_t evt = {
        .event_flags = ROUTE_EVT_CONNECT,
        .pid  = pid,
        .tgid  = k_pid,
    };

    bpf_get_current_comm(evt.comm_name, sizeof(evt.comm_name));
    evt.daddr = status->addr; evt.dport = status->port;
    evt.data[0] =  0 - retval;
    evt.data[1] = (bpf_ktime_get_ns() - status->start) / 1000000;
    route_evt.perf_submit(ctx, &evt, sizeof(evt));
    bpf_trace_printk("on connect error, ret %d, speedtime %d\n", evt.data[0], evt.data[1]);
    return 0;
}

int kp_tcp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int event_flags, int *addr_len){
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct inet_sock *inet = inet_sk(sk);
    u32 inet_saddr;
    u16 inet_sport;
    member_read(&inet_saddr, inet, inet_saddr);
    member_read(&inet_sport, inet, inet_sport);
    
    addr_port a_p; a_p.addr_port[0] = inet_saddr; a_p.addr_port[1] = inet_sport;

    if(!conn_nat_map.lookup(&a_p)) {
        return 0;
    }

    struct sock_common sock_comm;
    member_read(&sock_comm, sk, __sk_common);

    struct conn_status_args status = {};
    status.addr = sock_comm.skc_daddr;
    status.port = sock_comm.skc_dport;
    status.start = bpf_ktime_get_ns();
    
    conn_rw_map.update(&pid_tgid, &status);    
    return 0;
}

int kretp_tcp_recvmsg(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 k_pid = pid_tgid & 0xFFFFFFFF;
    u32 pid = pid_tgid >> 32;

    struct conn_status_args* status = (struct conn_status_args*)conn_rw_map.lookup(&pid_tgid);
    if(!status) { return 0;}
    conn_rw_map.delete(&pid_tgid);

    int retval = PT_REGS_RC(ctx);
    if(retval > 0 || retval == -EAGAIN) {
        return 0; 
    }

    struct route_evt_t evt = {
        .event_flags = ROUTE_EVT_READ,
        .pid  = pid,
        .tgid  = k_pid,
    };

    bpf_get_current_comm(evt.comm_name, sizeof(evt.comm_name));
    evt.daddr = status->addr; evt.dport = status->port;
    evt.data[0] =  retval;
    evt.data[1] = (bpf_ktime_get_ns() - status->start) / 1000000;
    route_evt.perf_submit(ctx, &evt, sizeof(evt));
    bpf_trace_printk("on tcp_recvmsg error, ret %d, speedtime %d, flags %d\n", evt.data[0], evt.data[1], evt.event_flags);
    return 0;
}

int kp_tcp_retransmit_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb, int segs) {
    return 0;
}

int kretp_tcp_retransmit_skb(struct pt_regs *ctx) {
    return 0;
}