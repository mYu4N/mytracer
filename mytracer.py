#!/usr/bin/env python
# coding: utf-8

import sys
import socket
from socket import inet_ntop, AF_INET, AF_INET6
from bcc import BPF
import ctypes as ct
import subprocess
from struct import pack
import argparse
import time
import struct
import datetime

examples = """examples:
      mytracer.py                                      # trace all packets
      mytracer.py --proto=icmp -H 140.205.60.46 --icmpid 22  # trace icmp packet with addr=140.205.60.46 and icmpid=22
      mytracer.py --proto=tcp  -H 140.205.60.46 -P 22        # trace tcp  packet with addr=140.205.60.46:22
      mytracer.py --proto=udp  -H 140.205.60.46 -P 22        # trace udp  packet wich addr=140.205.60.46:22
      mytracer.py -T -p 1 --debug -P 80 -H 127.0.0.1 --proto=tcp --callstack --icmpid=100 -N 10000
"""

parser = argparse.ArgumentParser(
    description="Trace any packet through TCP/IP stack",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("-H", "--ipaddr", type=str,
    help="ip address")

parser.add_argument("--proto", type=str,
    help="tcp|udp|icmp|any ")

parser.add_argument("--icmpid", type=int, default=0,
    help="trace icmp id")

parser.add_argument("-c", "--catch-count", type=int, default=1000000,
    help="catch and print count")

parser.add_argument("-P", "--port", type=int, default=0,
    help="udp or tcp port")

parser.add_argument("-p", "--pid", type=int, default=0,
    help="trace this PID only")

parser.add_argument("-N", "--netns", type=int, default=0,
    help="trace this Network Namespace only")

parser.add_argument("--dropstack", action="store_true",
    help="output kernel stack trace when drop packet,kfree_skb")

parser.add_argument("--callstack", action="store_true",
    help="output kernel stack trace")

parser.add_argument("--iptable", action="store_true",
    help="output iptable path")

parser.add_argument("--route", action="store_true",
    help="output route path")

parser.add_argument("--keep", action="store_true",
    help="keep trace packet all lifetime")

parser.add_argument("-T", "--time", action="store_true",
    help="show HH:MM:SS timestamp")

parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)

parser.add_argument("--debug", action="store_true",
    help=argparse.SUPPRESS)

args = parser.parse_args()
if args.debug == True:
    print("pid=%d time=%d ipaddr=%s port=%d netns=%d proto=%s icmpid=%d dropstack=%d" % \
            (args.pid,args.time,args.ipaddr, args.port,args.netns,args.proto,args.icmpid, args.dropstack))
    sys.exit()


ipproto={}
#ipproto["tcp"]="IPPROTO_TCP"
ipproto["tcp"]="6"
#ipproto["udp"]="IPPROTO_UDP"
ipproto["udp"]="17"
#ipproto["icmp"]="IPPROTO_ICMP"
ipproto["icmp"]="1"
proto = 0 if args.proto == None else (0 if ipproto.get(args.proto) == None else ipproto[args.proto])
#ipaddr=socket.htonl(struct.unpack("I",socket.inet_aton("0" if args.ipaddr == None else args.ipaddr))[0])
#port=socket.htons(args.port)
ipaddr=(struct.unpack("I",socket.inet_aton("0" if args.ipaddr == None else args.ipaddr))[0])
port=(args.port)
icmpid=socket.htons(args.icmpid)

bpf_def="#define __BCC_ARGS__\n"
bpf_args="#define __BCC_pid (%d)\n" % (args.pid)
bpf_args+="#define __BCC_ipaddr (0x%x)\n" % (ipaddr)
bpf_args+="#define __BCC_port (%d)\n" % (port)
bpf_args+="#define __BCC_netns (%d)\n" % (args.netns)
bpf_args+="#define __BCC_proto (%s)\n" % (proto)
bpf_args+="#define __BCC_icmpid (%d)\n" % (icmpid)
bpf_args+="#define __BCC_dropstack (%d)\n" % (args.dropstack)
bpf_args+="#define __BCC_callstack (%d)\n" % (args.callstack)
bpf_args+="#define __BCC_iptable (%d)\n" % (args.iptable)
bpf_args+="#define __BCC_route (%d)\n" % (args.route)
bpf_args+="#define __BCC_keep (%d)\n" % (args.keep)


# bpf_text=open(r"mytracer.c", "r").read()
bpf_text= """
#include <bcc/proto.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/icmpv6.h>
#include <net/inet_sock.h>
#include <linux/netfilter/x_tables.h>
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/tcp.h>

#define ROUTE_EVENT_IF 		0x0001
#define ROUTE_EVENT_IPTABLE	0x0002
#define ROUTE_EVENT_DROP 	0x0004
#define ROUTE_EVENT_NEW 	0x0010

#ifdef __BCC_ARGS__
__BCC_ARGS_DEFINE__
#else
#define __BCC_pid        0
#define __BCC_ipaddr     0
#define __BCC_port       0
#define __BCC_icmpid     0
#define __BCC_dropstack  0
#define __BCC_callstack  0
#define __BCC_iptable    0
#define __BCC_route      0
#define __BCC_keep       0
#define __BCC_proto      0
#define __BCC_netns      0
#endif

/* route info as default  */
#if !__BCC_dropstack && !__BCC_iptable && !__BCC_route
#undef __BCC_route
#define __BCC_route      1
#endif

#if (__BCC_dropstack) || (!__BCC_pid && !__BCC_ipaddr && !__BCC_port && !__BCC_icmpid &&! __BCC_proto && !__BCC_netns)
#undef __BCC_keep
#define __BCC_keep 0
#endif

BPF_STACK_TRACE(stacks, 2048);

#define FUNCNAME_MAX_LEN 64
struct event_t {
    char func_name[FUNCNAME_MAX_LEN];
    u8 flags;

    // route info
    char comm[IFNAMSIZ];
    char ifname[IFNAMSIZ];

    u32  netns;

    // pkt info
    u8 dest_mac[6];
    u32 len;
    u8 ip_version;
    u8 l4_proto;
    u64 saddr[2];
    u64 daddr[2];
    u8 icmptype;
    u16 icmpid;
    u16 icmpseq;
    u16 sport;
    u16 dport;
    u16 tcpflags;
    u32 seq;
    u32 ack_seq;
 //   u32 tcp_len;

    // ipt info
    u32 hook;
    u8 pf;
    u32 verdict;
    char tablename[XT_TABLE_MAXNAMELEN];

    void *skb;
    // skb info
    u8 pkt_type; //skb->pkt_type

    // call stack
    int kernel_stack_id;
    u64 kernel_ip;

    //time
    u64 test;
};
BPF_PERF_OUTPUT(route_event);

struct ipt_do_table_args
{
    struct sk_buff *skb;
    const struct nf_hook_state *state;
    struct xt_table *table;
};
BPF_HASH(cur_ipt_do_table_args, u32, struct ipt_do_table_args);

union ___skb_pkt_type {
    __u8 value;
    struct {
        __u8			__pkt_type_offset[0];
        __u8			pkt_type:3;
        __u8			pfmemalloc:1;
        __u8			ignore_df:1;

        __u8			nf_trace:1;
        __u8			ip_summed:2;
    };
};

#if __BCC_keep
#endif

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

enum {
__TCP_FLAG_CWR,
__TCP_FLAG_ECE,
__TCP_FLAG_URG,
__TCP_FLAG_ACK,
__TCP_FLAG_PSH,
__TCP_FLAG_RST,
__TCP_FLAG_SYN,
__TCP_FLAG_FIN
};

static void bpf_strncpy(char *dst, const char *src, int n)
{
    int i = 0, j;
#define CPY(n) \
    do { \
        for (; i < n; i++) { \
            if (src[i] == 0) return; \
            dst[i] = src[i]; \
        } \
    } while(0)

    for (j = 10; j < 64; j += 10)
    	CPY(j);
    CPY(64);
#undef CPY
}

#define TCP_FLAGS_INIT(new_flags, orig_flags, flag) \
    do { \
        if (orig_flags & flag) { \
            new_flags |= (1U<<__##flag); \
        } \
    } while (0)
#define init_tcpflags_bits(new_flags, orig_flags) \
    ({ \
        new_flags = 0; \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_CWR); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_ECE); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_URG); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_ACK); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_PSH); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_RST); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_SYN); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_FIN); \
    })

static void get_stack(struct pt_regs *ctx, struct event_t *event)
{
    event->kernel_stack_id = stacks.get_stackid(ctx, 0);
    if (event->kernel_stack_id >= 0) {
        u64 ip = PT_REGS_IP(ctx);
        u64 page_offset;
        // if ip isn't sane, leave key ips as zero for later checking
#if defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE)
        // x64, 4.16, ..., 4.11, etc., but some earlier kernel didn't have it
        page_offset = __PAGE_OFFSET_BASE;
#elif defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE_L4)
        // x64, 4.17, and later
#if defined(CONFIG_DYNAMIC_MEMORY_LAYOUT) && defined(CONFIG_X86_5LEVEL)
        page_offset = __PAGE_OFFSET_BASE_L5;
#else
        page_offset = __PAGE_OFFSET_BASE_L4;
#endif
#else
        // earlier x86_64 kernels, e.g., 4.6, comes here
        // arm64, s390, powerpc, x86_32
        page_offset = PAGE_OFFSET;
#endif
        if (ip > page_offset) {
            event->kernel_ip = ip;
        }
    }
    return;
}

#define CALL_STACK(ctx, event) \
do { \
if (__BCC_callstack) \
    get_stack(ctx, event); \
} while (0)


/**
  * Common tracepoint handler. Detect IPv4/IPv6 and
  * emit event with address, interface and namespace.
  */
static int
do_trace_skb(struct event_t *event, void *ctx, struct sk_buff *skb, void *netdev)
{
    struct net_device *dev;

    char *head;
    char *l2_header_address;
    char *l3_header_address;
    char *l4_header_address;

    u16 mac_header;
    u16 network_header;

    u8 proto_icmp_echo_request;
    u8 proto_icmp_echo_reply;
    u8 l4_offset_from_ip_header;

    struct icmphdr icmphdr;
    union tcp_word_hdr tcphdr;
    struct udphdr udphdr;

    // Get device pointer, we'll need it to get the name and network namespace
    event->ifname[0] = 0;
    if (netdev)
        dev = netdev;
    else
        member_read(&dev, skb, dev);

    bpf_probe_read(&event->ifname, IFNAMSIZ, dev->name);

    if (event->ifname[0] == 0 || dev == NULL)
        bpf_strncpy(event->ifname, "nil", IFNAMSIZ);

    event->flags |= ROUTE_EVENT_IF;

#ifdef CONFIG_NET_NS
    struct net* net;

    // Get netns id. The code below is equivalent to: event->netns = dev->nd_net.net->ns.inum
    possible_net_t *skc_net = &dev->nd_net;
    member_read(&net, skc_net, net);
    struct ns_common *ns = member_address(net, ns);
    member_read(&event->netns, ns, inum);

    // maybe the skb->dev is not init, for this situation, we can get ns by sk->__sk_common.skc_net.net->ns.inum
    if (event->netns == 0) {
        struct sock *sk;
        struct sock_common __sk_common;
        struct ns_common* ns2;
        member_read(&sk, skb, sk);
        if (sk != NULL) {
            member_read(&__sk_common, sk, __sk_common);
            ns2 = member_address(__sk_common.skc_net.net, ns);
            member_read(&event->netns, ns2, inum);
        }
    }


#endif

    member_read(&event->len, skb, len);
    member_read(&head, skb, head);
    member_read(&mac_header, skb, mac_header);
    member_read(&network_header, skb, network_header);

    if(network_header == 0) {
        network_header = mac_header + MAC_HEADER_SIZE;
    }

    l2_header_address = mac_header + head;
    bpf_probe_read(&event->dest_mac, 6, l2_header_address);

    l3_header_address = head + network_header;
    bpf_probe_read(&event->ip_version, sizeof(u8), l3_header_address);
    event->ip_version = event->ip_version >> 4 & 0xf;

    if (event->ip_version == 4) {
        struct iphdr iphdr;
        bpf_probe_read(&iphdr, sizeof(iphdr), l3_header_address);

        l4_offset_from_ip_header = iphdr.ihl * 4;
        event->l4_proto  = iphdr.protocol;
        event->saddr[0] = iphdr.saddr;
        event->daddr[0] = iphdr.daddr;
        bpf_get_current_comm(event->comm, sizeof(event->comm));

	if (event->l4_proto == IPPROTO_ICMP) {
       	    proto_icmp_echo_request = ICMP_ECHO;
       	    proto_icmp_echo_reply   = ICMP_ECHOREPLY;
        }

    } else if (event->ip_version == 6) {
        // Assume no option header --> fixed size header
        struct ipv6hdr* ipv6hdr = (struct ipv6hdr*)l3_header_address;
        l4_offset_from_ip_header = sizeof(*ipv6hdr);

        bpf_probe_read(&event->l4_proto,  sizeof(ipv6hdr->nexthdr),  (char*)ipv6hdr + offsetof(struct ipv6hdr, nexthdr));
        bpf_probe_read(event->saddr, sizeof(ipv6hdr->saddr),   (char*)ipv6hdr + offsetof(struct ipv6hdr, saddr));
        bpf_probe_read(event->daddr, sizeof(ipv6hdr->daddr),   (char*)ipv6hdr + offsetof(struct ipv6hdr, daddr));

	if (event->l4_proto == IPPROTO_ICMPV6) {
            proto_icmp_echo_request = ICMPV6_ECHO_REQUEST;
            proto_icmp_echo_reply   = ICMPV6_ECHO_REPLY;
        }

    } else {
        return -1;
    }

    l4_header_address = l3_header_address + l4_offset_from_ip_header;
    switch (event->l4_proto) {
    case IPPROTO_ICMPV6:
    case IPPROTO_ICMP:
        bpf_probe_read(&icmphdr, sizeof(icmphdr), l4_header_address);
        if (icmphdr.type != proto_icmp_echo_request && icmphdr.type != proto_icmp_echo_reply) {
            return -1;
        }
        event->icmptype = icmphdr.type;
        event->icmpid   = be16_to_cpu(icmphdr.un.echo.id);
        event->icmpseq  = be16_to_cpu(icmphdr.un.echo.sequence);
        break;
    case IPPROTO_TCP:
        bpf_probe_read(&tcphdr, sizeof(tcphdr), l4_header_address);
        init_tcpflags_bits(event->tcpflags, tcp_flag_word(&tcphdr));
        event->sport = be16_to_cpu(tcphdr.hdr.source);
        event->dport = be16_to_cpu(tcphdr.hdr.dest);
        event->seq = be32_to_cpu(tcphdr.hdr.seq);      
        event->ack_seq = be32_to_cpu(tcphdr.hdr.ack_seq);
        // event->tcp_len = tcphdr.hdr.doff * 4;
        break;
    case IPPROTO_UDP:
        bpf_probe_read(&udphdr, sizeof(udphdr), l4_header_address);
        event->sport = be16_to_cpu(udphdr.source);
        event->dport = be16_to_cpu(udphdr.dest);
        break;
    default:
        return -1;
    }

#if __BCC_keep
#endif


    /*
     * netns filter
     */
    if (__BCC_netns !=0 && event->netns != 0 && event->netns != __BCC_netns) {
        return -1;
    }

    /*
     * pid filter
     */
#if __BCC_pid
    u64 tgid = bpf_get_current_pid_tgid() >> 32;
    if (tgid != __BCC_pid)
        return -1;
#endif

    /*
     * skb filter
     */
#if __BCC_ipaddr
   if (event->ip_version == 4) {
       if (__BCC_ipaddr != event->saddr[0] && __BCC_ipaddr != event->daddr[0])
           return -1;
   } else {
       return -1;
   }
#endif

#if __BCC_proto
   if (__BCC_proto != event->l4_proto)
       return -1;
#endif

#if __BCC_port
   if ( (event->l4_proto == IPPROTO_UDP || event->l4_proto == IPPROTO_TCP) &&
	(__BCC_port != event->sport && __BCC_port != event->dport))
       return -1;
#endif

#if __BCC_icmpid
   if (__BCC_proto == IPPROTO_ICMP && __BCC_icmpid != event->icmpid)
       return -1;
#endif

#if __BCC_keep
#endif

    return 0;
}

static int
do_trace(void *ctx, struct sk_buff *skb, const char *func_name, void *netdev)
{
    struct event_t event = {};
    union ___skb_pkt_type type = {};

    if (do_trace_skb(&event, ctx, skb, netdev) < 0)
        return 0;

    event.skb=skb;
    bpf_probe_read(&type.value, 1, ((char*)skb) + offsetof(typeof(*skb), __pkt_type_offset));
    event.pkt_type = type.pkt_type;
    bpf_strncpy(event.func_name, func_name, FUNCNAME_MAX_LEN);
    CALL_STACK(ctx, &event);
    route_event.perf_submit(ctx, &event, sizeof(event));
out:
    return 0;
}

#if __BCC_route

/*
 * netif rcv hook:
 * 1) int netif_rx(struct sk_buff *skb)
 * 2) int __netif_receive_skb(struct sk_buff *skb)
 * 3) gro_result_t napi_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
 * 4) ...
 */
int kprobe__netif_rx(struct pt_regs *ctx, struct sk_buff *skb)
{
    return do_trace(ctx, skb, __func__+8, NULL);
}

int kprobe____netif_receive_skb(struct pt_regs *ctx, struct sk_buff *skb)
{
    return do_trace(ctx, skb, __func__+8, NULL);
}

int kprobe__tpacket_rcv(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
    return do_trace(ctx, skb, __func__+8, orig_dev);
}

int kprobe__packet_rcv(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
    return do_trace(ctx, skb, __func__+8, orig_dev);
}

int kprobe__napi_gro_receive(struct pt_regs *ctx, struct napi_struct *napi, struct sk_buff *skb)
{
    return do_trace(ctx, skb, __func__+8, NULL);
}


/*
 * tcp recv hook:
 * 1) int __tcp_v4_rcv(struct sk_buff *skb, struct net_device *sb_dev)
 * 2) ...
 */

int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb)
{
    return do_trace(ctx, skb, __func__+8, NULL);
}

/*
 * skb copy hook:
 * 1) int skb_copy_datagram_iter(const struct sk_buff *skb, int offset, struct iov_iter *to, int len)
 * 2) ...
 */
int kprobe__skb_copy_datagram_iter(struct pt_regs *ctx, const struct sk_buff *skb, int offset, struct iov_iter *to, int len)
{
    return do_trace(ctx, skb, __func__+8, NULL);
}

/*
 * netif send hook:
 * 1) int __dev_queue_xmit(struct sk_buff *skb, struct net_device *sb_dev)
 * 2) ...
 */

int kprobe____dev_queue_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *sb_dev)
{
   return do_trace(ctx, skb, __func__+8, NULL);
}

/*
 * br process hook:
 * 1) rx_handler_result_t br_handle_frame(struct sk_buff **pskb)
 * 2) int br_handle_frame_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 3) unsigned int br_nf_pre_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
 * 4) int br_nf_pre_routing_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 5) int br_pass_frame_up(struct sk_buff *skb)
 * 6) int br_netif_receive_skb(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 7) void br_forward(const struct net_bridge_port *to, struct sk_buff *skb, bool local_rcv, bool local_orig)
 * 8) int br_forward_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 9) unsigned int br_nf_forward_ip(void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
 * 10)int br_nf_forward_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 11)unsigned int br_nf_post_routing(void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
 * 12)int br_nf_dev_queue_xmit(struct net *net, struct sock *sk, struct sk_buff *skb)
*/

int kprobe__br_handle_frame(struct pt_regs *ctx, struct sk_buff **pskb)
{
   return do_trace(ctx, *pskb, __func__+8, NULL);
}

int kprobe__br_handle_frame_finish(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL);
}

int kprobe__br_nf_pre_routing(struct pt_regs *ctx, void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
   return do_trace(ctx, skb, __func__+8, NULL);
}

int kprobe__br_nf_pre_routing_finish(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL);
}

int kprobe__br_pass_frame_up(struct pt_regs *ctx, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL);
}

int kprobe__br_netif_receive_skb(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL);
}


int kprobe__br_forward(struct pt_regs *ctx, const void *to, struct sk_buff *skb, bool local_rcv, bool local_orig)
{
   return do_trace(ctx, skb, __func__+8, NULL);
}

int kprobe____br_forward(struct pt_regs *ctx, const void *to, struct sk_buff *skb, bool local_orig)
{
   return do_trace(ctx, skb, __func__+8, NULL);
}

/*
if the kernel version is  5.10.x kernel(alinux3)，we need disable this probe(kprobe__deliver_clone). 
If the kernel version below 4.19(alinux2), this probe you can enable 
if you use flannel network ,please open this probe

int kprobe__deliver_clone(struct pt_regs *ctx, const void *prev, struct sk_buff *skb, bool local_orig)
{
   return do_trace(ctx, skb, __func__+8, NULL);
}


int kprobe__br_forward_finish(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL);
}

int kprobe__br_nf_forward_ip(struct pt_regs *ctx, void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
{
   return do_trace(ctx, skb, __func__+8, NULL);
}

int kprobe__br_nf_forward_finish(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL);
}

int kprobe__br_nf_post_routing(struct pt_regs *ctx, void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
{
   return do_trace(ctx, skb, __func__+8, NULL);
}

int kprobe__br_nf_dev_queue_xmit(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL);
}
*/

/*
 * ip layer:
 * 1) int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
 * 2) int ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 3) int ip_output(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 4) int ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 5) int ip_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 6) ...
 */

int kprobe__ip_rcv(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
   return do_trace(ctx, skb, __func__+8, NULL);
}

int kprobe__ip_rcv_finish(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL);
}

int kprobe__ip_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL);
}

int kprobe__ip_finish_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL);
}

#endif

#if __BCC_iptable
static int
__ipt_do_table_in(struct pt_regs *ctx, struct sk_buff *skb,
		const struct nf_hook_state *state, struct xt_table *table)
{
    u32 pid = bpf_get_current_pid_tgid();

    struct ipt_do_table_args args = {
        .skb = skb,
        .state = state,
        .table = table,
    };
    cur_ipt_do_table_args.update(&pid, &args);

    return 0;
};

static int
__ipt_do_table_out(struct pt_regs * ctx, struct sk_buff *skb)
{
    struct event_t event = {};
    union ___skb_pkt_type type = {};
    struct ipt_do_table_args *args;
    u32 pid = bpf_get_current_pid_tgid();

    args = cur_ipt_do_table_args.lookup(&pid);
    if (args == 0)
        return 0;

    cur_ipt_do_table_args.delete(&pid);

    if (do_trace_skb(&event, ctx, args->skb, NULL) < 0)
        return 0;

    event.flags |= ROUTE_EVENT_IPTABLE;
    member_read(&event.hook, args->state, hook);
    member_read(&event.pf, args->state, pf);
    member_read(&event.tablename, args->table, name);
    event.verdict = PT_REGS_RC(ctx);
    event.skb=args->skb;
    bpf_probe_read(&type.value, 1, ((char*)args->skb) + offsetof(typeof(*args->skb), __pkt_type_offset));
    event.pkt_type = type.pkt_type;
    CALL_STACK(ctx, &event);
    route_event.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

int kprobe__ipt_do_table(struct pt_regs *ctx, struct sk_buff *skb, const struct nf_hook_state *state, struct xt_table *table)
{
    return __ipt_do_table_in(ctx, skb, state, table);
};

/*
 * tricky: use ebx as the 1st parms, thus get skb
 */
int kretprobe__ipt_do_table(struct pt_regs *ctx)
{
    struct sk_buff *skb=(void*)ctx->bx;
    return __ipt_do_table_out(ctx, skb);
}
#endif


#if __BCC_dropstack
int kprobe____kfree_skb(struct pt_regs *ctx, struct sk_buff *skb)
{
    struct event_t event = {};

    if (do_trace_skb(&event, ctx, skb, NULL) < 0)
        return 0;

    event.flags |= ROUTE_EVENT_DROP;
    bpf_strncpy(event.func_name, __func__+8, FUNCNAME_MAX_LEN);
    get_stack(ctx, &event);
    route_event.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
#endif

#if 0
int kprobe__ip6t_do_table(struct pt_regs *ctx, struct sk_buff *skb, const struct nf_hook_state *state, struct xt_table *table)
{
    return __ipt_do_table_in(ctx, skb, state, table);
};

int kretprobe__ip6t_do_table(struct pt_regs *ctx)
{
    return __ipt_do_table_out(ctx);
}
#endif

"""
bpf_text=bpf_def + bpf_text
bpf_text=bpf_text.replace("__BCC_ARGS_DEFINE__", bpf_args)

if args.ebpf == True:
   print("%s" % (bpf_text))
   sys.exit()

# uapi/linux/if.h
IFNAMSIZ = 16

# uapi/linux/netfilter/x_tables.h
XT_TABLE_MAXNAMELEN = 32

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

TCPFLAGS = [
    "CWR",
    "ECE",
    "URG",
    "ACK",
    "PSH",
    "RST",
    "SYN",
    "FIN",
]

ROUTE_EVENT_IF = 0x0001
ROUTE_EVENT_IPTABLE = 0x0002
ROUTE_EVENT_DROP = 0x0004
ROUTE_EVENT_NEW = 0x0010
FUNCNAME_MAX_LEN = 64

class TestEvt(ct.Structure):
    _fields_ = [
        ("func_name",   ct.c_char * FUNCNAME_MAX_LEN),
        ("flags",       ct.c_ubyte),
        ("comm",        ct.c_char * IFNAMSIZ),
        ("ifname",      ct.c_char * IFNAMSIZ),
        ("netns",       ct.c_uint),

        ("dest_mac",    ct.c_ubyte * 6),
        ("len",         ct.c_uint),
        ("ip_version",  ct.c_ubyte),
        ("l4_proto",    ct.c_ubyte),
        ("saddr",       ct.c_ulonglong * 2),
        ("daddr",       ct.c_ulonglong * 2),
        ("icmptype",    ct.c_ubyte),
        ("icmpid",      ct.c_ushort),
        ("icmpseq",     ct.c_ushort),
        ("sport",       ct.c_ushort),
        ("dport",       ct.c_ushort),
        ("tcpflags",    ct.c_ushort),
        ("seq",         ct.c_uint),
        ("ack_seq",         ct.c_uint),

        ("hook",        ct.c_uint),
        ("pf",          ct.c_ubyte),
        ("verdict",     ct.c_uint),
        ("tablename",   ct.c_char * XT_TABLE_MAXNAMELEN),

        ("skb",         ct.c_ulonglong),
        ("pkt_type",    ct.c_ubyte),

	("kernel_stack_id", ct.c_int),
	("kernel_ip",   ct.c_ulonglong),

	("test",        ct.c_ulonglong)
    ]


def _get(l, index, default):
    '''
    Get element at index in l or return the default
    '''
    if index < len(l):
        return l[index]
    return default
def _get_tcpflags(tcpflags):
    flag=""
    start=1
    for index in range(len(TCPFLAGS)):
        if (tcpflags & (1<<index)):
            if start:
                flag += TCPFLAGS[index]
                start = 0
            else:
                flag += ","+TCPFLAGS[index]
    return flag

def trans_bytes_to_string(bbytes):
    return bbytes.decode() if isinstance(bbytes,bytes) else bbytes

def print_stack(event):
    user_stack = []
    stack_traces = b.get_table("stacks")

    kernel_stack = []
    if event.kernel_stack_id > 0:
        kernel_tmp = stack_traces.walk(event.kernel_stack_id)
        # fix kernel stack
        for addr in kernel_tmp:
            kernel_stack.append(addr)
    for addr in kernel_stack:
        print("    %s" % trans_bytes_to_string(b.sym(addr, -1, show_offset=True)))

def time_str(event):
    if args.time:
       return "%-7s " % datetime.datetime.now()
    else:
       return "%-7s " % datetime.datetime.now()

def event_printer(cpu, data, size):
    # Decode event
    event = ct.cast(data, ct.POINTER(TestEvt)).contents

    if event.ip_version == 4:
        saddr = inet_ntop(AF_INET, pack("=I", event.saddr[0]))
        daddr = inet_ntop(AF_INET, pack("=I", event.daddr[0]))
    elif event.ip_version == 6:
        saddr = inet_ntop(AF_INET6, event.saddr)
        daddr = inet_ntop(AF_INET6, event.daddr)
    else:
        return

    mac_info = ''.join('%02x' % b for b in event.dest_mac)

    if event.l4_proto == socket.IPPROTO_TCP:
        pkt_info = "T_%s:%s:%u->%s:%u" % (_get_tcpflags(event.tcpflags), saddr, event.sport, daddr, event.dport)
    elif event.l4_proto == socket.IPPROTO_UDP:
        pkt_info = "U:%s:%u->%s:%u" % (saddr, event.sport, daddr, event.dport)
    elif event.l4_proto == socket.IPPROTO_ICMP:
        if event.icmptype in [8, 128]:
            pkt_info = "I_request:%s->%s" % (saddr, daddr)
        elif event.icmptype in [0, 129]:
            pkt_info = "I_reply:%s->%s" % (saddr, daddr)
        else:
            pkt_info = "I:%s->%s" % (saddr, daddr)
    else:
        pkt_info = "%u:%s->%s" % (event.l4_proto, saddr, daddr)

    iptables = ""
    if event.flags & ROUTE_EVENT_IPTABLE == ROUTE_EVENT_IPTABLE:
        verdict = _get(NF_VERDICT_NAME, event.verdict, "~UNK~")
        hook = _get(HOOKNAMES, event.hook, "~UNK~")
        iptables = "%u.%s.%s.%s " % (event.pf, event.tablename, hook, verdict)

    trace_info = "%x.%u:%s%s" % (event.skb, event.pkt_type, iptables, trans_bytes_to_string(event.func_name))

    # Print event
    # print("[%-8s] [%-10s] %-12s %-12s %-40s %s" % (time_str(event), event.netns, event.ifname, mac_info, pkt_info, trace_info)) 
    print("[%-8s] [%-10s]  %-10s %-12s %-12s %-12s %-12s %-40s %s" % (time_str(event), event.netns, trans_bytes_to_string(event.comm), trans_bytes_to_string(event.ifname), mac_info, event.seq, event.ack_seq, pkt_info, trace_info))

    print_stack(event)
    args.catch_count = args.catch_count - 1
    if args.catch_count <= 0:
        sys.exit(0)

if __name__ == "__main__":
    b = BPF(text=bpf_text)
    b["route_event"].open_perf_buffer(event_printer)
    print("%-29s %-12s  %-10s %-12s %-12s %-12s %-12s %-40s %s" % ('Time', 'NETWORK_NS', 'COMMAND', 'INTERFACE', 'DEST_MAC', 'Seq', 'Ack', 'PKT_INFO', 'TRACE_INFO'))

    try:
        while True:
            b.kprobe_poll(10)
    except KeyboardInterrupt:
        sys.exit(0)
