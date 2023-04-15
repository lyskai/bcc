#!/usr/bin/env python
#
# udp_rcvbuf_errors.py	UDP RcvbufErrors analysis tool.
#
# Prints out information for UDP packets which were dropped
# a result of the socket receive buffer being full.
#
# USAGE: udp_rcvbuf_errors

# Copyright (c) 2019 Cloudflare, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 15-Jan-2019 Thomas Lefebvre Created this.

from bcc import BPF
import ctypes as ct
import argparse
from time import strftime
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack

examples = """examples:
    ./udp_rcvbuf_errors           # trace UDP RcvbufErrors kernel drops
"""
parser = argparse.ArgumentParser(
    description="Trace UDP RcvbufErrors drops by the kernel",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/udp.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <net/sock.h>
#include <net/inet_sock.h>

struct ipv4_data_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 rmem_alloc;
    u32 rcvbuf;
    u32 sk_wmem_alloc;
    u32 sk_sndbuf;
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport;
    u16 dport;
    u32 rmem_alloc;
    u32 rcvbuf;
};
BPF_PERF_OUTPUT(ipv6_events);

static struct udphdr *skb_to_udphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in udp_hdr() -> skb_transport_header().
    return (struct udphdr *)(skb->head + skb->transport_header);
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in ip_hdr() -> skb_network_header().
    return (struct iphdr *)(skb->head + skb->network_header);
}

int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len) {
    struct inet_sock *inet = (struct inet_sock *)(sk);
    struct sockaddr_in *usin = (struct sockaddr_in *)msg->msg_name;
    struct ipv4_data_t data4 = {};
        data4.sport = 111;
        //data4.dport = (u32)usin;
        //data4.dport = be16_to_cpu(inet->inet_dport);
        data4.dport = inet->inet_dport;
        data4.sk_wmem_alloc = sk->sk_wmem_alloc.refs.counter;
        data4.sk_sndbuf = sk->sk_sndbuf;
        if (data4.sk_wmem_alloc < 32992)
            return 0;
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    return 0;
}
"""


class Data_ipv4(ct.Structure):
    _fields_ = [
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("rmem_alloc", ct.c_uint),
        ("rcvbuf", ct.c_uint),
        ("sk_wmem_alloc", ct.c_uint),
        ("sk_sndbuf", ct.c_uint),
    ]


class Data_ipv6(ct.Structure):
    _fields_ = [
        ("saddr", (ct.c_ulonglong * 2)),
        ("daddr", (ct.c_ulonglong * 2)),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("rmem_alloc", ct.c_uint),
        ("rcvbuf", ct.c_uint),
    ]


def print_ipv4_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
    print("%s %-30s >> %-30s %-13s %-9s" % (
        strftime("%H:%M:%S"),
        "%s:%d" % (inet_ntop(AF_INET, pack('I', event.saddr)), event.sport),
        "%s:%s" % (inet_ntop(AF_INET, pack('I', event.daddr)), event.dport),
        event.sk_wmem_alloc,
        event.sk_sndbuf,
       ))


def print_ipv6_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv6)).contents
    print("%-8s %-30s > %-30s %-13s %-9s" % (
        strftime("%H:%M:%S"),
        "%s:%d" % (inet_ntop(AF_INET6, pack('I', event.saddr)), event.sport),
        "%s:%s" % (inet_ntop(AF_INET6, pack('I', event.daddr)), event.dport),
        event.rmem_alloc,
        event.rcvbuf,
       ))


b = BPF(text=bpf_text)

b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)

while 1:
    b.perf_buffer_poll()
