/*
 * NetSentinel eBPF/XDP Kernel Hook Template
 * Demonstrates high-throughput line-rate packet parsing and 5-tuple flow aggregation
 * using eBPF/XDP with BPF hash maps. Compatible with BCC and libbpf.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_FLOW_ENTRIES 65536

// 5-tuple flow key definition
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  pad[3];
};

// Flow statistical metrics stored in kernel BPF map
struct flow_metrics {
    __u64 packets_forward;
    __u64 bytes_forward;
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u32 syn_count;
    __u32 ack_count;
    __u32 fin_count;
    __u32 rst_count;
    __u8  drop_flag;
};

// BPF Map for flow tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOW_ENTRIES);
    __type(key, struct flow_key);
    __type(value, struct flow_metrics);
} flow_table SEC(".maps");

// BPF Map for blocked IP blacklist (hardware-rate filtering)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);   // IPv4 address
    __type(value, __u8);  // 1 = Block
} blacklist_map SEC(".maps");

SEC("xdp")
int netsentinel_xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 now = bpf_ktime_get_ns();

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IPv4 header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Line-rate blacklist check (O(1) look-up)
    __u32 src_ip = ip->saddr;
    __u8 *blocked = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    if (blocked && *blocked == 1) {
        return XDP_DROP; // Mitigate immediately at network interface layer
    }

    // Extract 5-tuple
    struct flow_key key = {};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.proto = ip->protocol;

    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u8 is_syn = 0, is_ack = 0, is_fin = 0, is_rst = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
        is_syn = tcp->syn;
        is_ack = tcp->ack;
        is_fin = tcp->fin;
        is_rst = tcp->rst;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    }

    key.src_port = src_port;
    key.dst_port = dst_port;

    __u64 pkt_len = (__u64)(data_end - data);

    // Update flow counters in BPF map
    struct flow_metrics *metrics = bpf_map_lookup_elem(&flow_table, &key);
    if (metrics) {
        __sync_fetch_and_add(&metrics->packets_forward, 1);
        __sync_fetch_and_add(&metrics->bytes_forward, pkt_len);
        metrics->last_seen_ns = now;
        if (is_syn) __sync_fetch_and_add(&metrics->syn_count, 1);
        if (is_ack) __sync_fetch_and_add(&metrics->ack_count, 1);
        if (is_fin) __sync_fetch_and_add(&metrics->fin_count, 1);
        if (is_rst) __sync_fetch_and_add(&metrics->rst_count, 1);
    } else {
        struct flow_metrics new_metrics = {
            .packets_forward = 1,
            .bytes_forward = pkt_len,
            .first_seen_ns = now,
            .last_seen_ns = now,
            .syn_count = is_syn ? 1 : 0,
            .ack_count = is_ack ? 1 : 0,
            .fin_count = is_fin ? 1 : 0,
            .rst_count = is_rst ? 1 : 0,
            .drop_flag = 0
        };
        bpf_map_update_elem(&flow_table, &key, &new_metrics, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
