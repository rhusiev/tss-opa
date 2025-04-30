#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "../include/xdp-firewall.h"

#define ETH_P_IP 0x0800

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u16));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, MAX_PORTS);
} allowed_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct passwd_hdr));
    __uint(max_entries, 1);
} password_config SEC(".maps");

static bool has_valid_password(struct ethhdr *eth, void *data_end) {
    if ((void *)(eth + 1) > data_end)
        return false;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return false;

    if (ip->protocol != IPPROTO_UDP)
        return false;

    // Password is between IP and UDP
    struct passwd_hdr *incoming_pw = (struct passwd_hdr *)(ip + 1);
    if ((void *)(incoming_pw + 1) > data_end)
        return false;

    __u32 key = 0;
    struct passwd_hdr *expected_pw = bpf_map_lookup_elem(&password_config, &key);
    if (!expected_pw)
        return false;  // No password - reject

    // For now compare 8 bytes, simply like this
    if (incoming_pw->password[0] != expected_pw->password[0])
        return false;
    if (incoming_pw->password[1] != expected_pw->password[1])
        return false;
    if (incoming_pw->password[2] != expected_pw->password[2])
        return false;
    if (incoming_pw->password[3] != expected_pw->password[3])
        return false;
    if (incoming_pw->password[4] != expected_pw->password[4])
        return false;
    if (incoming_pw->password[5] != expected_pw->password[5])
        return false;
    if (incoming_pw->password[6] != expected_pw->password[6])
        return false;
    if (incoming_pw->password[7] != expected_pw->password[7])
        return false;

    return true;
}

static bool is_port_allowed(__u16 port) {
    __u8 *value;
    value = bpf_map_lookup_elem(&allowed_ports, &port);
    return value != NULL;
}

SEC("xdp")
int firewall_xdp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    // Drop non-IPv4
    if ((void *)(eth + 1) > data_end || bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_DROP;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    // Pass non-UDP
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct passwd_hdr *pw = (struct passwd_hdr *)(ip + 1);
    if ((void *)(pw + 1) > data_end)
        return XDP_DROP;

    struct udphdr *udp = (struct udphdr *)((char *)pw + sizeof(struct passwd_hdr));
    if ((void *)(udp + 1) > data_end)
        return XDP_DROP;

    __u16 dest_port = bpf_ntohs(udp->dest);
    if (!is_port_allowed(dest_port))
        return XDP_DROP;

    if (!has_valid_password(eth, data_end))
        return XDP_DROP;

    return XDP_PASS;
}
