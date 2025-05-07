#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "../include/xdp-firewall.h"

#define ETH_P_IP 0x0800
#define MOD 1773884659UL
#define EXP 131073UL

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

static __always_inline bool is_port_allowed(__u16 port) {
    __u8 *value;
    value = bpf_map_lookup_elem(&allowed_ports, &port);
    return value != NULL;
}

static inline __u64 ntohll(__u64 x) {
    return (((x & 0xff00000000000000ULL) >> 56) |
            ((x & 0x00ff000000000000ULL) >> 40) |
            ((x & 0x0000ff0000000000ULL) >> 24) |
            ((x & 0x000000ff00000000ULL) >> 8)  |
            ((x & 0x00000000ff000000ULL) << 8)  |
            ((x & 0x0000000000ff0000ULL) << 24) |
            ((x & 0x000000000000ff00ULL) << 40) |
            ((x & 0x00000000000000ffULL) << 56));
}

static __always_inline uint64_t mod_exp(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

static __always_inline bool decrypt_and_compare(uint64_t *msg, char *expected) {
    // Decrypt 64-bits at a time and compare byte by byte

    uint64_t time = mod_exp(ntohll(msg[0]), EXP, MOD);
    if (time < ((bpf_ktime_get_ns() / 1000000000) - 10000)) return false;

    uint64_t decrypted0 = mod_exp(ntohll(msg[1]), EXP, MOD); // Decrypt first 64 bits
    // uint64_t decrypted0 = msg[0];

    if (((char *)&decrypted0)[0] != expected[0]) return false;
    if (((char *)&decrypted0)[1] != expected[1]) return false;
    if (((char *)&decrypted0)[2] != expected[2]) return false;
    if (((char *)&decrypted0)[3] != expected[3]) return false;
    if (((char *)&decrypted0)[4] != expected[4]) return false;
    if (((char *)&decrypted0)[5] != expected[5]) return false;
    if (((char *)&decrypted0)[6] != expected[6]) return false;
    if (((char *)&decrypted0)[7] != expected[7]) return false;

    uint64_t decrypted1 = mod_exp(ntohll(msg[2]), EXP, MOD); // Decrypt first 64 bits
    // uint64_t decrypted1 = msg[1];

    if (((char *)&decrypted1)[0] != expected[8]) return false;
    if (((char *)&decrypted1)[1] != expected[9]) return false;
    if (((char *)&decrypted1)[2] != expected[10]) return false;
    if (((char *)&decrypted1)[3] != expected[11]) return false;
    if (((char *)&decrypted1)[4] != expected[12]) return false;
    if (((char *)&decrypted1)[5] != expected[13]) return false;
    if (((char *)&decrypted1)[6] != expected[14]) return false;
    if (((char *)&decrypted1)[7] != expected[15]) return false;

    return true;
}

static __always_inline bool has_valid_password(struct ethhdr *eth, void *data_end) {
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

    return decrypt_and_compare((uint64_t *)incoming_pw->password, (char *)expected_pw->password);
}

SEC("xdp")
int check_passwd(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    // Drop non-IPv4
    if ((void *)(eth + 1) > data_end || bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_DROP;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    // Drop non-UDP
    if (ip->protocol != IPPROTO_UDP)
        return XDP_DROP;

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

SEC("xdp")
int filter_pass(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    return XDP_DROP;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;
    struct passwd_hdr *pw = (struct passwd_hdr *)(ip + 1);
    struct udphdr *udp = (struct udphdr *)((char *)pw + sizeof(struct passwd_hdr));
    if ((void *)(udp + 1) > data_end)
        return XDP_DROP;

    char *pw_start = (char *)pw;
    char *payload = (char *)(udp);
    int payload_len = (char *)data_end - payload;
    size_t shift_len = ((void *)data_end) - ((void *)udp);

    if (payload + shift_len > ((char *)data_end))
        return XDP_DROP;

    // if (udp + shift_len > ((char *)data_end))
    //     return XDP_DROP;

    // for (size_t i = 0; udp + i < data_end; i++) {
    //     pw_start[i] = ((char *)udp)[i];
    // }

    // __u16 old_ip_len = ip->tot_len;
    // __u16 new_ip_len = bpf_htons(bpf_ntohs(old_ip_len) - sizeof(struct passwd_hdr) - 8);
    // ip->tot_len = new_ip_len;
    //
    // ip->check = 0;
    // __u32 csum = 0;
    // __u16 *ip_u16 = (__u16 *)ip;
    // #pragma unroll
    // for (int i = 0; i < sizeof(struct iphdr) / 2; i++)
    //     csum += ip_u16[i];
    // while (csum >> 16)
    //     csum = (csum & 0xFFFF) + (csum >> 16);
    // ip->check = ~csum;
    //
    // struct udphdr *udp_new = (struct udphdr *)pw_start;
    //
    // if ((void *)(udp_new + 1) > data_end)
    //     return XDP_DROP;
    //
    // __u16 old_udp_len = udp->len;
    // __u16 new_udp_len = bpf_htons(bpf_ntohs(old_udp_len) - sizeof(struct passwd_hdr));
    // udp_new->len = new_udp_len;
    //
    // if (udp->check) {
    //     __u32 udp_csum = bpf_csum_diff((__be32 *)&old_udp_len, sizeof(old_udp_len),
    //                                    (__be32 *)&new_udp_len, sizeof(new_udp_len),
    //                                    ~udp->check & 0xFFFF);
    //     udp_new->check = ~((udp_csum + (udp_csum >> 16)) & 0xFFFF);
    // }

    return XDP_PASS;
}
