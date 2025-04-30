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

// From https://github.com/andrewkiluk/RSA-Library
static int rsa_decrypt(const long long *message, char *decrypted,
                    const unsigned long message_size,
                    uint64_t modulus, uint64_t exponent);

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
    char result[32];
    rsa_decrypt(incoming_pw->password, result, sizeof(struct passwd_hdr), MOD, EDP);

    __u32 key = 0;
    struct passwd_hdr *expected_pw = bpf_map_lookup_elem(&password_config, &key);
    if (!expected_pw)
        return false;  // No password - reject

    // For now compare 8 bytes, simply like this
    if (result[0] != expected_pw->password[0])
        return false;
    if (result[1] != expected_pw->password[1])
        return false;
    if (result[2] != expected_pw->password[2])
        return false;
    if (result[3] != expected_pw->password[3])
        return false;
    if (result[4] != expected_pw->password[4])
        return false;
    if (result[5] != expected_pw->password[5])
        return false;
    if (result[6] != expected_pw->password[6])
        return false;
    if (result[7] != expected_pw->password[7])
        return false;

    return true;
}

static bool is_port_allowed(__u16 port) {
    __u8 *value;
    value = bpf_map_lookup_elem(&allowed_ports, &port);
    return value != NULL;
}

// From https://github.com/andrewkiluk/RSA-Library
static inline uint64_t modmult(uint64_t a, uint64_t b, uint64_t mod) {
  // this is necessary since we will be dividing by a
  if (a == 0) {
    return 0;
  }
  register uint64_t product = a * b;
  // if multiplication does not overflow, we can use it
  if (product / a == b) {
    return product % mod;
  }
  // if a % 2 == 1 i. e. a >> 1 is not a / 2
  if (a & 1) {
    product = modmult((a >> 1), b, mod);
    if ((product << 1) > product) {
      return (((product << 1) % mod) + b) % mod;
    }
  }
  // implicit else
  product = modmult((a >> 1), b, mod);
  if ((product << 1) > product) {
    return (product << 1) % mod;
  }
  // implicit else: this is about 10x slower than the code above, but it will
  // not overflow
  uint64_t sum;
  sum = 0;
  while (b > 0) {
    if (b & 1)
      sum = (sum + a) % mod;
    a = (2 * a) % mod;
    b >>= 1;
  }
  return sum;
}

// From https://github.com/andrewkiluk/RSA-Library
uint64_t rsa_modExp(uint64_t b, uint64_t e, uint64_t m) {
  uint64_t product;
  product = 1;
  if (b < 0 || e < 0 || m <= 0) {
    return -1;
  }
  b = b % m;
  while (e > 0) {
    if (e & 1) {
      product = modmult(product, b, m);
    }
    b = modmult(b, b, m);
    e >>= 1;
  }
  return product;
}

// From https://github.com/andrewkiluk/RSA-Library
static int rsa_decrypt(const long long *message, char *decrypted,
                    const unsigned long message_size,
                    uint64_t modulus, uint64_t exponent) {
  if (message_size % sizeof(uint64_t) != 0) {
    fprintf(stderr,
            "Error: message_size is not divisible by %d, so cannot be output "
            "of rsa_encrypt\n",
            (int)sizeof(uint64_t));
    return NULL;
  }
  // We allocate space to do the decryption (temp) and space for the output as a
  // char array (decrypted)
  // char *temp = malloc(message_size);
  if ((decrypted == NULL) || (temp == NULL)) {
    fprintf(stderr, "Error: Heap allocation failed.\n");
    return 1;
  }
  // Now we go through each 8-byte chunk and decrypt it.
  for (size_t i = 0; i < message_size / 8; i++) {
    decrypted[i] = rsa_modExp(message[i], priv->exponent, priv->modulus)) ==
  }
  return 0;
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

    char *pw_start = (char *)pw;
    char *payload = (char *)(udp + 1);
    int payload_len = (char *)data_end - payload;
    size_t shift_len = packet_end - udp_start;

    if (pw_start + shift_len > packet_end)
        return XDP_DROP;

    for (size_t i = 0; i < shift_len; i++) {
        pw_start[i] = udp[i];
    }

    __u16 old_ip_len = ip->tot_len;
    __u16 new_ip_len = bpf_htons(bpf_ntohs(old_ip_len) - sizeof(struct passwd_hdr));
    ip->tot_len = new_ip_len;

    ip->check = 0;
    __u32 csum = 0;
    __u16 *ip_u16 = (__u16 *)ip;
    for (int i = 0; i < sizeof(struct iphdr) / 2; i++)
        csum += ip_u16[i];
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = ~csum;

    struct udphdr *udp_new = (struct udphdr *)pw_start;
    __u16 old_udp_len = udp->len;
    __u16 new_udp_len = bpf_htons(bpf_ntohs(old_udp_len) - sizeof(struct passwd_hdr));
    udp_new->len = new_udp_len;

    if (udp->check) {
        __u32 udp_csum = bpf_csum_diff((__be32 *)&old_udp_len, sizeof(old_udp_len),
                                       (__be32 *)&new_udp_len, sizeof(new_udp_len),
                                       ~udp->check & 0xFFFF);
        udp_new->check = ~((udp_csum + (udp_csum >> 16)) & 0xFFFF);
    }

    return XDP_PASS;
}
