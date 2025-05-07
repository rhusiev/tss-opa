#ifndef XDP_FIREWALL_H
#define XDP_FIREWALL_H

#define MAX_PORTS 16
#define PASSWORD_SIZE 16

/* Password header structure (must match the one in XDP program) */
struct passwd_hdr {
    uint64_t timestamp;
    unsigned char password[128];
};

#endif /* XDP_FIREWALL_H */
