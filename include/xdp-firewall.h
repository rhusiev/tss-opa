#ifndef XDP_FIREWALL_H
#define XDP_FIREWALL_H

#define MAX_PORTS 128
#define PASSWORD_SIZE 128

/* Password header structure (must match the one in XDP program) */
struct passwd_hdr {
    unsigned char password[PASSWORD_SIZE];
};

#endif /* XDP_FIREWALL_H */
