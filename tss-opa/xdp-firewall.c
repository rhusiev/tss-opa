#include "xdp-firewall.skel.h"
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xdp-firewall.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
    if (level == LIBBPF_WARN) {
        return vfprintf(stderr, format, args);
    }
    return 0;
}

static int xdp_detach(int ifindex, __u32 xdp_flags) {
    int err;

    err = bpf_xdp_detach(ifindex, xdp_flags, NULL);
    if (err)
        fprintf(stderr, "Failed to detach XDP program from interface %d: %s\n",
                ifindex, strerror(-err));
    return err;
}

static int xdp_attach(int ifindex, int prog_fd, __u32 xdp_flags) {
    int err;

    err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
    if (err)
        fprintf(stderr, "Failed to attach XDP program to interface %d: %s\n",
                ifindex, strerror(-err));
    return err;
}

static void print_hex_password(const unsigned char *password, size_t len) {
    printf("Password set: ");
    for (size_t i = 0; i < len; i++) {
        printf("%02X", password[i]);
        if (i < len - 1)
            printf(":");
    }
    printf("\n");
}

static int setup_allowed_ports(int map_fd, uint16_t *ports, int num_ports) {
    uint8_t value = 1;
    int err;

    for (int i = 0; i < num_ports; i++) {
        err = bpf_map_update_elem(map_fd, &ports[i], &value, BPF_ANY);
        if (err) {
            fprintf(stderr, "Failed to add port %d to allowed ports map: %s\n",
                    ports[i], strerror(errno));
            return -1;
        }
        printf("Added port %d to allowed list\n", ports[i]);
    }

    return 0;
}

static int setup_password(int map_fd, const unsigned char *password,
                          size_t len) {
    struct passwd_hdr pw_config;
    uint32_t key = 0;
    int err;

    memcpy(pw_config.password, password,
           len > PASSWORD_SIZE ? PASSWORD_SIZE : len);

    err = bpf_map_update_elem(map_fd, &key, &pw_config, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to set password configuration: %s\n",
                strerror(errno));
        return -1;
    }

    print_hex_password(password, PASSWORD_SIZE);
    return 0;
}

static void usage(const char *prog) {
    fprintf(
        stderr,
        "Usage: %s [-p password] [-D] <ifname> <port1> [port2] [port3] ...\n"
        "\n"
        "       -p password   Set the 16-byte password (in hex, e.g., "
        "AABBCCDDEEFF11223344556677889900)\n"
        "       -D            Detach XDP program instead of attaching\n"
        "       -S            Use SKB mode instead of DRV mode\n"
        "       -h            Display this help and exit\n",
        prog);
}

static unsigned char *parse_hex_password(const char *hex_str, size_t *out_len) {
    size_t len = strlen(hex_str);
    unsigned char *result;
    size_t i, j;

    if (len % 2 != 0) {
        fprintf(stderr, "Invalid hex string length. Must be even.\n");
        return NULL;
    }

    *out_len = len / 2;
    result = malloc(*out_len);
    if (!result) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    for (i = 0, j = 0; i < len; i += 2, j++) {
        char byte_str[3] = {hex_str[i], hex_str[i + 1], '\0'};
        result[j] = (unsigned char)strtol(byte_str, NULL, 16);
    }

    return result;
}

int main(int argc, char **argv) {
    struct xdp_firewall_bpf *skel;
    int err, i, num_ports;
    int ifindex, map_fd;
    __u32 xdp_flags = XDP_FLAGS_DRV_MODE;
    uint16_t ports[MAX_PORTS];
    unsigned char password[PASSWORD_SIZE] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                                             0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                                             0xAA, 0xAA, 0xAA, 0xAA};
    unsigned char *custom_password = NULL;
    size_t password_len = 0;
    int opt, detach = 0;

    while ((opt = getopt(argc, argv, "p:DSh")) != -1) {
        switch (opt) {
        case 'p':
            custom_password = parse_hex_password(optarg, &password_len);
            if (!custom_password) {
                fprintf(stderr, "Invalid password format\n");
                return 1;
            }
            break;
        case 'D':
            detach = 1;
            break;
        case 'S':
            xdp_flags = XDP_FLAGS_SKB_MODE;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Expected interface name after options\n");
        usage(argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(argv[optind]);
    if (!ifindex) {
        fprintf(stderr, "Failed to get interface index for %s: %s\n",
                argv[optind], strerror(errno));
        return 1;
    }

    if (detach) {
        err = xdp_detach(ifindex, xdp_flags);
        if (custom_password)
            free(custom_password);
        return err;
    }

    num_ports = argc - optind - 1;
    if (num_ports <= 0 || num_ports > MAX_PORTS) {
        fprintf(stderr, "Please specify between 1 and %d port numbers\n",
                MAX_PORTS);
        usage(argv[0]);
        if (custom_password)
            free(custom_password);
        return 1;
    }

    for (i = 0; i < num_ports; i++) {
        ports[i] = (uint16_t)atoi(argv[optind + 1 + i]);
    }

    if (custom_password && password_len > 0) {
        memcpy(password, custom_password,
               password_len > PASSWORD_SIZE ? PASSWORD_SIZE : password_len);
        free(custom_password);
    }

    libbpf_set_print(libbpf_print_fn);

    skel = xdp_firewall_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = xdp_firewall_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        xdp_firewall_bpf__destroy(skel);
        return 1;
    }

    map_fd = bpf_map__fd(skel->maps.allowed_ports);
    err = setup_allowed_ports(map_fd, ports, num_ports);
    if (err) {
        xdp_firewall_bpf__destroy(skel);
        return 1;
    }

    map_fd = bpf_map__fd(skel->maps.password_config);
    err = setup_password(map_fd, password, PASSWORD_SIZE);
    if (err) {
        xdp_firewall_bpf__destroy(skel);
        return 1;
    }

    err = xdp_attach(ifindex, bpf_program__fd(skel->progs.firewall_xdp),
                     xdp_flags);
    if (err) {
        xdp_firewall_bpf__destroy(skel);
        return 1;
    }

    printf("Successfully attached to %s\n", argv[optind]);

    xdp_firewall_bpf__destroy(skel);
    return 0;
}
