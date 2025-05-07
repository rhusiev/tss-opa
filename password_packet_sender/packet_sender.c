#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include "../include/xdp-firewall.h"


static const uint64_t MOD = 1773884659UL;
static const uint64_t EXP = 782852353UL;

uint64_t htonll(uint64_t value) {
    // Convert from little endian to big endian (network order)
    const uint32_t high_part = htonl((uint32_t)(value >> 32));
    const uint32_t low_part = htonl((uint32_t)(value & 0xFFFFFFFFLL));
    // Swap the high and low parts
    return (((uint64_t)low_part) << 32) | high_part;
}

// Checksum calculation for IP and UDP headers
unsigned short in_cksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

unsigned char *parse_hex_password(const char *hex_str, size_t *out_len) {
    size_t len = strlen(hex_str) + 8;
    unsigned char *result;
    size_t i, j;

    if (len % 2 != 0) {
        fprintf(stderr, "Invalid hex string length. Must be even.\n");
        return NULL;
    }

    *out_len = len / 2;
    result = malloc(*out_len + sizeof(uint64_t));
    uint64_t *timestamp = (uint64_t*)result;
    *timestamp = htonll(time(NULL));
    if (!result) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    for (i = 0, j = 0; i < len; i += 2, j++) {
        char byte_str[3] = {hex_str[i], hex_str[i + 1], '\0'};
        result[j + 8] = (unsigned char)strtol(byte_str, NULL, 16);
    }

    return result;
}

void print_hex_password(const unsigned char *password, size_t len) {
    printf("Using password: ");
    for (size_t i = 0; i < len; i++) {
        printf("%02X", password[i]);
        if (i < len - 1)
            printf(":");
    }
    printf("\n");
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
int rsa_encrypt(const char *message, uint64_t *encrypted,
                    const unsigned long message_size,
                    uint64_t modulus, uint64_t exponent) {
  if (encrypted == NULL) {
    fprintf(stderr, "Error: Heap allocation failed.\n");
    return 1;
  }

  for (size_t i = 0; i < message_size; i++) {
    uint64_t encrypt = rsa_modExp(message[i], exponent, modulus);
    if ((encrypted[i] = htonll(encrypt)) ==
        -1)
      return 1;
  }

  return 0;
}

int main(int argc, char **argv) {
    int sockfd;
    struct sockaddr_in dest;
    int packet_size;
    char *packet;
    struct ip *ip_header;
    struct passwd_hdr *pw_header;
    struct udphdr *udp_header;
    char *data;
    int data_len;
    unsigned char password[16] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                                             0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                             0x77, 0x88, 0x99, 0x00};
    unsigned char *custom_password = NULL;
    size_t password_len = 0;
    int opt;
    char *src_ip_str = NULL;

    if (argc < 4) {
        fprintf(stderr,
                "Usage: %s [-p password] [-s source_ip] <destination_ip> <destination_port> "
                "<message>\n",
                argv[0]);
        return 1;
    }

    /* Parse command line arguments */
    while ((opt = getopt(argc, argv, "p:s:")) != -1) {
        switch (opt) {
        case 'p':
            custom_password = parse_hex_password(optarg, &password_len);
            if (!custom_password) {
                fprintf(stderr, "Invalid password format\n");
                return 1;
            }
            break;
        case 's':
            src_ip_str = optarg;
            break;
        default:
            fprintf(
                stderr,
                "Usage: %s [-p password] [-s source_ip] <destination_ip> <destination_port> "
                "<message>\n",
                argv[0]);
            return 1;
        }
    }

    if (optind + 2 >= argc) {
        fprintf(stderr, "Need destination IP, port and message\n");
        if (custom_password)
            free(custom_password);
        return 1;
    }

    /* If custom password provided, use it */
    if (custom_password && password_len > 0) {
        memcpy(password, custom_password,
               password_len > PASSWORD_SIZE ? PASSWORD_SIZE : password_len);
        free(custom_password);
    }

    print_hex_password(password, PASSWORD_SIZE);

    /* Create raw socket */
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    /* Set destination address */
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(atoi(argv[optind + 1]));
    if (inet_pton(AF_INET, argv[optind], &dest.sin_addr) <= 0) {
        perror("inet_pton for destination IP");
        close(sockfd);
        return 1;
    }

    /* Get the message data */
    data_len = strlen(argv[optind + 2]);

    /* Allocate memory for the packet */
    packet_size = sizeof(struct ip) + sizeof(struct passwd_hdr) +
                  sizeof(struct udphdr) + data_len;
    packet = malloc(packet_size);
    if (!packet) {
        perror("malloc");
        close(sockfd);
        return 1;
    }
    memset(packet, 0, packet_size);

    /* Set up IP header */
    ip_header = (struct ip *)packet;
    ip_header->ip_v = 4;
    ip_header->ip_hl = 5;
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(packet_size);
    ip_header->ip_id = htons(54321);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 64;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_sum = 0;

    if (src_ip_str) {
        if (inet_pton(AF_INET, src_ip_str, &ip_header->ip_src) <= 0) {
            perror("inet_pton for source IP");
            free(packet);
            close(sockfd);
            return 1;
        }
        printf("Using source IP: %s\n", src_ip_str);
    } else {
        ip_header->ip_src.s_addr = inet_addr("127.0.0.1");
        printf("Using default source IP: 127.0.0.1\n");
    }

    ip_header->ip_dst.s_addr = dest.sin_addr.s_addr;

    /* Set up password header */
    pw_header = (struct passwd_hdr *)(packet + sizeof(struct ip));
    rsa_encrypt((char *)password, (uint64_t *)pw_header->timestamp, 24, MOD, EXP);
    // memcpy(pw_header->password, password, sizeof(struct passwd_hdr));

    /* Set up UDP header */
    udp_header = (struct udphdr *)(packet + sizeof(struct ip) +
                                   sizeof(struct passwd_hdr));
    udp_header->source = htons(12345); /* Source port - maybe make this an option too? */
    udp_header->dest = dest.sin_port;  /* Destination port */
    udp_header->len = htons(sizeof(struct udphdr) + data_len);
    udp_header->check = 0; /* Optional for IPv4 */

    /* Copy data */
    data = packet + sizeof(struct ip) + sizeof(struct passwd_hdr) +
           sizeof(struct udphdr);
    memcpy(data, argv[optind + 2], data_len);

    /* Calculate IP header checksum */
    ip_header->ip_sum =
        in_cksum((unsigned short *)ip_header, sizeof(struct ip));

    /* Send the packet */
    if (sendto(sockfd, packet, packet_size, 0, (struct sockaddr *)&dest,
               sizeof(dest)) < 0) {
        perror("sendto");
        free(packet);
        close(sockfd);
        return 1;
    }

    printf("Sent packet to %s:%s with message: %s\n", argv[optind],
           argv[optind + 1], argv[optind + 2]);

    free(packet);
    close(sockfd);
    return 0;
}
