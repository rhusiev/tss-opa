#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../include/xdp-firewall.h"

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

void print_hex_password(const unsigned char *password, size_t len) {
    printf("Using password: ");
    for (size_t i = 0; i < len; i++) {
        printf("%02X", password[i]);
        if (i < len - 1)
            printf(":");
    }
    printf("\n");
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
    unsigned char password[PASSWORD_SIZE] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                                             0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                             0x77, 0x88, 0x99, 0x00};
    unsigned char *custom_password = NULL;
    size_t password_len = 0;
    int opt;

    if (argc < 4) {
        fprintf(stderr,
                "Usage: %s [-p password] <destination_ip> <destination_port> "
                "<message>\n",
                argv[0]);
        return 1;
    }

    /* Parse command line arguments */
    while ((opt = getopt(argc, argv, "p:")) != -1) {
        switch (opt) {
        case 'p':
            custom_password = parse_hex_password(optarg, &password_len);
            if (!custom_password) {
                fprintf(stderr, "Invalid password format\n");
                return 1;
            }
            break;
        default:
            fprintf(
                stderr,
                "Usage: %s [-p password] <destination_ip> <destination_port> "
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
        perror("inet_pton");
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
    ip_header->ip_src.s_addr = inet_addr("127.0.0.1"); /* Source IP */
    ip_header->ip_dst.s_addr = dest.sin_addr.s_addr;   /* Destination IP */

    /* Set up password header */
    pw_header = (struct passwd_hdr *)(packet + sizeof(struct ip));
    memcpy(pw_header->password, password, PASSWORD_SIZE);

    /* Set up UDP header */
    udp_header = (struct udphdr *)(packet + sizeof(struct ip) +
                                   sizeof(struct passwd_hdr));
    udp_header->source = htons(12345); /* Source port */
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
