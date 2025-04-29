#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define CBC 1
#define CTR 1
#define ECB 1

#include "aes.h"

static const uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

int main(int argc, char **argv) {
  int sockfd;
  struct sockaddr_in serv_addr, cli_addr;
  socklen_t cli_len = sizeof(cli_addr);
  struct AES_ctx ctx;

  if (argc < 2) {
    fprintf(stderr, "Usage: ./test_server <port>\n");
    return 1;
  }

  AES_init_ctx(&ctx, key);

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("socket");
    return 1;
  }

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port = htons(atoi(argv[1]));

  if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    perror("bind");
    close(sockfd);
    return 1;
  }

  printf("Listening on port %s...\n", argv[1]);

  while (1) {
    char buf[512] = {0};
    int len = recvfrom(sockfd, buf, sizeof(buf), 0,
                       (struct sockaddr *)&cli_addr, &cli_len);
    if (len < 0) {
      perror("recvfrom");
      continue;
    }

    printf("Received %d bytes\n", len);

    // Decrypt in 16-byte blocks
    for (int i = 0; i < len; i += 16) {
      AES_ECB_decrypt(&ctx, (uint8_t *)(buf + i));
    }

    // Print time and message
    if (len >= sizeof(uint64_t)) {
      uint64_t network_time;
      memcpy(&network_time, buf, sizeof(uint64_t));
      uint64_t time_val =
          (((uint64_t)ntohl(network_time)) << 32) + ntohl(network_time >> 32);
      printf("Timestamp: %lu\n", time_val);
      printf("Message: %s\n", buf + sizeof(uint64_t));
    } else {
      printf("Invalid message\n");
    }
  }

  close(sockfd);
  return 0;
}
