#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define CBC 1
#define CTR 1
#define ECB 1

#include "../aes/include/aes.h"

static const uint8_t key[16] = {
    (uint8_t)0x2b, (uint8_t)0x7e, (uint8_t)0x15, (uint8_t)0x16,
    (uint8_t)0x28, (uint8_t)0xae, (uint8_t)0xd2, (uint8_t)0xa6,
    (uint8_t)0xab, (uint8_t)0xf7, (uint8_t)0x15, (uint8_t)0x88,
    (uint8_t)0x09, (uint8_t)0xcf, (uint8_t)0x4f, (uint8_t)0x3c};

int create_sock(int type, int kind);
int setup_addr(struct sockaddr_in *serv_addr, char const *srv_addr, int port);
int send_all(int socket, void const *buffer, size_t length, int flags,
             struct sockaddr_in *addr);

int main(int argc, char **argv) {
  int sock = 0;
  struct sockaddr_in serv_addr;
  struct AES_ctx ctx;
  AES_init_ctx(&ctx, key);

  if (argc < 3) {
    fprintf(stderr, "usage: ./custom_data <ip_address> <port>\n");
    return 1;
  }

  sock = create_sock(AF_INET, SOCK_DGRAM);
  if (sock < 0) {
    return 1;
  }

  if (setup_addr(&serv_addr, argv[1], atoi(argv[2])) < 0) {
    return 1;
  }

  uint64_t cur_time = time(NULL);
  // Weird, i know, sorry,
  // but this is kinda the easiest way to get
  // network order in C
  cur_time = (((uint64_t)htonl(cur_time)) << 32) + htonl(cur_time >> 32);

  size_t end_idx = sizeof(uint64_t);

  char *buf = malloc(128);
  *((uint64_t *)buf) = cur_time;
  buf[end_idx + 1] = 'H';
  buf[end_idx + 2] = 'e';
  buf[end_idx + 3] = 'l';
  buf[end_idx + 4] = 'l';
  buf[end_idx + 5] = 'o';
  buf[end_idx + 6] = '!';
  buf[end_idx + 7] = '\0';

  int plain_len = end_idx + 8;
  int msg_len = ((plain_len + 15) / 16) * 16;
  memset(buf + plain_len, 0, msg_len - plain_len);

  char *out_buf = malloc(512);
  int i = 0;
  for (i = 0; i * 16 < msg_len; ++i) {
    AES_ECB_encrypt(&ctx, buf + (i * 16));
  }

  if (send_all(sock, buf, msg_len, 0, &serv_addr)) {
    fprintf(stderr, "ERROR: Counldn't send message\n");
  }

  free(buf);

  return 0;
}

int create_sock(int domain, int type) {
  int sock = 0;

  sock = socket(domain, type, 0);
  if (sock < 0) {
    fprintf(stderr, "ERROR: Failed to open socket\n");
  }

  return sock;
}

int setup_addr(struct sockaddr_in *serv_addr, char const *srv_addr, int port) {
  int err = 0;

  memset(serv_addr, 0, sizeof(struct sockaddr_in));
  serv_addr->sin_family = AF_INET;
  serv_addr->sin_port = htons(port);

  err = inet_pton(AF_INET, srv_addr, &serv_addr->sin_addr);
  if (err < 0) {
    fprintf(stderr, "ERROR: failed to resolve %s\n", srv_addr);
    return err;
  }

  return 0;
}

int send_all(int socket, void const *buffer, size_t length, int flags,
             struct sockaddr_in *addr) {
  char *ptr = (char *)buffer;
  while (length > 0) {
    int len = sendto(socket, ptr, length, flags, (struct sockaddr *)addr,
                     sizeof(struct sockaddr_in));
    if (len < 1) {
      if (errno == EINTR) {
        continue;
      }
      return errno;
    }
    ptr += len;
    length -= len;
  }
  return 0;
}
