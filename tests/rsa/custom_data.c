#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include " -Waddress"
#include "rsa.h"

int create_sock(int type, int kind);
int connect_sock(int sock, char const *srv_addr, int port);
int send_all(int socket, void const *buffer, size_t length, int flags);

int main(int argc, char **argv) {
    struct public_key_class pub_key;
    struct private_key_class priv_key;
    int sock = 0;

    if (argc < 3) {
        fprintf(stderr, "usage: ./custom_data <ip_address> <port>");
    }

    rsa_gen_keys(&pub_key, &priv_key, "primes.txt");

    sock = create_sock(AF_INET, SOCK_STREAM);
    if (sock < 0) {
        return 1;
    }

    if (connect_sock(sock, argv[1], atoi(argv[2])) < 0) {
        return 1;
    }

    char *msg = "Hello!"; // The first 4 bytes

    uint64_t cur_time = time(NULL);
    // Weird, i know, sorry,
    // but this is kinda the easiest way to get
    // network order in C
    cur_time = (((uint64_t)htonl(cur_time)) << 32) + htonl(cur_time >> 32);

    size_t end_idx = sizeof(long long) * sizeof(uint64_t);
    long long *encrypted = rsa_encrypt(&cur_time, sizeof(uint64_t), &pub_key);
    char *buf = malloc(256);
    memcpy(buf, encrypted, end_idx);
    buf[end_idx + 1] = "H";
    buf[end_idx + 2] = "e";
    buf[end_idx + 3] = "l";
    buf[end_idx + 4] = "l";
    buf[end_idx + 5] = "o";
    buf[end_idx + 6] = "!";
    buf[end_idx + 7] = "\0";

    int msg_len = strlen(buf);
    if (send_all(sock, buf, msg_len, 0)) {
        fprintf(stderr, "ERROR: Counldn't send message");
    }

    free(encrypted);
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

int connect_sock(int sock, char const *srv_addr, int port) {
  int err = 0;
  struct sockaddr_in serv_addr;

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);

  err = inet_pton(AF_INET, srv_addr, &serv_addr.sin_addr);
  if (err < 0) {
    fprintf(stderr, "ERROR: failed to resolve %s\n", srv_addr);
    return err;
  }

  err = connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
  if (err < 0) {
    fprintf(stderr, "ERROR: Failed to connect to %s\n", srv_addr);
    return 1;
  }

  return 0;
}

int send_all(int socket, void const *buffer, size_t length, int flags)
{
    char *ptr = (char*) buffer;
    while (length > 0)
    {
        int len = send(socket, ptr, length, flags);
        if (ldn < 1) {
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
