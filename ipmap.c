#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define TIMEOUT_SEC 5

unsigned short seqnum = 0;

struct cidr_block {
  unsigned int ipaddr;
  unsigned int num_addrs;
};

struct __attribute__((packed)) icmp_echo {
  unsigned char type;
  unsigned char code;
  unsigned short chksum;
  unsigned short id;
  unsigned short seqnum;
};

struct cidr_block parse_cidr(char *cidr) {
  char *ptr;
  int i;
  struct cidr_block block;

  // parse ip address part
  block.ipaddr = 0;
  ptr = cidr;
  for (i = 24; i >= 0; i -= 8) {
    while (*ptr != '.' && *ptr != '/')
      ptr++;
    *ptr = '\0';
    block.ipaddr += atoi(cidr) << i;
    cidr = ptr + 1;
  }

  // parse subnet mask park
  block.num_addrs = 1 << (32 - atoi(cidr));
  return block;
}

// borrowed from http://www.ping127001.com/pingpage/ping.text
unsigned short ip_chksum(unsigned short *w, size_t len) {
  int nleft, sum;

  nleft = len;
  sum = 0;
  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }
  if (nleft == 1) {
    unsigned short u;

    u = 0;
    *(unsigned char *)(&u) = *(unsigned char *)w;
    sum += u;
  }
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}

int try_host(int sock, unsigned int ipaddr) {
  struct icmp_echo packet;
  struct sockaddr_in addr;

  // create a ping packet
  packet.type = 8;
  packet.code = 0;
  packet.chksum = 0;
  packet.id = getpid() & 0xFFFF;
  packet.seqnum = seqnum++;
  packet.chksum =
      ip_chksum((unsigned short *)&packet, sizeof(struct icmp_echo));

  // send the packet
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(ipaddr);
  if (sendto(sock, &packet, sizeof(struct icmp_echo), 0,
             (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 1) {
    perror("sendto");
    return 1;
  }
  return 0;
}

// worker thread to send ping packets to each address
void *send_thread(void *args) {
  struct cidr_block block;
  int sock;
  unsigned int next_ipaddr;

  block = *(struct cidr_block *)args;

  sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sock == -1) {
    perror("socket()");
    exit(1);
  }

  next_ipaddr = block.ipaddr;
  while (next_ipaddr < block.ipaddr + block.num_addrs) {
    try_host(sock, next_ipaddr);

    // increment but skip over reserved blocks
    next_ipaddr++;
    if (next_ipaddr == 0xE0000000 || next_ipaddr == 0xF0000000) {
      next_ipaddr += 1 << (32 - 4);
    } else if (next_ipaddr == 0x0 || next_ipaddr == 0xA000000 ||
               next_ipaddr == 0x7F000000) {
      next_ipaddr += 1 << (32 - 8);
    } else if (next_ipaddr == 0x64400000) {
      next_ipaddr += 1 << (32 - 10);
    } else if (next_ipaddr == 0xAC100000) {
      next_ipaddr += 1 << (32 - 12);
    } else if (next_ipaddr == 0xC6120000) {
      next_ipaddr += 1 << (32 - 15);
    } else if (next_ipaddr == 0xA9FE0000 || next_ipaddr == 0xC0A80000) {
      next_ipaddr += 1 << (32 - 16);
    } else if (next_ipaddr == 0xC0000000 || next_ipaddr == 0xC0000200 ||
               next_ipaddr == 0xC0586300 || next_ipaddr == 0xC6336400 ||
               next_ipaddr == 0xCB007100) {
      next_ipaddr += 1 << (32 - 24);
    } else if (next_ipaddr == 0xFFFFFFFF) {
      next_ipaddr += 1;
    }
  }

  close(sock);
  return NULL;
}

int main(int argc, char *argv[]) {
  struct cidr_block block;
  pthread_t send_thrd;
  size_t ip_bitaddr_cap;
  unsigned char *ip_bitarr;
  unsigned int num_ips;
  int sock;
  struct timeval timeout;
  FILE *out;

  // parse arguments
  if (argc != 3) {
    fprintf(stderr, "%s cidr output_file\n", argv[0]);
    return 1;
  }
  block = parse_cidr(argv[1]);

  // open a thread to send ping requests while we receive them
  if (pthread_create(&send_thrd, NULL, send_thread, &block))
    return 1;

  // allocate a bitarray to keep track of ip addresses
  if (block.num_addrs % 8 == 0)
    ip_bitaddr_cap = block.num_addrs / 8;
  else
    ip_bitaddr_cap = block.num_addrs / 8 + 1;
  ip_bitarr = calloc(1, ip_bitaddr_cap);

  // open the socket and add a timeout
  sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sock == -1) {
    perror("socket()");
    return 1;
  }
  timeout.tv_sec = TIMEOUT_SEC;
  timeout.tv_usec = 0;
  if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout,
                 sizeof(struct timeval)) < 0) {
    perror("setsockopt()");
    return 1;
  }

  // receive all
  num_ips = block.num_addrs;
  while (num_ips > 0) {
    struct icmp_echo packet;
    struct sockaddr_in addr;
    unsigned int ipaddr;
    char ipaddr_str[INET_ADDRSTRLEN];
    socklen_t addrlen;

    addrlen = sizeof(struct sockaddr_in);
    if (recvfrom(sock, &packet, sizeof(struct icmp_echo), 0,
                 (struct sockaddr *)&addr, &addrlen) <= 0) {
      // timeout
      if (errno == EWOULDBLOCK)
        break;
      // genuine error, so print
      perror("recvfrom");
      return 1;
    }
    inet_ntop(AF_INET, &addr.sin_addr.s_addr, ipaddr_str, INET_ADDRSTRLEN);

    ipaddr = ntohl(addr.sin_addr.s_addr);
    if (ipaddr - block.ipaddr > block.num_addrs) {
      // either a host is sending us back garbage (unlikely), or this is an
      // error message from a router like TTL Exceeded (more likely). either
      // way, the host is unreachable.
      fprintf(stderr, "unexpected address: %s\n", ipaddr_str);
      continue;
    }
    ip_bitarr[(ipaddr - block.ipaddr) / 8] |= 1
                                              << ((ipaddr - block.ipaddr) % 8);
    num_ips--;

    // logging
    printf("up: %s\n", ipaddr_str);
  }
  printf("%u hosts up, %u down\n", block.num_addrs - num_ips, num_ips);

  // output ip bitarray to the output file
  out = fopen(argv[2], "w");
  if (out == NULL) {
    perror("fwrite");
    return 1;
  }
  if (fwrite(ip_bitarr, ip_bitaddr_cap, 1, out) < 1) {
    perror("fwrite");
    return 1;
  }

  free(ip_bitarr);
  return 0;
}
