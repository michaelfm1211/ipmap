#include "util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define TIMEOUT_SEC 5
#define NUM_THRDS 32

unsigned short seqnum = 0;

pthread_mutex_t thrds_working_mutex;
size_t thrds_working = 0;

struct sender_args {
  int id;
  int sock;
  struct cidr_block block;
};

/* struct __attribute__((packed)) icmp_echo { */
struct icmp_echo {
  unsigned char type;
  unsigned char code;
  unsigned short chksum;
  unsigned short id;
  unsigned short seqnum;
};

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

int try_host(__attribute__((unused)) int thrd_id, int sock, unsigned int ipaddr) {
  struct icmp_echo packet;
  struct sockaddr_in addr;
  char ipaddr_str[INET_ADDRSTRLEN];

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

  // logging
  inet_ntop(AF_INET, &addr.sin_addr.s_addr, ipaddr_str, INET_ADDRSTRLEN);
#ifdef DEBUG
  printf("%d: trying %s\n", thrd_id, ipaddr_str);
#endif

  if (sendto(sock, &packet, sizeof(struct icmp_echo), 0,
             (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 1) {
    perror("sendto()");
    return 1;
  }
  return 0;
}

// worker thread to send ping packets to each address
void *send_thread(void *args_ptr) {
  struct sender_args *args;
  struct pollfd pfd;
  unsigned int next_ipaddr;
  int ready;
  struct timeval timeout;

  args = (struct sender_args *)args_ptr;
#ifdef DEBUG
  printf("%d: started thread\n", args->id);
#endif

  // create the pollfd
  pfd.fd = args->sock;
  pfd.events = POLLOUT;

  next_ipaddr = args->block.ipaddr;
  // we need the <= and -1 or else we the integer might overflow
  while (next_ipaddr <= args->block.ipaddr + args->block.num_addrs - 1) {
    // skip over reserved IP blocks
    if (next_ipaddr == 0xE0000000 || next_ipaddr == 0xF0000000) {
      next_ipaddr += 1 << (32 - 4);
      continue;
    } else if (next_ipaddr == 0x0 || next_ipaddr == 0xA000000 ||
               next_ipaddr == 0x7F000000) {
      next_ipaddr += 1 << (32 - 8);
      continue;
    } else if (next_ipaddr == 0x64400000) {
      next_ipaddr += 1 << (32 - 10);
      continue;
    } else if (next_ipaddr == 0xAC100000) {
      next_ipaddr += 1 << (32 - 12);
      continue;
    } else if (next_ipaddr == 0xC6120000) {
      next_ipaddr += 1 << (32 - 15);
      continue;
    } else if (next_ipaddr == 0xA9FE0000 || next_ipaddr == 0xC0A80000) {
      next_ipaddr += 1 << (32 - 16);
      continue;
    } else if (next_ipaddr == 0xC0000000 || next_ipaddr == 0xC0000200 ||
               next_ipaddr == 0xC0586300 || next_ipaddr == 0xC6336400 ||
               next_ipaddr == 0xCB007100) {
      next_ipaddr += 1 << (32 - 24);
      continue;
    } else if (next_ipaddr == 0xFFFFFFFF) {
      // this is reserved, but don't skip this address or else we'll integer
      // overflow. it the last possible address so just break;
      break;
    }

    ready = poll(&pfd, 1, -1);
    if (ready == -1) {
      perror("poll()");
      return NULL;
    }
    try_host(args->id, args->sock, next_ipaddr);
    next_ipaddr++;
  }

  // set a timeout on the socket now that we're done querying
#ifdef DEBUG
  printf("%d: finished sending requests\n", args->id);
#endif
  if ((errno = pthread_mutex_lock(&thrds_working_mutex)) != 0) {
    perror("pthread_mutex_lock()");
    exit(1);
  }
  thrds_working -= 1;

  if (thrds_working == 0) {
#ifdef DEBUG
    printf("all threads finished sending, setting timeout\n");
#endif
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;
    if (setsockopt(args->sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout,
                   sizeof(struct timeval)) < 0) {
      perror("setsockopt()");
      // no recovery here, or else we'll never end
      exit(1);
    }
  }

  if ((errno = pthread_mutex_unlock(&thrds_working_mutex)) != 0) {
    perror("pthread_mutex_unlock()");
    exit(1);
  }
  return NULL;
}

int write_outfile(const char *filename, struct cidr_block *block,
                  unsigned char *ip_bitarr, size_t ip_bitarr_len) {
  FILE *out;

  // output ip bitarray to the output file
  out = fopen(filename, "w");
  if (out == NULL) {
    perror("fwrite");
    return 1;
  }

  // write the magic
  if (fwrite(MAGIC, 8, 1, out) < 1) {
    perror("fwrite");
    return 1;
  }
  // write the CIDR block
  if (fwrite(block, sizeof(struct cidr_block), 1, out) < 1) {
    perror("fwrite");
    return 1;
  }
  // write the bitarray
  if (fwrite(ip_bitarr, ip_bitarr_len, 1, out) < 1) {
    perror("fwrite");
    return 1;
  }

  fclose(out);
  return 0;
}

int main(int argc, char *argv[]) {
  struct cidr_block block;
  struct sender_args thrd_args[NUM_THRDS];
  size_t ip_bitarr_cap, i;
  unsigned char *ip_bitarr;
  unsigned int num_ips;
  int sock;

  // make sure no padding has been added to struct icmp_echo
  if (sizeof(struct icmp_echo) != 8) {
    fprintf(stderr, "struct icmp_echo is aligned. Contact the developers.\n");
  }

  // parse arguments
  if (argc != 3) {
    fprintf(stderr, "%s cidr output-file\n", argv[0]);
    return 1;
  }

  if (parse_cidr(argv[1], &block)) {
    fprintf(stderr, "invalid CIDR block\n");
    return 1;
  }

  // open the socket
  sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sock == -1) {
    perror("socket()");
    return 1;
  }

  // split the block into subblocks and open a thread for each subblock to send
  // ping requests while we receive them
  if ((errno = pthread_mutex_init(&thrds_working_mutex, NULL)) != 0) {
    perror("pthread_mutex_init()");
    close(sock);
    return 1;
  }
  thrds_working = NUM_THRDS;
  for (i = 0; i < NUM_THRDS; i++) {
    struct cidr_block subblock;
    pthread_t send_thrd;

    subblock.ipaddr = block.ipaddr + i * (block.num_addrs / NUM_THRDS);
    if (i == NUM_THRDS - 1) {
      subblock.num_addrs = block.num_addrs - i * (block.num_addrs / NUM_THRDS);
    } else {
      subblock.num_addrs = block.num_addrs / NUM_THRDS;
    }

    thrd_args[i].id = i;
    thrd_args[i].block = subblock;
    thrd_args[i].sock = sock;
    if ((errno = pthread_create(&send_thrd, NULL, send_thread,
                                &thrd_args[i])) != 0) {
      perror("pthread_create()");
      return 1;
    }
  }

  // allocate a bitarray to keep track of ip addresses
  if (block.num_addrs % 8 == 0)
    ip_bitarr_cap = block.num_addrs / 8;
  else
    ip_bitarr_cap = block.num_addrs / 8 + 1;
  ip_bitarr = calloc(1, ip_bitarr_cap);
  if (ip_bitarr == NULL) {
    perror("calloc()");
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
    size_t offset;

    addrlen = sizeof(struct sockaddr_in);
    if (recvfrom(sock, &packet, sizeof(struct icmp_echo), 0,
                 (struct sockaddr *)&addr, &addrlen) <= 0) {
      // timeout
      if (errno == EWOULDBLOCK || errno == EAGAIN)
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
#ifdef DEBUG
      printf("unexpected address: %s\n", ipaddr_str);
#endif
      continue;
    }
    offset = ipaddr - block.ipaddr;
    ip_bitarr[offset / 8] |= 1 << (offset % 8);
    num_ips--;

    // logging
#ifdef DEBUG
    printf("up: %s\n", ipaddr_str);
#endif
  }
  printf("%u hosts up, %u down\n", block.num_addrs - num_ips, num_ips);

  if (write_outfile(argv[2], &block, ip_bitarr, ip_bitarr_cap))
    return 1;

  if ((errno = pthread_mutex_destroy(&thrds_working_mutex)) != 0) {
    perror("pthread_mutex_destroy()");
    return 1;
  }
  free(ip_bitarr);
  return 0;
}
