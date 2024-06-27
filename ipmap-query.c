#include "util.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
  struct cidr_block query, block;
  unsigned char *ip_bitarr;
  size_t ip_bitarr_sz, num_ip, num_up;

  if (argc != 3) {
    fprintf(stderr, "usage: %s input-file cidr\n", argv[0]);
    return 1;
  }

  if (parse_cidr(argv[2], &query)) {
    fprintf(stderr, "invalid query\n"); 
    return 1;
  }

  ip_bitarr = read_ipmap(argv[1], &block, &ip_bitarr_sz);
  if (ip_bitarr == NULL) {
    return 1;
  }

  if (!query_in_block(&query, &block)) {
    fprintf(stderr, "query ip address out of range\n");
    return 1;
  }

  // print the statuses of every address in the query range
  num_ip = query.num_addrs;
  num_up = 0;
  while (num_ip > 0) {
    size_t offset;
    int status;
    char ipaddr_str[INET_ADDRSTRLEN];
    unsigned int ipaddr;

    offset = query.ipaddr - block.ipaddr;
    status = (ip_bitarr[offset / 8] >> (offset % 8)) & 1;
    if (status)
      num_up++;

    ipaddr = htonl(query.ipaddr);
    inet_ntop(AF_INET, &ipaddr, ipaddr_str, INET_ADDRSTRLEN);
    printf("%s: %s\n", status ? "up" : "down", ipaddr_str);

    query.ipaddr++;
    num_ip--;
  }
  printf("%zu up, %zu down\n", num_up, query.num_addrs - num_up);

  free(ip_bitarr);
  return 0;
}
