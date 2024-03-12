#include "util.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int check_magic(FILE *file) {
  char magic[8];
  if (fread(magic, 8, 1, file) < 1) {
    perror("fread");
    return 1;
  }
  return strncmp(magic, MAGIC, 8);
}

int main(int argc, char *argv[]) {
  FILE *input;
  struct cidr_block query, block;
  unsigned char *ip_bitarr;
  size_t ip_bitarr_sz, num_ips, num_up;

  if (argc != 3) {
    fprintf(stderr, "usage: %s input-file cidr\n", argv[0]);
    return 1;
  }
  query = parse_cidr(argv[2]);
  if (query.ipaddr + query.num_addrs - 1 < query.ipaddr) {
    fprintf(stderr,
            "query subnet is too large (extends past 255.255.255.255)\n");
    return 1;
  }

  input = fopen(argv[1], "r");
  if (input == NULL) {
    perror("fopen()");
    return 1;
  }

  // read magic from input file
  if (check_magic(input)) {
    fprintf(stderr, "input has invalid magic\n");
    return 1;
  }

  // get the CIDR block of the input file
  if (fread(&block, sizeof(struct cidr_block), 1, input) < 1) {
    fprintf(stderr, "cannot read block information from input file\n");
    return 1;
  }
  // check that the block doesn't overflow
  if (block.ipaddr + block.num_addrs - 1 < block.ipaddr) {
    fprintf(stderr, "invalid block information in input file (subnet extends "
                    "past 255.255.255.255)\n");
    return 1;
  }

  // check that query is in the CIDR block. three conditions: the query lower
  // bound is too low, the query lower bound is too high, or the query upper
  // bound is too high (if the query upper bound is too high, then so must be
  // the lower bound).
  if (query.ipaddr < block.ipaddr ||
      query.ipaddr > block.ipaddr + block.num_addrs ||
      query.ipaddr + query.num_addrs > block.ipaddr + block.num_addrs) {
    fprintf(stderr, "query ip address out of range\n");
    return 1;
  }

  // read the bitarray into memory
  if (block.num_addrs % 8 == 0)
    ip_bitarr_sz = block.num_addrs / 8;
  else
    ip_bitarr_sz = block.num_addrs / 8 + 1;
  ip_bitarr = malloc(ip_bitarr_sz);
  if (fread(ip_bitarr, ip_bitarr_sz, 1, input) < 1) {
    fprintf(stderr, "cannot read bitarray from input file\n");
    return 1;
  }

  // print the statuses of every address in the query range
  num_ips = query.num_addrs;
  num_up = 0;
  while (num_ips > 0) {
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
    num_ips--;
  }
  printf("%zu up, %zu down\n", num_up, query.num_addrs - num_up);

  free(ip_bitarr);
  return 0;
}
