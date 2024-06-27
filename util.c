#include "util.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int parse_cidr(char *cidr, struct cidr_block *block) {
  char *end, *ptr;
  int i;
  int masknum;

  end = cidr + strlen(cidr);

  // parse ip address part
  block->ipaddr = 0;
  ptr = cidr;
  for (i = 24; i >= 0; i -= 8) {
    while (*ptr != '.' && *ptr != '/')
      ptr++;
    *ptr = '\0';
    block->ipaddr += (unsigned int)atoi(cidr) << i;
    cidr = ptr + 1;
  }

  // parse subnet mask part
  // if no subnet is provided, assume /32
  if (cidr > end)
    masknum = 32;
  else
    masknum = atoi(cidr);

  // /0 (2^32 addresses) can't fit in a 32 bit unsigned integer, but we'll just
  // make it 2^32-1
  if (masknum != 0)
    block->num_addrs = (unsigned int)1 << (32 - masknum);
  else
    block->num_addrs = ~(unsigned int)0;

  if (block->ipaddr + block->num_addrs - 1 < block->ipaddr) {
    // query subnet is too large (extends past 255.255.255.255)
    return 1;
  }
  return 0;
}

int read_ipmap_block(FILE *file, struct cidr_block *block) {
  char magic[8];

  // check magic
  if (fread(magic, 8, 1, file) < 1) {
    perror("fread");
    return 1;
  }
  if (strncmp(magic, MAGIC, 8)) {
    fprintf(stderr, "invalid magic\n");
    return 1;
  }

  // get the CIDR block of the input file
  if (fread(block, sizeof(struct cidr_block), 1, file) < 1) {
    fprintf(stderr, "cannot read block information from input file\n");
    return 1;
  }
  // check that the block doesn't overflow
  if (block->ipaddr + block->num_addrs - 1 < block->ipaddr) {
    fprintf(stderr, "invalid block information in input file (subnet extends "
                    "past 255.255.255.255)\n");
    return 1;
  }

  return 0;
}

unsigned char *read_ipmap(const char *filename, struct cidr_block *block,
                          size_t *ip_bitarr_sz) {
  FILE *input;
  unsigned char *ip_bitarr;

  input = fopen(filename, "r");
  if (input == NULL) {
    perror("fopen()");
    return NULL;
  }

  if (read_ipmap_block(input, block)) {
    fclose(input);
    return NULL;
  }

  // read the bitarray into memory
  if (block->num_addrs % 8 == 0)
    *ip_bitarr_sz = block->num_addrs / 8;
  else
    *ip_bitarr_sz = block->num_addrs / 8 + 1;
  ip_bitarr = malloc(*ip_bitarr_sz);
  if (fread(ip_bitarr, *ip_bitarr_sz, 1, input) < 1) {
    fprintf(stderr, "cannot read bitarray from input file\n");
    free(ip_bitarr);
    fclose(input);
    return NULL;
  }

  fclose(input);
  return ip_bitarr;
}

int query_in_block(struct cidr_block *query, struct cidr_block *block) {
  // check that query is in the CIDR block. three conditions: the query lower
  // bound is too low, the query lower bound is too high, or the query upper
  // bound is too high (if the query upper bound is too high, then so must be
  // the lower bound).
  if (query->ipaddr < block->ipaddr ||
      query->ipaddr > block->ipaddr + block->num_addrs ||
      query->ipaddr + query->num_addrs > block->ipaddr + block->num_addrs) {
    return 0;
  }
  return 1;
}
