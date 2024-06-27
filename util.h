#pragma once

#include <stdio.h>

#define MAGIC "IPMAP002"

struct cidr_block {
  unsigned int ipaddr;
  unsigned int num_addrs;
};

int parse_cidr(char *cidr, struct cidr_block *block);
int read_ipmap_block(FILE *file, struct cidr_block *block);
unsigned char *read_ipmap(const char *filename, struct cidr_block *block,
                          size_t *ip_bitarr_sz);

int query_in_block(struct cidr_block *query, struct cidr_block *block);
