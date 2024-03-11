#pragma once

#define MAGIC "IPMAP002"

struct cidr_block {
  unsigned int ipaddr;
  unsigned int num_addrs;
};

struct cidr_block parse_cidr(char *cidr);
