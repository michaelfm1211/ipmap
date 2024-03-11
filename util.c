#include "util.h"
#include <stdlib.h>

struct cidr_block parse_cidr(char *cidr) {
  char *ptr;
  int i;
  struct cidr_block block;
  int masknum;

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

  // parse subnet mask part
  // if no subnet is provided, assume /32
  if (*cidr != '\0')
    masknum = 32;
  else
    masknum = atoi(cidr);
  block.num_addrs = 1 << (32 - masknum);
  return block;
}
