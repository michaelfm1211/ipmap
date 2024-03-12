#include "util.h"
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

struct cidr_block parse_cidr(char *cidr) {
  char *end, *ptr;
  int i;
  struct cidr_block block;
  int masknum;

  end = cidr + strlen(cidr);

  // parse ip address part
  block.ipaddr = 0;
  ptr = cidr;
  for (i = 24; i >= 0; i -= 8) {
    while (*ptr != '.' && *ptr != '/')
      ptr++;
    *ptr = '\0';
    block.ipaddr += (unsigned int)atoi(cidr) << i;
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
    block.num_addrs = (unsigned int)1 << (32 - masknum);
  else
    block.num_addrs = ~(unsigned int)0;
  return block;
}
