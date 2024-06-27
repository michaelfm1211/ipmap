#include "util.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// https://graphics.stanford.edu/~seander/bithacks.html#IntegerLogDeBruijn
static const int root_pow2_lookup[32] = {
    0,  1,  28, 2,  29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4,  8,
    31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6,  11, 5,  10, 9};

struct coord {
  unsigned short x;
  unsigned short y;
  char type;
};

int root_pow2(unsigned int v) {
  unsigned int log2;
  log2 = root_pow2_lookup[(uint32_t)(v * 0x077CB531U) >> 27];
  if (log2 & 3)
    return -1;
  return 1 << (log2 >> 1);
}

struct coord *build_hilbert_map(unsigned int side_len) {
  struct coord *hilbert;
  size_t level, size;

  hilbert = (struct coord *)calloc(side_len * side_len, sizeof(struct coord));
  if (hilbert == NULL) {
    perror("calloc()");
    return NULL;
  }

  // build the hilbert map
  level = side_len * side_len;
  size = side_len;
  hilbert[0].type = 'c';
  hilbert[0].x = 0;
  hilbert[0].y = 0;
  while (size > 1) {
    size_t i, next_level, next_size;
    next_level = level / 4;
    next_size = size / 2;
    for (i = 0; i < side_len * side_len; i += level) {
      switch (hilbert[i].type) {
      case 'a':
        hilbert[i + next_level].type = 'a';
        hilbert[i + next_level].x = hilbert[i].x;
        hilbert[i + next_level].y = hilbert[i].y;

        hilbert[i + 2 * next_level].type = 'a';
        hilbert[i + 2 * next_level].x = hilbert[i].x + next_size;
        hilbert[i + 2 * next_level].y = hilbert[i].y;

        hilbert[i + 3 * next_level].type = 'b';
        hilbert[i + 3 * next_level].x = hilbert[i].x + next_size;
        hilbert[i + 3 * next_level].y = hilbert[i].y + next_size;

        hilbert[i].type = 'd';
        hilbert[i].x = hilbert[i].x;
        hilbert[i].y = hilbert[i].y + next_size;
        break;
      case 'b':
        hilbert[i + next_level].type = 'b';
        hilbert[i + next_level].x = hilbert[i].x;
        hilbert[i + next_level].y = hilbert[i].y;

        hilbert[i + 2 * next_level].type = 'b';
        hilbert[i + 2 * next_level].x = hilbert[i].x;
        hilbert[i + 2 * next_level].y = hilbert[i].y + next_size;

        hilbert[i + 3 * next_level].type = 'a';
        hilbert[i + 3 * next_level].x = hilbert[i].x + next_size;
        hilbert[i + 3 * next_level].y = hilbert[i].y + next_size;

        hilbert[i].type = 'c';
        hilbert[i].x = hilbert[i].x + next_size;
        hilbert[i].y = hilbert[i].y;
        break;
      case 'c':
        hilbert[i + next_level].type = 'c';
        hilbert[i + next_level].x = hilbert[i].x + next_size;
        hilbert[i + next_level].y = hilbert[i].y + next_size;

        hilbert[i + 2 * next_level].type = 'c';
        hilbert[i + 2 * next_level].x = hilbert[i].x;
        hilbert[i + 2 * next_level].y = hilbert[i].y + next_size;

        hilbert[i + 3 * next_level].type = 'd';
        hilbert[i + 3 * next_level].x = hilbert[i].x;
        hilbert[i + 3 * next_level].y = hilbert[i].y;

        hilbert[i].type = 'b';
        hilbert[i].x = hilbert[i].x + next_size;
        hilbert[i].y = hilbert[i].y;
        break;
      case 'd':
        hilbert[i + next_level].type = 'd';
        hilbert[i + next_level].x = hilbert[i].x + next_size;
        hilbert[i + next_level].y = hilbert[i].y + next_size;

        hilbert[i + 2 * next_level].type = 'd';
        hilbert[i + 2 * next_level].x = hilbert[i].x + next_size;
        hilbert[i + 2 * next_level].y = hilbert[i].y;

        hilbert[i + 3 * next_level].type = 'c';
        hilbert[i + 3 * next_level].x = hilbert[i].x;
        hilbert[i + 3 * next_level].y = hilbert[i].y;

        hilbert[i].type = 'a';
        hilbert[i].x = hilbert[i].x;
        hilbert[i].y = hilbert[i].y + next_size;
        break;
      }
    }
    level = next_level;
    size = next_size;
  }

  return hilbert;
}

int main(int argc, char **argv) {
  struct cidr_block query, block;
  char fb_magic[8];
  int side_len, be_side_len;
  unsigned char *ip_bitarr;
  unsigned short *bitmap;
  struct coord *hilbert;
  size_t ip_bitarr_sz, i;

  if (argc != 3) {
    fprintf(stderr, "usage: %s ipmap cidr\n", argv[0]);
    return 1;
  }

  if (parse_cidr(argv[2], &query)) {
    fprintf(stderr, "invalid CIDR query\n");
    return 1;
  }
  side_len = root_pow2(query.num_addrs);
  if (side_len == -1) {
    fprintf(stderr, "query length is incompatible\n");
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

  // write magic
  strncpy(fb_magic, "farbfeld", 8);
  if (fwrite(fb_magic, sizeof(char), 8, stdout) != 8) {
    perror("fwrite()");
    free(ip_bitarr);
    return 1;
  }

  // write length, twice
  be_side_len = htonl(side_len);
  if (fwrite(&be_side_len, sizeof(int), 1, stdout) != 1 ||
      fwrite(&be_side_len, sizeof(int), 1, stdout) != 1) {
    perror("fwrite()");
    free(ip_bitarr);
    return 1;
  }

  hilbert = build_hilbert_map(side_len);
  if (hilbert == NULL) {
    free(ip_bitarr);
    return 1;
  }

  bitmap = malloc(4 * sizeof(unsigned short) * query.num_addrs);
  if (bitmap == NULL) {
    free(ip_bitarr);
    free(hilbert);
    return 1;
  }

  for (i = 0; i < query.num_addrs; i++) {
    size_t pixel;
    int status;

    status = (ip_bitarr[i / 8] >> (i % 8)) & 1;
    pixel = 4 * (hilbert[i].x + hilbert[i].y * side_len);
    if (status) {
      bitmap[pixel] = 0;
      bitmap[pixel + 1] = UINT16_MAX;
      bitmap[pixel + 2] = 0;
      bitmap[pixel + 3] = UINT16_MAX;
    } else {
      bitmap[pixel] = UINT16_MAX;
      bitmap[pixel + 1] = 0;
      bitmap[pixel + 2] = 0;
      bitmap[pixel + 3] = UINT16_MAX;
    }
  }

  if (fwrite(bitmap, 4 * sizeof(unsigned short), query.num_addrs, stdout) !=
      query.num_addrs) {
    perror("fwrite()");
    free(ip_bitarr);
    free(hilbert);
    free(bitmap);
    return 1;
  }

  fclose(stdout);
  free(ip_bitarr);
  free(hilbert);
  free(bitmap);
  return 0;
}
