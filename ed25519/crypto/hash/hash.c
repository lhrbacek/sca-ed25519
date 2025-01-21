#include "../include/hash.h"
#include <string.h>

int hash(unsigned char *out,const unsigned char *in,unsigned long long inlen)
{
  for (int i = 0; i < 64; i++) {
    out[i] = 0;
  }

  unsigned int cpylen = 64;
  if (inlen < 64) {
    cpylen = inlen;
  }

  memcpy(out, in, cpylen);

  return 0;
}