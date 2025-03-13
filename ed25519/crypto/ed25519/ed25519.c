#include "../include/sc25519.h"
#include "../include/crypto_scalarmult.h"
#include "../include/ed25519.h"
#include "../include/sha512_supercop.h"
#include "../include/fips202-masked.h"
#include "../include/randombytes.h"
#include "../../stm32wrapper.h"

#include <string.h>

static void __attribute__ ((noinline)) memxor(void *dest, const void *src, size_t len)
{
  char *d = dest;
  const char *s = src;
  while(len--)
    *d++ ^= *s++;
}

void hash_masked_32(unsigned char *output, const unsigned char *input)
{
  unsigned char input_s0[32] = {};
  unsigned char input_s1[32] = {};

  unsigned char output_s0[64] = {};
  unsigned char output_s1[64] = {};

  memcpy(input_s0, input, 32);
  randombytes(input_s1, 32);
  memxor(input_s0, input_s1, 32);

  shake256_masked(output_s0, output_s1, 64, input_s0, input_s1, 32);

  memcpy(output, output_s0, 64);
  memxor(output, output_s1, 64);
}

void hash_masked_64(unsigned char *output, const unsigned char *input)
{
  unsigned char input_s0[64] = {};
  unsigned char input_s1[64] = {};

  unsigned char output_s0[64] = {};
  unsigned char output_s1[64] = {};

  memcpy(input_s0, input, 64);
  randombytes(input_s1, 64);
  memxor(input_s0, input_s1, 64);

  shake256_masked(output_s0, output_s1, 64, input_s0, input_s1, 64);

  memcpy(output, output_s0, 64);
  memxor(output, output_s1, 64);
}

void hash_masked(unsigned char *output, const unsigned char *input, unsigned long long inlen)
{
  unsigned char input_s0[inlen] = {};
  unsigned char input_s1[inlen] = {};

  unsigned char output_s0[64] = {};
  unsigned char output_s1[64] = {};

  memcpy(input_s0, input, inlen);
  randombytes(input_s1, inlen);
  memxor(input_s0, input_s1, inlen);

  shake256_masked(output_s0, output_s1, 64, input_s0, input_s1, inlen);

  memcpy(output, output_s0, 64);
  memxor(output, output_s1, 64);
}


// msg_len max 64 bytes
int sign(unsigned char *signed_msg,unsigned long long *signed_msg_len, const unsigned char *msg,unsigned long long msg_len, const unsigned char *priv_pub_key)
{
  unsigned char priv_hashed[64];
  unsigned char priv_hashed_msg[96];
  UN_512bitValue r;
  UN_256bitValue rG = { 0 };
  unsigned char rqm[128];
  unsigned char rqm_hashed[64];
  unsigned char s[32];
  sc25519 r_int;
  sc25519 rqm_hashed_int;
  sc25519 s_int;
  sc25519 rqm_hashed_mul_s;
  sc25519 S;

  char str[100];


  if (msg_len > 64) {
    return 1;
  }

  // 1. Compute the hash of the private key
  // crypto_hash(priv_hashed, priv_pub_key, 32);
  hash_masked_32(priv_hashed, priv_pub_key);

  // print
  // to_string_256bitvalue(str, priv_hashed);
  // send_USART_str((unsigned char *)"priv_hashed:");
  // send_USART_str((unsigned char *)str);

  memcpy(priv_hashed_msg, priv_hashed + 32, 32);
  memcpy(priv_hashed_msg + 32, msg, msg_len); // H(priv_key)32-64 || M

  // print
  // to_string_256bitvalue(str, priv_hashed_msg);
  // send_USART_str((unsigned char *)"priv_hashed_msg:");
  // send_USART_str((unsigned char *)str);

  // 2. r = H(H(priv_key)32-64 || M)
  // crypto_hash(r.as_uint8_t, priv_hashed_msg, 32 + msg_len);
  hash_masked(r.as_uint8_t, priv_hashed_msg, 32 + msg_len);

  // print
  // to_string_512bitvalue(str, &r);
  // send_USART_str((unsigned char *)"r:");
  // send_USART_str((unsigned char *)str);
  sc25519_reduce(&r);
  memcpy(r_int.as_uint8_t, r.as_uint8_t, 32);

  // print
  // to_string_256bitvalue(str, &r_int);
  // send_USART_str((unsigned char *)"r_int(reduced):");
  // send_USART_str((unsigned char *)str);

  // 3. Compute the point [r]G
  if (0 != crypto_scalarmult_base_curve25519(rG.as_uint8_t, r.as_uint8_t))
  {
    return -1;
  }

  // print
  // to_string_256bitvalue(str, &rG);
  // send_USART_str((unsigned char *)"rG:");
  // send_USART_str((unsigned char *)str);

  // 4. Derive s from H(priv_key) as in the key pair generation algorithm
  memcpy(s, priv_hashed, 32);
  s[0] &= 248;
  s[31] &= 63;
  s[31] |= 64;

  // s scalar blinding
  uint8_t r1[32];
  uint8_t r2[32];

  randombytes(r1, 32);
  randombytes(r2, 32);

  sc25519 r1r2, r1r2_inv, r1s;
  
  sc25519_mul(&r1r2, (sc25519*)r1, (sc25519*)r2);
  
  // TODO do I need protected inverse?
#if 1 // inverse protection
  UN_256bitValue rand;
  sc25519 r1r2rand, r1r2rand_inv;

  randombytes(rand.as_uint8_t, 32);
  sc25519_mul(&r1r2rand, &r1r2, &rand);
  sc25519_inverse(&r1r2rand_inv, &r1r2rand);
  sc25519_mul(&r1r2_inv, &r1r2rand_inv, &rand);
#else
  sc25519_inverse(&r1r2_inv, &r1r2);
#endif

  sc25519_mul(&r1s, (sc25519*)s, (sc25519*)r1);
  //sc25519_mul(&r1r2s, &r1s, (sc25519*)r2);

  // 4.1 rqm = H(rG||pub_key||M)
  memcpy(rqm, rG.as_uint8_t, 32);
  memcpy(rqm + 32, priv_pub_key + 32, 32);
  memcpy(rqm + 64, msg, msg_len);

  // crypto_hash(rqm_hashed, rqm, 32+32+msg_len);
  hash_masked(rqm_hashed, rqm, 32+32+msg_len);

  sc25519_reduce((UN_512bitValue*)rqm_hashed);
  memcpy(rqm_hashed_int.as_uint8_t, rqm_hashed, 32);

  // 5. S = (r + rqm_hashed * s)
  //sc25519_mul(&rqm_hashed_mul_s, &rqm_hashed_int, (sc25519*)s);
  sc25519 rqm_hashed_mul_r1s;
  sc25519 rqm_hashed_mul_s_r2_inv;

  sc25519_mul(&rqm_hashed_mul_r1s, &rqm_hashed_int, &r1s);                // = rqm_hashed * r1*s
  sc25519_mul(&rqm_hashed_mul_s_r2_inv, &rqm_hashed_mul_r1s, &r1r2_inv);  // = (rqm_hashed * r1*s) * 1/(r1*r2)
  sc25519_mul(&rqm_hashed_mul_s, &rqm_hashed_mul_s_r2_inv, (sc25519*)r2); // = (rqm_hashed * s * 1/r2) * r2

  sc25519_add(&S, &r_int, &rqm_hashed_mul_s);
  
  // 6. signed_msg = R||S
  memcpy(signed_msg, rG.as_uint8_t, 32);
  memcpy(signed_msg + 32, S.as_uint8_t, 32);
  *signed_msg_len = 64;

  return 0;
}