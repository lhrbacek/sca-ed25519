#include "main.h"

#include <stdio.h>
#include <string.h>

#include "stm32wrapper.h"
#include "crypto/include/fe25519.h"
#include "crypto/include/bigint.h"
#include "crypto/include/sc25519.h"
#include "crypto/include/crypto_scalarmult.h"
#include "crypto/include/sha512_supercop.h"
#include "crypto/include/fips202-masked.h"
#include "crypto/include/fips202.h"
#include "crypto/include/ed25519.h"
#include "crypto/include/randombytes.h"

static void __attribute__ ((noinline)) memxor(void *dest, const void *src, size_t len)
{
  char *d = dest;
  const char *s = src;
  while(len--)
    *d++ ^= *s++;
}

int main(void) {
  clock_setup();
  gpio_setup();
  usart_setup(115200);
  rng_enable();

  send_USART_str((unsigned char *)"Program startet.");

  // fe25519 a1, a2, a3;
  // fe25519 *x1 = &a1;
  // fe25519 *x2 = &a2;
  // fe25519 *x3 = &a3;

  // send_USART_str((unsigned char *)"a and x initialized");

  // fe25519_setone(x2);
  // fe25519_setone(x3);
  // fe25519_add(x1, x2, x3);

  // send_USART_str((unsigned char *)"first addition done");

  // char str[100];
  // to_string_256bitvalue(str, x1);
  // send_USART_str((unsigned char *)str);

  // send_USART_str((unsigned char *)"lets init b and y");

  // fe25519 b1;
  // fe25519 b2 = {
  //   { 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  //               0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 
  //               0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xaa }}; // L - 67

  // fe25519 b3 = {
  //   { 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  //     0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 
  //     0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xbb }}; // L - 50
  
  // fe25519 *y1 = &b1;
  // fe25519 *y2 = &b2;
  // fe25519 *y3 = &b3;

  // send_USART_str((unsigned char *)"b and y initialized");

  // fe25519_add(y1, y2, y3);

  // send_USART_str((unsigned char *)"second addition done");

  // to_string_256bitvalue(str, y1);
  // send_USART_str((unsigned char *)str);

  // send_USART_str((unsigned char *)"Done!");

  char str[100];

  // UN_512bitValue r = { // test vector
  // { 0xb6, 0xb1, 0x9c, 0xd8, 0xe0, 0x42, 0x6f, 0x59, 0x83, 0xfa, 0x11,
  //   0x2d, 0x89, 0xa1, 0x43, 0xaa, 0x97, 0xda, 0xb8, 0xbc, 0x5d, 0xeb,
  //   0x8d, 0x5b, 0x62, 0x53, 0xc9, 0x28, 0xb6, 0x52, 0x72, 0xf4, 0x04,
  //   0x40, 0x98, 0xc2, 0xa9, 0x90, 0x03, 0x9c, 0xde, 0x5b, 0x6a, 0x48,
  //   0x18, 0xdf, 0x0b, 0xfb, 0x6e, 0x40, 0xdc, 0x5d, 0xee, 0x54, 0x24,
  //   0x80, 0x32, 0x96, 0x23, 0x23, 0xe7, 0x01, 0x35, 0x2d }};

  // sc25519_reduce(&r);

  // UN_256bitValue r_mod_l = { 0 };
  // memcpy(r_mod_l.as_uint8_t, r.as_uint8_t, 32);

  // to_string_256bitvalue(str, &r_mod_l);
  // send_USART_str((unsigned char *)"r_mod_l:");
  // send_USART_str((unsigned char *)str);

  // UN_256bitValue rG = { 0 };
  // crypto_scalarmult_base_curve25519(rG.as_uint8_t, r_mod_l.as_uint8_t);

  // to_string_256bitvalue(str, &rG);
  // send_USART_str((unsigned char *)"rG:");
  // send_USART_str((unsigned char *)str);

  unsigned char signed_msg[64] = { 0 };
  unsigned long long signed_msg_len;
  unsigned char msg[] = {
    0xab, 0x11, 0xcc, 0xdd, 0xee, 0xff, 0xee, 0xff, 0xee, 0xdd};
  unsigned long long msg_len = sizeof(msg);
  /*unsigned char priv_pub_key[64] = { // pubkey created with SHA512
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 
    0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 
    0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x3, 0x1c, 0xae, 
    0x7f, 0x60, 0xd7, 0x5a, 0x98, 0x1, 0x82, 0xb1, 0xa, 0xb7, 
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x7, 0x3a, 0xe, 0xe1, 
    0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x2, 0x1a, 0x68, 
    0xf7, 0x7, 0x51, 0x1a, };*/

  unsigned char priv_pub_key[64] = { // pubkey created with SHAKE256
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84,
    0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69,
    0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x3, 0x1c, 0xae,
    0x7f, 0x60, 0xc, 0xdb, 0x1e, 0xd8, 0x64, 0x17, 0x7, 0x7e,
    0xae, 0xb7, 0x30, 0x37, 0x9c, 0xa3, 0x28, 0x6c, 0x57, 0x9,
    0xaa, 0xfe, 0xc4, 0x6, 0x86, 0xc7, 0x31, 0xa1, 0x2d, 0x63,
    0x49, 0x9e, 0xe0, 0xb5, };
  
  if (0 == sign(signed_msg, &signed_msg_len, msg, msg_len, priv_pub_key))
  {
    to_string_512bitvalue(str, (UN_512bitValue*)signed_msg);
    send_USART_str((unsigned char *)"my ed25519:");
    send_USART_str((unsigned char *)str);
  } else {
    send_USART_str((unsigned char *)"my ed25519: -1");
  }



  // HASH SHAKE DEBUG
  // unsigned char hash_out[64];
  // unsigned char hash_in[32] = {
  //      0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  //      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  //      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0xbb, 0xaa };
  // unsigned int hash_len = 32;

  // crypto_hash(hash_out, hash_in, hash_len);

  // to_string_256bitvalue(str, hash_in);
  // send_USART_str((unsigned char *)"hash_in:");
  // send_USART_str((unsigned char *)str);

  // to_string_512bitvalue(str, hash_out);
  // send_USART_str((unsigned char *)"hash_out:");
  // send_USART_str((unsigned char *)str);

  /*
  send_USART_str((unsigned char *)"-----------------------------");
  send_USART_str((unsigned char *)"SHAKE256:");

  size_t inlen = 32;
  size_t outlen = 64;

  unsigned char input[32] = {
      0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0xbb, 0xaa };
  unsigned char output[outlen];

  shake256(output, outlen, input, inlen);
  //sha3_512(output, input, inlen);

  to_string_256bitvalue(str, (UN_256bitValue*)input);
  send_USART_str((unsigned char *)"hash_in:");
  send_USART_str((unsigned char *)str);
  to_string_256bitvalue(str, (UN_256bitValue*)output);
  send_USART_str((unsigned char *)"hash_out:");
  send_USART_str((unsigned char *)str);



  send_USART_str((unsigned char *)"-----------------------------");
  send_USART_str((unsigned char *)"SHAKE256 MASKED:");

  unsigned char input_s0[inlen] = {};
  unsigned char input_s1[inlen] = {};

  unsigned char output_s0[outlen] = {};
  unsigned char output_s1[outlen] = {};

  memcpy(input_s0, input, inlen);
  randombytes(input_s1, inlen);
  memxor(input_s0, input_s1, inlen);
  
  shake256_masked(output_s0, output_s1, outlen, input_s0, input_s1, inlen);
  //sha3_512_masked(output_s0, output_s1, input_s0, input_s1, inlen);

  memcpy(output, output_s0, outlen);
  memxor(output, output_s1, outlen);

  to_string_256bitvalue(str, (UN_256bitValue*)input);
  send_USART_str((unsigned char *)"hash_in:");
  send_USART_str((unsigned char *)str);
  to_string_256bitvalue(str, (UN_256bitValue*)input_s0);
  send_USART_str((unsigned char *)"hash_in_s0:");
  send_USART_str((unsigned char *)str);
  to_string_256bitvalue(str, (UN_256bitValue*)input_s1);
  send_USART_str((unsigned char *)"hash_in_s1:");
  send_USART_str((unsigned char *)str);

  to_string_256bitvalue(str, (UN_256bitValue*)output);
  send_USART_str((unsigned char *)"hash_out:");
  send_USART_str((unsigned char *)str);
  to_string_256bitvalue(str, (UN_256bitValue*)output_s0);
  send_USART_str((unsigned char *)"hash_out_s0:");
  send_USART_str((unsigned char *)str);
  to_string_256bitvalue(str, (UN_256bitValue*)output_s1);
  send_USART_str((unsigned char *)"hash_out_s1:");
  send_USART_str((unsigned char *)str);
  */


  while (1)
    ;

  return 0;
}
