#include "../include/sc25519.h"
#include "../include/fe25519.h"
#include "../include/crypto_scalarmult.h"
#include "../include/ed25519.h"
#include "../include/fips202-masked.h"
#include "../include/randombytes.h"
#include "../../stm32wrapper.h"

#include <string.h>

// To make sure that copying is unrolled when possible.
static inline void __attribute__((always_inline)) memcpy32(unsigned char* dst, const unsigned char* src)
{
  ((UN_256bitValue*)dst)->as_uint32_t[0] = ((UN_256bitValue*)src)->as_uint32_t[0];
  ((UN_256bitValue*)dst)->as_uint32_t[1] = ((UN_256bitValue*)src)->as_uint32_t[1];
  ((UN_256bitValue*)dst)->as_uint32_t[2] = ((UN_256bitValue*)src)->as_uint32_t[2];
  ((UN_256bitValue*)dst)->as_uint32_t[3] = ((UN_256bitValue*)src)->as_uint32_t[3];
  ((UN_256bitValue*)dst)->as_uint32_t[4] = ((UN_256bitValue*)src)->as_uint32_t[4];
  ((UN_256bitValue*)dst)->as_uint32_t[5] = ((UN_256bitValue*)src)->as_uint32_t[5];
  ((UN_256bitValue*)dst)->as_uint32_t[6] = ((UN_256bitValue*)src)->as_uint32_t[6];
  ((UN_256bitValue*)dst)->as_uint32_t[7] = ((UN_256bitValue*)src)->as_uint32_t[7];
}

// To make sure that copying is unrolled when possible.
static inline void __attribute__((always_inline)) memcpy64(unsigned char* dst, const unsigned char* src)
{
  ((UN_512bitValue*)dst)->as_uint32_t[0] = ((UN_512bitValue*)src)->as_uint32_t[0];
  ((UN_512bitValue*)dst)->as_uint32_t[1] = ((UN_512bitValue*)src)->as_uint32_t[1];
  ((UN_512bitValue*)dst)->as_uint32_t[2] = ((UN_512bitValue*)src)->as_uint32_t[2];
  ((UN_512bitValue*)dst)->as_uint32_t[3] = ((UN_512bitValue*)src)->as_uint32_t[3];
  ((UN_512bitValue*)dst)->as_uint32_t[4] = ((UN_512bitValue*)src)->as_uint32_t[4];
  ((UN_512bitValue*)dst)->as_uint32_t[5] = ((UN_512bitValue*)src)->as_uint32_t[5];
  ((UN_512bitValue*)dst)->as_uint32_t[6] = ((UN_512bitValue*)src)->as_uint32_t[6];
  ((UN_512bitValue*)dst)->as_uint32_t[7] = ((UN_512bitValue*)src)->as_uint32_t[7];
  ((UN_512bitValue*)dst)->as_uint32_t[8] = ((UN_512bitValue*)src)->as_uint32_t[8];
  ((UN_512bitValue*)dst)->as_uint32_t[9] = ((UN_512bitValue*)src)->as_uint32_t[9];
  ((UN_512bitValue*)dst)->as_uint32_t[10] = ((UN_512bitValue*)src)->as_uint32_t[10];
  ((UN_512bitValue*)dst)->as_uint32_t[11] = ((UN_512bitValue*)src)->as_uint32_t[11];
  ((UN_512bitValue*)dst)->as_uint32_t[12] = ((UN_512bitValue*)src)->as_uint32_t[12];
  ((UN_512bitValue*)dst)->as_uint32_t[13] = ((UN_512bitValue*)src)->as_uint32_t[13];
  ((UN_512bitValue*)dst)->as_uint32_t[14] = ((UN_512bitValue*)src)->as_uint32_t[14];
  ((UN_512bitValue*)dst)->as_uint32_t[15] = ((UN_512bitValue*)src)->as_uint32_t[15];
}

static void __attribute__ ((noinline)) memxor(void *dest, const void *src, size_t len)
{
  char *d = dest;
  const char *s = src;
  while(len--)
    *d++ ^= *s++;
}

void hash_masked(unsigned char *output, const unsigned char *input, const unsigned long long inlen, unsigned char *helper_shake_share0, unsigned char *helper_shake_share1)
{
  unsigned char output_s0[64];
  unsigned char output_s1[64];

  // Shares generation
  memcpy(helper_shake_share0, input, inlen);
  randombytes(helper_shake_share1, inlen);
  memxor(helper_shake_share0, helper_shake_share1, inlen);

  shake256_masked(output_s0, output_s1, 64, helper_shake_share0, helper_shake_share1, inlen);

  // Shares recombination
  memcpy64(output, output_s0);
  memxor(output, output_s1, 64);
}

/// @brief Ephemeral Signature Generation
/// @param signed_msg output buffer, at least 64 bytes long
/// @param signed_msg_len length of resulted signature (64)
/// @param msg message to sign (max 1024 bytes)
/// @param msg_len length of the message (max 1024 bytes)
/// @param priv_pub_key 32 bytes of private key concatenated with 32 bytes of public key
/// @return 0 if success, -1 otherwise
int sign(unsigned char *signed_msg,unsigned long long *signed_msg_len,
        const unsigned char *msg,unsigned long long msg_len,
        const unsigned char *priv_pub_key)
{
  unsigned char buff[1088]; // 64+1024
  unsigned char helper_shake_share0[1056]; // 32+1024
  unsigned char helper_shake_share1[1056]; // 32+1024

  UN_512bitValue r; // scalar for scalar multiplication
  unsigned char digest_buff[64];

  // 1. Compute the hash of the private key
  hash_masked(digest_buff, priv_pub_key, 32, helper_shake_share0, helper_shake_share1); // H(priv_key)

  memcpy(buff+64, msg, msg_len);
  memcpy32(buff+32, digest_buff+32); // H(priv_key)32-64 || M

  // 2. r = H(H(priv_key)32-64 || M)
  hash_masked(r.as_uint8_t, buff+32, 32+msg_len, helper_shake_share0, helper_shake_share1);

  sc25519_reduce(&r); // r mod l

  // 3. Compute the point [r]B, static
  if (0 != crypto_scalarmult_base_curve25519(buff, ((UN_256bitValue*)&r)->as_uint8_t)) // buff = [R, H(priv_key)32-64, M]
  {
    return -1;
  }

  // reusable variables
  sc25519 t1, t2, t3, t4, t5, t6;
  UN_512bitValue r1_tmp, r2_tmp;

  // rng to 512b, then reduction to 256 for better uniform random distribution
  randombytes(r1_tmp.as_uint8_t, 64);
  randombytes(r2_tmp.as_uint8_t, 64);
  fe25519_reduceTo256Bits(&t1, &r1_tmp); // u in Alg. Sign, Generate random value for further private scalar multiplication blinding
  fe25519_reduceTo256Bits(&t2, &r2_tmp); // v in Alg. Sign, Generate random value for further private scalar multiplication blinding

  sc25519_mul(&t3, &t1, &t2); // u*v
  
  // inverse protection
  randombytes(r1_tmp.as_uint8_t, 64);
  fe25519_reduceTo256Bits(&t4, &r1_tmp); // tmp1 in Alg. Sign, Generate random value for inversion blinding

  sc25519_mul(&t5, &t3, &t4); // tmp2 = u*v*tmp1 in Alg. Sign, Blind the product for future inversion, t3 is freed
  sc25519_inverse(&t6, &t5);  // tmp2^(-1) = (u*v*tmp1)^(-1), Inversion, t5 is freed
  sc25519_mul(&t3, &t6, &t4); // uv_inv = tmp2^(-1) * tmp1 = (u*v*tmp1)^(-1) * tmp1 = (u*v)^(-1) in Alg. Sign, Unblind the inverse, t6 and t4 is freed

  // 4. Derive s (private scalar) from H(priv_key) as in the key pair generation algorithm
  memcpy32(t4.as_uint8_t, digest_buff);
  t4.as_uint8_t[0] &= 248;
  t4.as_uint8_t[31] &= 63;
  t4.as_uint8_t[31] |= 64;

  sc25519_mul(&t5, &t4, &t1); // us = u*s in Alg. Sign, Blind the private scalar, t1 and t4 are freed

  // 4.1 buff = [R, A, M]
  memcpy32(buff + 32, priv_pub_key + 32);

  // dif = H(R,A,M)
  hash_masked(digest_buff, buff, 32+32+msg_len, helper_shake_share0, helper_shake_share1);

  sc25519_reduce((UN_512bitValue*)digest_buff); // dig mod l

  // --- t1, t4, t6 are free ---

  memcpy32(t1.as_uint8_t, digest_buff); // dig = H(R||A||M) in Alg. Sign

  // 5. S = (r + dig * s)
  sc25519_mul(&t4, &t1, &t5); // dig_tmp1 = dig * us in Alg. Sign, Multiply digest with blinded private scalar, t1 and t5 are freed
  sc25519_mul(&t6, &t4, &t3); // dig_tmp2 = dig_tmp1 * uv_inv = dig * u*s * (u*v)^(-1) = dig * s * v^(-1) in Alg. Sign, Unblind part of result, t4 and t3 are freed
  sc25519_mul(&t3, &t6, &t2); // dig_s = dig_tmp2 * v = dig * s * v^(-1) * v = dig*s in Alg. Sign, Unblind rest of result, t2 and t6 are freed

  sc25519_add(&t4, (UN_256bitValue*)(&r), &t3); // S = r + dig*s in Alg. Sign, t3 is freed

  // 6. signed_msg = R||S
  memcpy32(buff + 32, t4.as_uint8_t); // t4 is freed
  memcpy64(signed_msg, buff);
  *signed_msg_len = 32+32;

  return 0;
}

/// @brief Ephemeral Signature Generation
/// @param signed_msg output buffer, at least 64 bytes long
/// @param signed_msg_len length of resulted signature (64)
/// @param msg message to sign (max 1024 bytes)
/// @param msg_len length of the message (max 1024 bytes)
/// @param priv_pub_key 32 bytes of private key concatenated with 32 bytes of public key
/// @return 0 if success, -1 otherwise
int sign_ephemeral(unsigned char *signed_msg,unsigned long long *signed_msg_len,
  const unsigned char *msg,unsigned long long msg_len,
  const unsigned char *priv_pub_key)
{
  unsigned char buff[1088]; // 64+1024
  unsigned char helper_shake_share0[1056]; // 32+1024
  unsigned char helper_shake_share1[1056]; // 32+1024

  UN_512bitValue r; // scalar for scalar multiplication
  unsigned char digest_buff[64];

  // 1. Compute the hash of the private key
  hash_masked(digest_buff, priv_pub_key, 32, helper_shake_share0, helper_shake_share1); // H(priv_key)

  memcpy(buff+64, msg, msg_len);
  memcpy32(buff+32, digest_buff+32); // H(priv_key)32-64 || M

  // 2. r = H(H(priv_key)32-64 || M)
  hash_masked(r.as_uint8_t, buff+32, 32+msg_len, helper_shake_share0, helper_shake_share1);

  sc25519_reduce(&r); // r mod l

  // 3. Compute the point [r]B, ephemeral
  if (0 != ephemeral_crypto_scalarmult_base_curve25519(buff, ((UN_256bitValue*)&r)->as_uint8_t)) // buff = [R, H(priv_key)32-64, M]
  {
    return -1;
  }

  // reusable variables
  sc25519 t1, t2, t3, t4, t5, t6;
  UN_512bitValue r1_tmp, r2_tmp;

  // rng to 512b, then reduction to 256 for better uniform random distribution
  randombytes(r1_tmp.as_uint8_t, 64);
  randombytes(r2_tmp.as_uint8_t, 64);
  fe25519_reduceTo256Bits(&t1, &r1_tmp); // u in Alg. Sign, Generate random value for further private scalar multiplication blinding
  fe25519_reduceTo256Bits(&t2, &r2_tmp); // v in Alg. Sign, Generate random value for further private scalar multiplication blinding

  sc25519_mul(&t3, &t1, &t2); // u*v
  
  // inverse protection
  randombytes(r1_tmp.as_uint8_t, 64);
  fe25519_reduceTo256Bits(&t4, &r1_tmp); // tmp1 in Alg. Sign, Generate random value for inversion blinding

  sc25519_mul(&t5, &t3, &t4); // tmp2 = u*v*tmp1 in Alg. Sign, Blind the product for future inversion, t3 is freed
  sc25519_inverse(&t6, &t5);  // tmp2^(-1) = (u*v*tmp1)^(-1), Inversion, t5 is freed
  sc25519_mul(&t3, &t6, &t4); // uv_inv = tmp2^(-1) * tmp1 = (u*v*tmp1)^(-1) * tmp1 = (u*v)^(-1) in Alg. Sign, Unblind the inverse, t6 and t4 is freed

  // 4. Derive s (private scalar) from H(priv_key) as in the key pair generation algorithm
  memcpy32(t4.as_uint8_t, digest_buff);
  t4.as_uint8_t[0] &= 248;
  t4.as_uint8_t[31] &= 63;
  t4.as_uint8_t[31] |= 64;

  sc25519_mul(&t5, &t4, &t1); // us = u*s in Alg. Sign, Blind the private scalar, t1 and t4 are freed

  // 4.1 buff = [R, A, M]
  memcpy32(buff + 32, priv_pub_key + 32);

  // dif = H(R,A,M)
  hash_masked(digest_buff, buff, 32+32+msg_len, helper_shake_share0, helper_shake_share1);

  sc25519_reduce((UN_512bitValue*)digest_buff); // dig mod l

  // --- t1, t4, t6 are free ---

  memcpy32(t1.as_uint8_t, digest_buff); // dig = H(R||A||M) in Alg. Sign

  // 5. S = (r + dig * s)
  sc25519_mul(&t4, &t1, &t5); // dig_tmp1 = dig * us in Alg. Sign, Multiply digest with blinded private scalar, t1 and t5 are freed
  sc25519_mul(&t6, &t4, &t3); // dig_tmp2 = dig_tmp1 * uv_inv = dig * u*s * (u*v)^(-1) = dig * s * v^(-1) in Alg. Sign, Unblind part of result, t4 and t3 are freed
  sc25519_mul(&t3, &t6, &t2); // dig_s = dig_tmp2 * v = dig * s * v^(-1) * v = dig*s in Alg. Sign, Unblind rest of result, t2 and t6 are freed

  sc25519_add(&t4, (UN_256bitValue*)(&r), &t3); // S = r + dig*s in Alg. Sign, t3 is freed

  // 6. signed_msg = R||S
  memcpy32(buff + 32, t4.as_uint8_t); // t4 is freed
  memcpy64(signed_msg, buff);
  *signed_msg_len = 32+32;

  return 0;
}

/// @brief Unprotected Signature Generation
/// @param signed_msg output buffer, at least 64 bytes long
/// @param signed_msg_len length of resulted signature (64)
/// @param msg message to sign (max 1024 bytes)
/// @param msg_len length of the message (max 1024 bytes)
/// @param priv_pub_key 32 bytes of private key concatenated with 32 bytes of public key
/// @return 0 if success, -1 otherwise
int sign_unprotected(unsigned char *signed_msg,unsigned long long *signed_msg_len,
  const unsigned char *msg,unsigned long long msg_len,
  const unsigned char *priv_pub_key)
{
  unsigned char buff[1088]; // 64+1024
  unsigned char helper_shake_share0[1056]; // 32+1024
  unsigned char helper_shake_share1[1056]; // 32+1024

  unsigned char digest_buf[64];

  UN_512bitValue r; // scalar for scalar multiplication
  sc25519 ram_hashed_int;
  sc25519 ram_hashed_mul_s;
  sc25519 s; // private scalar

  // 1. Compute the hash of the private key
  hash_masked(digest_buf, priv_pub_key, 32, helper_shake_share0, helper_shake_share1);

  memcpy(buff+64, msg, msg_len);
  memcpy(buff+32, digest_buf+32, 32); // H(priv_key)32-64 || M

  // 2. r = H(H(priv_key)32-64 || M)
  hash_masked(r.as_uint8_t, buff+32, 32+msg_len, helper_shake_share0, helper_shake_share1);

  sc25519_reduce(&r); // r mod l

  // 3. Compute the point [r]B, unprotected
  if (0 != unprotected_crypto_scalarmult_base_curve25519(buff, ((UN_256bitValue*)&r)->as_uint8_t)) // buff = [R, H(priv_key)32-64, M]
  {
    return -1;
  }

  // 4. Derive s (private scalar) from H(priv_key) as in the key pair generation algorithm (clamping)
  memcpy(s.as_uint8_t, digest_buf, 32);
  s.as_uint8_t[0] &= 248;
  s.as_uint8_t[31] &= 63;
  s.as_uint8_t[31] |= 64;

  // 4.1 buff = [R, A, M]
  memcpy(buff + 32, priv_pub_key + 32, 32); 

  // dig = H(rG||pub_key||M)
  hash_masked(digest_buf, buff, 32+32+msg_len, helper_shake_share0, helper_shake_share1);

  sc25519_reduce((UN_512bitValue*)digest_buf); // dig mod l
  memcpy(ram_hashed_int.as_uint8_t, digest_buf, 32);

  // 5. S = (r + dig * s)
  sc25519_mul(&ram_hashed_mul_s, &ram_hashed_int, &s); // dig * s
  sc25519_add(&s, (UN_256bitValue*)(&r), &ram_hashed_mul_s); // dig * s + r, reuse of s variable

  // 6. signed_msg = R||S
  memcpy(buff + 32, s.as_uint8_t, 32);
  memcpy(signed_msg, buff, 64);
  *signed_msg_len = 32+32;
  
  return 0;
}
