#include "../include/sc25519.h"
#include "../include/fe25519.h"
#include "../include/crypto_scalarmult.h"
#include "../include/ed25519.h"
#include "../include/fips202-masked.h"
#include "../include/randombytes.h"
#include "../../stm32wrapper.h"

#include <string.h>

// To make sure that copying is unrolled when possible.
static void __attribute__((always_inline)) memcpy32(unsigned char* dst, const unsigned char* src)
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
static void __attribute__((always_inline)) memcpy64(unsigned char* dst, const unsigned char* src)
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

  memcpy(helper_shake_share0, input, inlen);
  randombytes(helper_shake_share1, inlen);
  memxor(helper_shake_share0, helper_shake_share1, inlen);

  shake256_masked(output_s0, output_s1, 64, helper_shake_share0, helper_shake_share1, inlen);

  memcpy64(output, output_s0);
  memxor(output, output_s1, 64);
}


// signed_msg must be at least 64+msg_len long, signed_msg in the end contains [R,S,M]
int sign(unsigned char *signed_msg,unsigned long long *signed_msg_len,
        const unsigned char *msg,unsigned long long msg_len,
        const unsigned char *priv_pub_key,
        unsigned char *helper_shake_share0x, unsigned char *helper_shake_share1x)
{
  unsigned char buff[320]; // 64+256
  unsigned char helper_shake_share0[288]; // 32+256
  unsigned char helper_shake_share1[288]; // 32+256

  UN_512bitValue r;
  unsigned char digest_buff[64];

  //char str[100];

  // 1. Compute the hash of the private key
  hash_masked(digest_buff, priv_pub_key, 32, helper_shake_share0, helper_shake_share1); // H(priv_key)
  
  // print
  // to_string_256bitvalue(str, (sc25519*)priv_hashed);
  // send_USART_str((unsigned char *)"priv_hashed:");
  // send_USART_str((unsigned char *)str);

  memcpy(buff+64, msg, msg_len);
  //memcpy(buff+32, priv_hashed+32, 32); // H(priv_key)32-64 || M
  memcpy32(buff+32, digest_buff+32);

  // print
  // to_string_256bitvalue(str, priv_hashed_msg);
  // send_USART_str((unsigned char *)"priv_hashed_msg:");
  // send_USART_str((unsigned char *)str);

  // 2. r = H(H(priv_key)32-64 || M)
  hash_masked(r.as_uint8_t, buff+32, 32+msg_len, helper_shake_share0, helper_shake_share1);

  // print
  // to_string_512bitvalue(str, &r);
  // send_USART_str((unsigned char *)"r:");
  // send_USART_str((unsigned char *)str);

  sc25519_reduce(&r);

  // print
  // to_string_256bitvalue(str, (UN_256bitValue*)&r);
  // send_USART_str((unsigned char *)"r_int(reduced):");
  // send_USART_str((unsigned char *)str);

  // 3. Compute the point [r]G
  if (0 != crypto_scalarmult_base_curve25519(buff, ((UN_256bitValue*)&r)->as_uint8_t)) // buff = [R, H(priv_key)32-64, M]
  {
    return -1;
  }

  // print
  // to_string_256bitvalue(str, &rG);
  // send_USART_str((unsigned char *)"rG:");
  // send_USART_str((unsigned char *)str);

  // rng to 512b, then reduction to 256 for better uniform random distribution
  sc25519 t1, t2, t3, t4, t5, t6;

  UN_512bitValue r1_tmp, r2_tmp;
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

  // 4. Derive s from H(priv_key) as in the key pair generation algorithm
  //memcpy(s, priv_hashed, 32);
  memcpy32(t4.as_uint8_t, digest_buff);
  t4.as_uint8_t[0] &= 248;
  t4.as_uint8_t[31] &= 63;
  t4.as_uint8_t[31] |= 64;

  sc25519_mul(&t5, &t4, &t1); // us = u*s in Alg. Sign, Blind the private scalar, t1 and t4 are freed

  // 4.1 buff = [R, A, M]
  //memcpy(buff + 32, priv_pub_key + 32, 32); // signed_msg = [R, A, M]
  memcpy32(buff + 32, priv_pub_key + 32); // signed_msg = [R, A, M]

  // crypto_hash(rqm_hashed, rqm, 32+32+msg_len);
  hash_masked(digest_buff, buff, 32+32+msg_len, helper_shake_share0, helper_shake_share1);

  sc25519_reduce((UN_512bitValue*)digest_buff); // dig mod l
  //memcpy(ram_hashed_int.as_uint8_t, ram_hashed, 32);

  // --- t1, t4, t6 are free ---

  memcpy32(t1.as_uint8_t, digest_buff); // dig = H(R||A||M) in Alg. Sign

  // 5. S = (r + dig * s)
  sc25519_mul(&t4, &t1, &t5); // dig_tmp1 = dig * us in Alg. Sign, Multiply digest with blinded private scalar, t1 and t5 are freed
  sc25519_mul(&t6, &t4, &t3); // dig_tmp2 = dig_tmp1 * uv_inv = dig * u*s * (u*v)^(-1) = dig * s * v^(-1) in Alg. Sign, Unblind part of result, t4 and t3 are freed
  sc25519_mul(&t3, &t6, &t2); // = (ram_hashed * s * 1/r2) * r2, dig_s = dig_tmp2 * v = dig * s * v^(-1) * v = dig*s in Alg. Sign, Unblinf rest of result, t2 and t6 are freed

  sc25519_add(&t4, (UN_256bitValue*)(&r), &t3); // S = r + dig*s in Alg. Sign, t3 is freed

  // 6. signed_msg = R||S
  //memcpy(buff + 32, S.as_uint8_t, 32);
  memcpy32(buff + 32, t4.as_uint8_t); // t4 is freed
  //memcpy(signed_msg, buff, 64);
  memcpy64(signed_msg, buff);
  *signed_msg_len = 32+32;

  return 0;
}

// signed_msg must be at least 64+msg_len long, signed_msg in the end contains [R,S,M]
int sign_ephemeral(unsigned char *signed_msg,unsigned long long *signed_msg_len,
  const unsigned char *msg,unsigned long long msg_len,
  const unsigned char *priv_pub_key,
  unsigned char *helper_shake_share0, unsigned char *helper_shake_share1)
{
  unsigned char priv_hashed[64];
  //unsigned char priv_hashed_msg[96];
  UN_512bitValue r;
  //UN_256bitValue rG = { 0 };
  //unsigned char rqm[128];
  unsigned char ram_hashed[64];
  unsigned char s[32];
  //sc25519 r_int;
  sc25519 ram_hashed_int;
  sc25519 s_int;
  sc25519 ram_hashed_mul_s;
  sc25519 S;

  char str[100];

  //hash_masked(signed_msg, priv_pub_key, 32, helper_shake_share0, helper_shake_share1);

  // 1. Compute the hash of the private key
  // crypto_hash(priv_hashed, priv_pub_key, 32);
  hash_masked(priv_hashed, priv_pub_key, 32, helper_shake_share0, helper_shake_share1);

  // print
  // to_string_256bitvalue(str, (sc25519*)priv_hashed);
  // send_USART_str((unsigned char *)"priv_hashed:");
  // send_USART_str((unsigned char *)str);

  // use the fact that signed_msg will be at least 64 + msg_len long
  memcpy(signed_msg+64, msg, msg_len);
  memcpy(signed_msg+32, priv_hashed+32, 32); // H(priv_key)32-64 || M

  // memcpy(priv_hashed_msg, priv_hashed + 32, 32);
  // memcpy(priv_hashed_msg + 32, msg, msg_len); // H(priv_key)32-64 || M

  // print
  // to_string_256bitvalue(str, priv_hashed_msg);
  // send_USART_str((unsigned char *)"priv_hashed_msg:");
  // send_USART_str((unsigned char *)str);

  // 2. r = H(H(priv_key)32-64 || M)
  // crypto_hash(r.as_uint8_t, priv_hashed_msg, 32 + msg_len);
  hash_masked(r.as_uint8_t, signed_msg+32, 32+msg_len, helper_shake_share0, helper_shake_share1);

  // print
  // to_string_512bitvalue(str, &r);
  // send_USART_str((unsigned char *)"r:");
  // send_USART_str((unsigned char *)str);

  sc25519_reduce(&r);
  //sc_reduce(r.as_uint8_t);
  //memcpy(r_int.as_uint8_t, r.as_uint8_t, 32);

  // print
  // to_string_256bitvalue(str, (UN_256bitValue*)&r);
  // send_USART_str((unsigned char *)"r_int(reduced):");
  // send_USART_str((unsigned char *)str);

  // 3. Compute the point [r]G
  if (0 != ephemeral_crypto_scalarmult_base_curve25519(signed_msg, ((UN_256bitValue*)&r)->as_uint8_t)) // signed_msg = [R, H(priv_key)32-64, M]
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
  // rng to 512b, then reduction to 256 for better uniform random distribution
  UN_512bitValue r1_tmp, r2_tmp;
  fe25519 r1, r2;
  randombytes(r1.as_uint8_t, 64);
  randombytes(r2.as_uint8_t, 64);
  fe25519_reduceTo256Bits(&r1, &r1_tmp);
  fe25519_reduceTo256Bits(&r2, &r2_tmp);

  // sc25519 zero;
  // fe25519_setzero(&zero);

  sc25519 r1r2, r1r2_inv, r1s;
  sc25519_mul(&r1r2, &r1, &r2);
  //sc_muladd(r1r2.as_uint8_t, r1.as_uint8_t, r2.as_uint8_t, zero.as_uint8_t);

  // TODO do I need protected inverse?
  // inverse protection
  UN_512bitValue rnd_for_inv_tmp;
  fe25519 rnd_for_inv;
  randombytes(rnd_for_inv_tmp.as_uint8_t, 64);
  fe25519_reduceTo256Bits(&rnd_for_inv, &rnd_for_inv_tmp);

  sc25519 r1r2rnd, r1r2rnd_inv;
  sc25519_mul(&r1r2rnd, &r1r2, &rnd_for_inv);
  sc25519_inverse(&r1r2rnd_inv, &r1r2rnd);
  sc25519_mul(&r1r2_inv, &r1r2rnd_inv, &rnd_for_inv);

  //sc25519_inverse(&r1r2_inv, &r1r2);

  sc25519_mul(&r1s, (sc25519*)s, &r1);

  // 4.1 rqm = H(rG||pub_key||M)
  //memcpy(rqm, rG.as_uint8_t, 32);
  memcpy(signed_msg + 32, priv_pub_key + 32, 32); // signed_msg = [R, A, M]
  //memcpy(rqm + 64, msg, msg_len);

  // crypto_hash(rqm_hashed, rqm, 32+32+msg_len);
  hash_masked(ram_hashed, signed_msg, 32+32+msg_len, helper_shake_share0, helper_shake_share1);

  sc25519_reduce((UN_512bitValue*)ram_hashed);
  memcpy(ram_hashed_int.as_uint8_t, ram_hashed, 32);

  // 5. S = (r + rqm_hashed * s)
  //sc25519_mul(&rqm_hashed_mul_s, &rqm_hashed_int, (sc25519*)s);
  sc25519 ram_hashed_mul_r1s;
  sc25519 ram_hashed_mul_s_r2_inv;

  sc25519_mul(&ram_hashed_mul_r1s, &ram_hashed_int, &r1s);                // = ram_hashed * r1*s
  sc25519_mul(&ram_hashed_mul_s_r2_inv, &ram_hashed_mul_r1s, &r1r2_inv);  // = (ram_hashed * r1*s) * 1/(r1*r2)
  sc25519_mul(&ram_hashed_mul_s, &ram_hashed_mul_s_r2_inv, &r2);          // = (ram_hashed * s * 1/r2) * r2

  sc25519_add(&S, (UN_256bitValue*)(&r), &ram_hashed_mul_s);

  // 6. signed_msg = R||S
  //memcpy(signed_msg, rG.as_uint8_t, 32); // TODO need to encode the R!!! or is it already?
  memcpy(signed_msg + 32, S.as_uint8_t, 32);
  *signed_msg_len = 32+32+msg_len;

  return 0;
}

// signed_msg must be at least 64+msg_len long, signed_msg in the end contains [R,S,M]
int sign_unprotected(unsigned char *signed_msg,unsigned long long *signed_msg_len,
  const unsigned char *msg,unsigned long long msg_len,
  const unsigned char *priv_pub_key,
  unsigned char *helper_shake_share0, unsigned char *helper_shake_share1)
{
  unsigned char priv_hashed[64];
  //unsigned char priv_hashed_msg[96];
  UN_512bitValue r;
  //UN_256bitValue rG = { 0 };
  //unsigned char rqm[128];
  unsigned char ram_hashed[64];
  unsigned char s[32];
  //sc25519 r_int;
  sc25519 ram_hashed_int;
  sc25519 s_int;
  sc25519 ram_hashed_mul_s;
  sc25519 S;

  char str[100];

  // 1. Compute the hash of the private key
  // crypto_hash(priv_hashed, priv_pub_key, 32);
  hash_masked(priv_hashed, priv_pub_key, 32, helper_shake_share0, helper_shake_share1);

  // print
  // to_string_256bitvalue(str, (sc25519*)priv_hashed);
  // send_USART_str((unsigned char *)"priv_hashed:");
  // send_USART_str((unsigned char *)str);

  // use the fact that signed_msg will be at least 64 + msg_len long
  memcpy(signed_msg+64, msg, msg_len);
  memcpy(signed_msg+32, priv_hashed+32, 32); // H(priv_key)32-64 || M

  // memcpy(priv_hashed_msg, priv_hashed + 32, 32);
  // memcpy(priv_hashed_msg + 32, msg, msg_len); // H(priv_key)32-64 || M

  // print
  // to_string_256bitvalue(str, priv_hashed_msg);
  // send_USART_str((unsigned char *)"priv_hashed_msg:");
  // send_USART_str((unsigned char *)str);

  // 2. r = H(H(priv_key)32-64 || M)
  // crypto_hash(r.as_uint8_t, priv_hashed_msg, 32 + msg_len);
  hash_masked(r.as_uint8_t, signed_msg+32, 32+msg_len, helper_shake_share0, helper_shake_share1);

  // print
  // to_string_512bitvalue(str, &r);
  // send_USART_str((unsigned char *)"r:");
  // send_USART_str((unsigned char *)str);

  sc25519_reduce(&r);
  //sc_reduce(r.as_uint8_t);
  //memcpy(r_int.as_uint8_t, r.as_uint8_t, 32);

  // print
  // to_string_256bitvalue(str, (UN_256bitValue*)&r);
  // send_USART_str((unsigned char *)"r_int(reduced):");
  // send_USART_str((unsigned char *)str);

  // 3. Compute the point [r]G
  // if (0 != crypto_scalarmult_base_curve25519(signed_msg, ((UN_256bitValue*)&r)->as_uint8_t)) // signed_msg = [R, H(priv_key)32-64, M]
  if (0 != unprotected_crypto_scalarmult_base_curve25519(signed_msg, ((UN_256bitValue*)&r)->as_uint8_t)) // signed_msg = [R, H(priv_key)32-64, M]
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

  // 4.1 rqm = H(rG||pub_key||M)
  //memcpy(rqm, rG.as_uint8_t, 32);
  memcpy(signed_msg + 32, priv_pub_key + 32, 32); // signed_msg = [R, A, M]
  //memcpy(rqm + 64, msg, msg_len);

  // crypto_hash(rqm_hashed, rqm, 32+32+msg_len);
  hash_masked(ram_hashed, signed_msg, 32+32+msg_len, helper_shake_share0, helper_shake_share1);

  sc25519_reduce((UN_512bitValue*)ram_hashed);
  memcpy(ram_hashed_int.as_uint8_t, ram_hashed, 32);

  // 5. S = (r + rqm_hashed * s)
  sc25519_mul(&ram_hashed_mul_s, &ram_hashed_int, (sc25519*)s);
  sc25519_add(&S, (UN_256bitValue*)(&r), &ram_hashed_mul_s);

  // 6. signed_msg = R||S
  //memcpy(signed_msg, rG.as_uint8_t, 32); // TODO need to encode the R!!! or is it already?
  memcpy(signed_msg + 32, S.as_uint8_t, 32);
  *signed_msg_len = 32+32+msg_len;

  return 0;
}

/*// signed_msg = (R, S, M) = (32, 32, M_len), msg_len >= signed_msg_len on input
int verify(unsigned char *msg, unsigned long long *msg_len,
          const unsigned char *signed_msg, const unsigned long long signed_msg_len,
          const unsigned char *pub_key)
{
  unsigned char R_compressed[32];
  fe25519 R_x_ea, R_y_ea, R_x_mp, R_y_mp, R_z_mp;
  fe25519 A_x_ea, A_y_ea, A_x_mp, A_y_mp, A_z_mp;
  fe25519 SB_x_ea, SB_y_ea, SB_x_mp, SB_y_mp, SB_z_mp;
  fe25519 R_kA_x_ea, R_kA_y_ea, R_kA_x_mp, R_kA_y_mp, R_kA_z_mp;
  unsigned char A[32];
  unsigned char hramA_encoded_ea[32];
  unsigned char S[32];
  unsigned char SB_encoded_ea[32];
  unsigned char ram[128];
  unsigned char hram[64];
  point25519 R_kA_mp;
  point25519 R_mp;
  //point25519 A_mp;
  point25519 SB_mp;
  point25519 hramA_mp;

  R_mp.x = &R_x_mp;
  R_mp.y = &R_y_mp;
  R_mp.z = &R_z_mp;

  hramA_mp.x = &A_x_mp;
  hramA_mp.y = &A_y_mp;
  hramA_mp.z = &A_z_mp;
  
  R_kA_mp.x = &R_kA_x_mp;
  R_kA_mp.y = &R_kA_y_mp;
  R_kA_mp.z = &R_kA_z_mp;

  unsigned char str[100];
  send_USART_str((unsigned char *)"-----verify()-----");

  memcpy(R_compressed, signed_msg, 32);

  to_string_256bitvalue(str, (UN_256bitValue*)R_compressed);
  send_USART_str((unsigned char *)"verify(): R_compressed:");
  send_USART_str((unsigned char *)str);
  to_string_256bitvalue(str, (UN_256bitValue*)pub_key);
  send_USART_str((unsigned char *)"verify(): pub_key(compressed):");
  send_USART_str((unsigned char *)str);

  // R <- point_decompress(R_compressed)
  if (ed25519_decode(&R_x_ea, &R_y_ea, R_compressed) != 0)
    return 1;
  to_string_256bitvalue(str, (UN_256bitValue*)&R_x_ea);
  send_USART_str((unsigned char *)"verify(): R_x_ea:");
  send_USART_str((unsigned char *)str);
  to_string_256bitvalue(str, (UN_256bitValue*)&R_y_ea);
  send_USART_str((unsigned char *)"verify(): R_y_ea:");
  send_USART_str((unsigned char *)str);

  // A <- point_decompress(pub_key)
  if (ed25519_decode(&A_x_ea, &A_y_ea, pub_key) != 0)
    return 1;  
  to_string_256bitvalue(str, (UN_256bitValue*)&A_x_ea);
  send_USART_str((unsigned char *)"verify(): A_x_ea:");
  send_USART_str((unsigned char *)str);
  to_string_256bitvalue(str, (UN_256bitValue*)&A_y_ea);
  send_USART_str((unsigned char *)"verify(): A_y_ea:");
  send_USART_str((unsigned char *)str);


  memcpy(S, signed_msg+32, 32); // TODO look at supercop, should not be reduced?
  

  memcpy(msg, signed_msg, signed_msg_len); // msg=[R,S,msg]
  memcpy(msg+32, pub_key, 32); // msg=[R,A,msg]

  //memcpy(ram, R_compressed, 32);
  //memcpy(ram+32, pub_key, 32);
  //memcpy(ram+64, msg, msg_len);
  //hash_masked(ram_hashed, ram, 32+32+msg_len);
  hash_masked(hram, msg, signed_msg_len);
  sc25519_reduce((UN_512bitValue*)hram);
  to_string_256bitvalue(str, (UN_256bitValue*)hram);
  send_USART_str((unsigned char *)"verify(): hram:");
  send_USART_str((unsigned char *)str);

  // R_mp <- point_conversion_ea_mp(R)
  point_conversion_ea_mp(R_mp.x, R_mp.y, R_mp.z, &R_x_ea, &R_y_ea);

  // A_mp <- point_conversion_ea_mp(A)
  point_conversion_ea_mp(&A_x_mp, &A_y_mp, &A_z_mp, &A_x_ea, &A_y_ea);
  to_string_256bitvalue(str, (UN_256bitValue*)&A_x_mp);
  send_USART_str((unsigned char *)"verify(): A_x_mp:");
  send_USART_str((unsigned char *)str);
  to_string_256bitvalue(str, (UN_256bitValue*)&A_y_mp);
  send_USART_str((unsigned char *)"verify(): A_y_mp:");
  send_USART_str((unsigned char *)str);

  // kA_mp <- scamult(A, k)
  crypto_scalarmult_curve25519(hramA_encoded_ea, hram, A_x_mp.as_uint8_t);

  // SB_mp <- scamult_base(S)
  crypto_scalarmult_base_curve25519(SB_encoded_ea, S);
  to_string_256bitvalue(str, (UN_256bitValue*)S);
  send_USART_str((unsigned char *)"verify(): S:");
  send_USART_str((unsigned char *)str);

  if (ed25519_decode(&A_x_ea, &A_y_ea, hramA_encoded_ea) != 0)
    return 1;
  to_string_256bitvalue(str, (UN_256bitValue*)&A_x_ea);
  send_USART_str((unsigned char *)"verify(): kA_x_ea:");
  send_USART_str((unsigned char *)str);
  to_string_256bitvalue(str, (UN_256bitValue*)&A_y_ea);
  send_USART_str((unsigned char *)"verify(): kA_y_ea:");
  send_USART_str((unsigned char *)str);
  point_conversion_ea_mp(&A_x_mp, &A_y_mp, &A_z_mp, &A_x_ea, &A_y_ea);

  // R_kA_mp <- curve25519_addPoint(res, R_mp, kA_mp)
  curve25519_addPoint(&R_kA_mp, &R_mp, &hramA_mp);

  // R_kA_ea <- point_conversion_mp_ea(R_kA_mp)
  point_conversion_mp_ea(&R_kA_x_ea, &R_kA_y_ea, &R_kA_x_mp, &R_kA_y_mp, &R_kA_z_mp);

  // SB_ea <- point_conversion_mp_ea(SB_mp)
  //point_conversion_mp_ea(&SB_x_ea, &SB_y_ea, &SB_x_mp, &SB_y_mp, &SB_z_mp);

  // compare(R_kA_ea, SB_ea) // maybe this can be done in mp
  unsigned char R_kA_ea_enc[32];
  unsigned char SB_ea_enc[32];
  ed25519_encode(R_kA_ea_enc, &R_kA_x_ea, &R_kA_y_ea);
  //ed25519_encode(SB_ea_enc, &SB_x_ea, &SB_y_ea);

  to_string_256bitvalue(str, (UN_256bitValue*)SB_encoded_ea);
  send_USART_str((unsigned char *)"verify(): SB_encoded_ea:");
  send_USART_str((unsigned char *)str);
  to_string_256bitvalue(str, (UN_256bitValue*)&R_kA_x_ea);
  send_USART_str((unsigned char *)"verify(): R_kA_x_ea:");
  send_USART_str((unsigned char *)str);
  to_string_256bitvalue(str, (UN_256bitValue*)&R_kA_y_ea);
  send_USART_str((unsigned char *)"verify(): R_kA_y_ea:");
  send_USART_str((unsigned char *)str);


  // test od conversion
  fe25519 tmp1_x_mp, tmp1_y_mp, tmp1_z_mp;

  send_USART_str((unsigned char *)"---TEST CONVERSION: BEFORE---");
  to_string_256bitvalue(str, (UN_256bitValue*)&R_x_ea);
  send_USART_str((unsigned char *)"verify(): R_x_ea:");
  send_USART_str((unsigned char *)str);
  to_string_256bitvalue(str, (UN_256bitValue*)&R_y_ea);
  send_USART_str((unsigned char *)"verify(): R_y_ea:");
  send_USART_str((unsigned char *)str);

  point_conversion_ea_mp(&tmp1_x_mp, &tmp1_y_mp, &tmp1_z_mp, &R_x_ea, &R_y_ea);

  send_USART_str((unsigned char *)"---TEST CONVERSION: MIDDLE---");
  to_string_256bitvalue(str, (UN_256bitValue*)&tmp1_x_mp);
  send_USART_str((unsigned char *)"verify(): tmp1_x_mp:");
  send_USART_str((unsigned char *)str);
  to_string_256bitvalue(str, (UN_256bitValue*)&tmp1_y_mp);
  send_USART_str((unsigned char *)"verify(): tmp1_y_mp:");
  send_USART_str((unsigned char *)str);

  point_conversion_mp_ea(&R_x_ea, &R_y_ea, &tmp1_x_mp, &tmp1_y_mp, &tmp1_z_mp);

  send_USART_str((unsigned char *)"---TEST CONVERSION: AFTER---");
  to_string_256bitvalue(str, (UN_256bitValue*)&R_x_ea);
  send_USART_str((unsigned char *)"verify(): R_x_ea:");
  send_USART_str((unsigned char *)str);
  to_string_256bitvalue(str, (UN_256bitValue*)&R_y_ea);
  send_USART_str((unsigned char *)"verify(): R_y_ea:");
  send_USART_str((unsigned char *)str);

  fe25519 B_x_ma = {{ 0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, }};
  fe25519 B_y_ma = {{ 0xd9, 0xd3, 0xce, 0x7e, 0xa2, 0xc5, 0xe9, 0x29, 0xb2, 0x61, 0x7c, 0x6d, 0x7e, 0x4d, 0x3d, 0x92, 0x4c, 0xd1, 0x48, 0x77, 0x2c, 0xdd, 0x1e, 0xe0, 0xb4, 0x86, 0xa0, 0xb8, 0xa1, 0x19, 0xae, 0x20, }};
  fe25519 B_x_ea = {{ 0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21, }};
  fe25519 B_y_ea = {{ 0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, }};
  fe25519 one;
  fe25519_setone(&one);

  fe25519 res_B_x_ea;
  fe25519 res_B_y_ea;
  fe25519 res_B_x_mp;
  fe25519 res_B_y_mp;
  fe25519 res_B_z_mp;


  point_conversion_ea_mp(&res_B_x_mp, &res_B_y_mp, &res_B_z_mp, &B_x_ea, &B_y_ea);
  point_conversion_mp_ea(&res_B_x_ea, &res_B_y_ea, &B_x_ma, &B_y_ma, &one);

  send_USART_str((unsigned char *)"---TEST BASE POINT CONVERSION:---");
  to_string_256bitvalue(str, (UN_256bitValue*)&res_B_x_mp);
  send_USART_str((unsigned char *)"verify(): res_B_x_mp:");
  send_USART_str((unsigned char *)str);
  to_string_256bitvalue(str, (UN_256bitValue*)&res_B_y_mp);
  send_USART_str((unsigned char *)"verify(): res_B_y_mp:");
  send_USART_str((unsigned char *)str);
  to_string_256bitvalue(str, (UN_256bitValue*)&res_B_x_ea);
  send_USART_str((unsigned char *)"verify(): res_B_x_ea:");
  send_USART_str((unsigned char *)str);
  to_string_256bitvalue(str, (UN_256bitValue*)&res_B_y_ea);
  send_USART_str((unsigned char *)"verify(): res_B_y_ea:");
  send_USART_str((unsigned char *)str);


  for (int i = 0; i < 32; i++) { // TODO rewrite const time
    if (R_kA_ea_enc[i] != SB_encoded_ea[i])
      return 1;
  }

  return 0;





  // SB = [S]B
  // kA = [k]A (k=ram_masked)
  // [S]B == R + [k]A



  // TODO look how supercop ref deals with variable msg len in sign, it returns sm = [R,S,msg]
}
*/
