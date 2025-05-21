#include "main.h"

#include <stdio.h>

//#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// cw dependencies
#include "hal.h"
#include "simpleserial.h"

#define DATA_LEN 16  // up to 190 for SS_VER_1_1
#define RESP_LEN 16
#define DATA_LEN_MSG 32
#define DATA_LEN_KEY 64
#define RESP_LEN_SANITY 16
#define RESP_LEN_POINT 32
#define RESP_LEN_SIGNATURE 64
#define TVLA_SCAMULT 0
#define TVLA_SIGN 1


#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
uint8_t scalarmult_unprotected_test(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) {
#else
uint8_t scalarmult_unprotected_test(uint8_t* data, uint8_t dlen) {
#endif

  // uint8_t resulted_point[32];
  char str[100];

  uint32_t res;
  trigger_high();
  res = test_scalarmult_unprotected();
  trigger_low();
  
  sprintf(str, "Sanity check : %lu", res);
  simpleserial_put('r', RESP_LEN_SANITY, (unsigned char*)str);
  // simpleserial_put('r', 32, resulted_point);

  return 0x00;
}

#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
uint8_t scalarmult_test(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) {
#else
uint8_t scalarmult_test(uint8_t* data, uint8_t dlen) {
#endif

  // uint8_t resulted_point[32];
  char str[100];

  uint32_t res;
  trigger_high();
  res = test_scalarmult();
  trigger_low();
  
  sprintf(str, "Sanity check : %lu", res);
  simpleserial_put('r', RESP_LEN_SANITY, (unsigned char*)str);
  // simpleserial_put('r', 32, resulted_point);

  return 0x00;
}

#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
uint8_t scalarmult_ephemeral_test(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) {
#else
uint8_t scalarmult_ephemeral_test(uint8_t* data, uint8_t dlen) {
#endif

  // uint8_t resulted_point[32];
  char str[100];

  uint32_t res;
  trigger_high();
  res = test_scalarmult_ephemeral();
  trigger_low();
  
  sprintf(str, "Sanity check : %lu", res);
  simpleserial_put('r', RESP_LEN_SANITY, (unsigned char*)str);
  // simpleserial_put('r', 32, resulted_point);

  return 0x00;
}

#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
uint8_t scalarmult_unprotected_var_sc_test(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) {
#else
uint8_t scalarmult_unprotected_var_sc_test(uint8_t* data, uint8_t dlen) {
#endif

  uint8_t R[32];
  uint8_t r[64];
  memcpy(r, data, 64);
  sc25519_reduce((UN_512bitValue*)r);

  uint32_t res;
  trigger_high();
  res = test_scalarmult_unprotected_var_in(R, r);
  trigger_low();

  simpleserial_put('r', RESP_LEN_POINT, R);

  return 0x00;
}

#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
uint8_t scalarmult_var_sc_test(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) {
#else
uint8_t scalarmult_var_sc_test(uint8_t* data, uint8_t dlen) {
#endif

  uint8_t R[32];
  uint8_t r[64];
  memcpy(r, data, 64);
  sc25519_reduce((UN_512bitValue*)r);

  uint32_t res;
  trigger_high();
  res = test_scalarmult_var_in(R, r);
  trigger_low();

  simpleserial_put('r', RESP_LEN_POINT, R);

  return 0x00;
}

#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
uint8_t scalarmult_ephemeral_var_sc_test(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) {
#else
uint8_t scalarmult_ephemeral_var_sc_test(uint8_t* data, uint8_t dlen) {
#endif

  uint8_t R[32];
  uint8_t r[64];
  memcpy(r, data, 64);
  sc25519_reduce((UN_512bitValue*)r);

  uint32_t res;
  trigger_high();
  res = test_scalarmult_ephemeral_var_in(R, r);
  trigger_low();

  simpleserial_put('r', RESP_LEN_POINT, R);

  return 0x00;
}

#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
uint8_t ed25519_sign_unprotected_test(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) {
#else
uint8_t ed25519_sign_unprotected_test(uint8_t* data, uint8_t dlen) {
#endif

  // uint8_t resulted_signature[64];
  char str[100];

  uint32_t res;
  trigger_high();
  res = test_ed25519_sign_unprotected();
  trigger_low();
  
  sprintf(str, "Sanity check : %lu", res);
  simpleserial_put('r', RESP_LEN_SANITY, (unsigned char*)str);
  // simpleserial_put('r', 32, (unsigned char*)resulted_signature);
  
  return 0x00;
}

#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
uint8_t ed25519_sign_test(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) {
#else
uint8_t ed25519_sign_test(uint8_t* data, uint8_t dlen) {
#endif

  // uint8_t resulted_signature[64];
  char str[100];

  uint32_t res;
  trigger_high();
  res = test_ed25519_sign();
  trigger_low();
  
  sprintf(str, "Sanity check : %lu", res);
  simpleserial_put('r', RESP_LEN_SANITY, (unsigned char*)str);
  // simpleserial_put('r', 32, (unsigned char*)resulted_signature);
  
  return 0x00;
}

#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
uint8_t ed25519_sign_ephemeral_test(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) {
#else
uint8_t ed25519_sign_ephemeral_test(uint8_t* data, uint8_t dlen) {
#endif

  // uint8_t resulted_signature[64];
  char str[100];

  uint32_t res;
  trigger_high();
  res = test_ed25519_sign_ephemeral();
  trigger_low();
  
  sprintf(str, "Sanity check : %lu", res);
  simpleserial_put('r', RESP_LEN_SANITY, (unsigned char*)str);
  // simpleserial_put('r', 32, (unsigned char*)resulted_signature);
  
  return 0x00;
}


#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
uint8_t ed25519_sign_unprotected_var_msg_test(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) {
#else
uint8_t ed25519_sign_unprotected_var_msg_test(uint8_t* data, uint8_t dlen) {
#endif

  // char str[100];

  // [R, S, M], M for testing will be 32 bytes long
  uint8_t signed_msg[32+32+32];
  unsigned long long signed_msg_len = sizeof(signed_msg) / sizeof(signed_msg[0]);

  uint8_t priv_pub_key[64] = { // pubkey created with SHAKE256
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x3, 0x1c, 0xae, 0x7f, 0x60,
    0xc, 0xdb, 0x1e, 0xd8, 0x64, 0x17, 0x7, 0x7e,
    0xae, 0xb7, 0x30, 0x37, 0x9c, 0xa3, 0x28, 0x6c,
    0x57, 0x9, 0xaa, 0xfe, 0xc4, 0x6, 0x86, 0xc7,
    0x31, 0xa1, 0x2d, 0x63, 0x49, 0x9e, 0xe0, 0xb5 };

  uint32_t res;
  trigger_high();
  res = test_ed25519_sign_unprotected_var_in(
    signed_msg, &signed_msg_len,
    priv_pub_key,
    data, (unsigned long long) dlen
  );
  trigger_low();
  
  // sprintf(str, "Sanity check : %lu", res);
  // simpleserial_put('r', 16, (unsigned char*)str);
  simpleserial_put('r', RESP_LEN_SIGNATURE, signed_msg);

  return 0x00;
}

#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
uint8_t ed25519_sign_var_msg_test(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) {
#else
uint8_t ed25519_sign_var_msg_test(uint8_t* data, uint8_t dlen) {
#endif

  // char str[100];

  // [R, S, M], M for testing will be 32 bytes long
  uint8_t signed_msg[32+32+32];
  unsigned long long signed_msg_len = sizeof(signed_msg) / sizeof(signed_msg[0]);

  uint8_t priv_pub_key[64] = { // pubkey created with SHAKE256
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x3, 0x1c, 0xae, 0x7f, 0x60,
    0xc, 0xdb, 0x1e, 0xd8, 0x64, 0x17, 0x7, 0x7e,
    0xae, 0xb7, 0x30, 0x37, 0x9c, 0xa3, 0x28, 0x6c,
    0x57, 0x9, 0xaa, 0xfe, 0xc4, 0x6, 0x86, 0xc7,
    0x31, 0xa1, 0x2d, 0x63, 0x49, 0x9e, 0xe0, 0xb5 };

  uint32_t res;
  trigger_high();
  res = test_ed25519_sign_var_in(
    signed_msg, &signed_msg_len,
    priv_pub_key,
    data, (unsigned long long) dlen
  );
  trigger_low();
  
  // sprintf(str, "Sanity check : %lu", res);
  // simpleserial_put('r', 16, (unsigned char*)str);
  simpleserial_put('r', RESP_LEN_SIGNATURE, signed_msg);

  return 0x00;
}

#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
uint8_t ed25519_sign_ephemeral_var_msg_test(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) {
#else
uint8_t ed25519_sign_ephemeral_var_msg_test(uint8_t* data, uint8_t dlen) {
#endif

  // char str[100];

  // [R, S, M], M for testing will be 32 bytes long
  uint8_t signed_msg[32+32+32];
  unsigned long long signed_msg_len = sizeof(signed_msg) / sizeof(signed_msg[0]);

  uint8_t priv_pub_key[64] = { // pubkey created with SHAKE256
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x3, 0x1c, 0xae, 0x7f, 0x60,
    0xc, 0xdb, 0x1e, 0xd8, 0x64, 0x17, 0x7, 0x7e,
    0xae, 0xb7, 0x30, 0x37, 0x9c, 0xa3, 0x28, 0x6c,
    0x57, 0x9, 0xaa, 0xfe, 0xc4, 0x6, 0x86, 0xc7,
    0x31, 0xa1, 0x2d, 0x63, 0x49, 0x9e, 0xe0, 0xb5 };

  uint32_t res;
  trigger_high();
  res = test_ed25519_sign_ephemeral_var_in(
    signed_msg, &signed_msg_len,
    priv_pub_key,
    data, (unsigned long long) dlen
  );
  trigger_low();
  
  // sprintf(str, "Sanity check : %lu", res);
  // simpleserial_put('r', 16, (unsigned char*)str);
  simpleserial_put('r', RESP_LEN_SIGNATURE, signed_msg);

  return 0x00;
}


#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
uint8_t ed25519_sign_unprotected_var_key_test(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) {
#else
uint8_t ed25519_sign_unprotected_var_key_test(uint8_t* data, uint8_t dlen) {
#endif

  if (dlen != 64) { // priv_pub_key must be 64 bytes long
    return 0x00;
  }

  // char str[100];

  unsigned char  msg[] = { // TODO better msg, at least 32
    0xab, 0x11, 0xcc, 0xdd, 0xee, 0xff, 0xee, 0xff, 0xee, 0xdd
  };
  unsigned long long msg_len = sizeof(msg) / sizeof(msg[0]);

  // [R, S, M]
  uint8_t signed_msg[msg_len+32+32];
  unsigned long long signed_msg_len = sizeof(signed_msg) / sizeof(signed_msg[0]);

  uint32_t res;
  trigger_high();
  res = test_ed25519_sign_unprotected_var_in(
    signed_msg, &signed_msg_len,
    data,
    msg, msg_len);
  trigger_low();
  
  // sprintf(str, "Sanity check : %lu", res);
  // simpleserial_put('r', 16, (unsigned char*)str);
  simpleserial_put('r', RESP_LEN_SIGNATURE, signed_msg);

  return 0x00;
}

#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
uint8_t ed25519_sign_var_key_test(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) {
#else
uint8_t ed25519_sign_var_key_test(uint8_t* data, uint8_t dlen) {
#endif

  if (dlen != 64) { // priv_pub_key must be 64 bytes long
    return 0x00;
  }

  // char str[100];

  unsigned char  msg[] = { // TODO better msg, at least 32
    0xab, 0x11, 0xcc, 0xdd, 0xee, 0xff, 0xee, 0xff, 0xee, 0xdd
  };
  unsigned long long msg_len = sizeof(msg) / sizeof(msg[0]);

  // [R, S, M]
  uint8_t signed_msg[msg_len+32+32];
  unsigned long long signed_msg_len = sizeof(signed_msg) / sizeof(signed_msg[0]);

  uint32_t res;
  trigger_high();
  res = test_ed25519_sign_var_in(
    signed_msg, &signed_msg_len,
    data,
    msg, msg_len);
  trigger_low();
  
  // sprintf(str, "Sanity check : %lu", res);
  // simpleserial_put('r', 16, (unsigned char*)str);
  simpleserial_put('r', RESP_LEN_SIGNATURE, signed_msg);

  return 0x00;
}

#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
uint8_t ed25519_sign_ephemeral_var_key_test(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) {
#else
uint8_t ed25519_sign_ephemeral_var_key_test(uint8_t* data, uint8_t dlen) {
#endif

  if (dlen != 64) { // priv_pub_key must be 64 bytes long
    return 0x00;
  }

  // char str[100];

  unsigned char  msg[] = { // TODO better msg, at least 32
    0xab, 0x11, 0xcc, 0xdd, 0xee, 0xff, 0xee, 0xff, 0xee, 0xdd
  };
  unsigned long long msg_len = sizeof(msg) / sizeof(msg[0]);

  // [R, S, M]
  uint8_t signed_msg[msg_len+32+32];
  unsigned long long signed_msg_len = sizeof(signed_msg) / sizeof(signed_msg[0]);

  uint32_t res;
  trigger_high();
  res = test_ed25519_sign_ephemeral_var_in(
    signed_msg, &signed_msg_len,
    data,
    msg, msg_len);
  trigger_low();
  
  // sprintf(str, "Sanity check : %lu", res);
  // simpleserial_put('r', 16, (unsigned char*)str);
  simpleserial_put('r', RESP_LEN_SIGNATURE, signed_msg);

  return 0x00;
}

#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
uint8_t echo_test(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) {
#else
uint8_t echo_test(uint8_t* data, uint8_t dlen) {
#endif
  trigger_high();
  simpleserial_put('r', RESP_LEN, data);
  trigger_low();
  return 0x00;
}

#define TVLA TVLA_SCAMULT

int main(void) {
  platform_init();
  init_uart();
  trigger_setup();
  simpleserial_init();
  srand(time(0));

  #if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
    
    simpleserial_addcmd('a', DATA_LEN, scalarmult_unprotected_test);
    simpleserial_addcmd('b', DATA_LEN, scalarmult_test);
    simpleserial_addcmd('m', DATA_LEN, scalarmult_ephemeral_test);
    simpleserial_addcmd('c', DATA_LEN, ed25519_sign_unprotected_test);
    simpleserial_addcmd('d', DATA_LEN, ed25519_sign_test);
    simpleserial_addcmd('n', DATA_LEN, ed25519_sign_ephemeral_test);

    simpleserial_addcmd('e', DATA_LEN, echo_test);

    #if TVLA == TVLA_SIGN
      simpleserial_addcmd('f', DATA_LEN_MSG, ed25519_sign_unprotected_var_msg_test);
      simpleserial_addcmd('g', DATA_LEN_MSG, ed25519_sign_var_msg_test);
      simpleserial_addcmd('h', DATA_LEN_KEY, ed25519_sign_unprotected_var_key_test);
      simpleserial_addcmd('i', DATA_LEN_KEY, ed25519_sign_var_key_test);
      simpleserial_addcmd('o', DATA_LEN_MSG, ed25519_sign_ephemeral_var_msg_test);
      simpleserial_addcmd('p', DATA_LEN_KEY, ed25519_sign_ephemeral_var_key_test);
    #elif TVLA == TVLA_SCAMULT
      simpleserial_addcmd('j', DATA_LEN_KEY, scalarmult_var_sc_test);
      simpleserial_addcmd('k', DATA_LEN_KEY, scalarmult_unprotected_var_sc_test);
      simpleserial_addcmd('l', DATA_LEN_KEY, scalarmult_ephemeral_var_sc_test);
    #endif // TVLA
    
  #else  // SS_VER_1_1, SS_VER_1_0
    simpleserial_addcmd('a', DATA_LEN, scalarmult_unprotected_test);
    simpleserial_addcmd('b', DATA_LEN, scalarmult_test);
    simpleserial_addcmd('m', DATA_LEN, scalarmult_ephemeral_test);
    simpleserial_addcmd('c', DATA_LEN, ed25519_sign_unprotected_test);
    simpleserial_addcmd('d', DATA_LEN, ed25519_sign_test);
    simpleserial_addcmd('n', DATA_LEN, ed25519_sign_ephemeral_test);

    simpleserial_addcmd('e', DATA_LEN, echo_test);

    #if TVLA == TVLA_SIGN
      simpleserial_addcmd('f', DATA_LEN_MSG, ed25519_sign_unprotected_var_msg_test);
      simpleserial_addcmd('g', DATA_LEN_MSG, ed25519_sign_var_msg_test);
      simpleserial_addcmd('h', DATA_LEN_KEY, ed25519_sign_unprotected_var_key_test);
      simpleserial_addcmd('i', DATA_LEN_KEY, ed25519_sign_var_key_test);
      simpleserial_addcmd('o', DATA_LEN_MSG, ed25519_sign_ephemeral_var_msg_test);
      simpleserial_addcmd('p', DATA_LEN_KEY, ed25519_sign_ephemeral_var_key_test);
    #elif TVLA == TVLA_SCAMULT
      simpleserial_addcmd('j', DATA_LEN_KEY, scalarmult_var_sc_test);
      simpleserial_addcmd('k', DATA_LEN_KEY, scalarmult_unprotected_var_sc_test);
      simpleserial_addcmd('l', DATA_LEN_KEY, scalarmult_ephemeral_var_sc_test);
    #endif // TVLA
  #endif

  while (1) {
    simpleserial_get();
  }

  return 0;
}
