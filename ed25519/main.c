#include "main.h"

#include <stdio.h>

#include "stm32wrapper.h"

#include "crypto/include/bigint.h"
#include "crypto/include/crypto_scalarmult.h"
#include "crypto/include/ed25519.h"

#define MAX 1000 // N of measurements

const unsigned char priv_pub_key[64] = { // pubkey created with SHAKE256
  0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
  0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
  0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
  0x70, 0x3b, 0xac, 0x3, 0x1c, 0xae, 0x7f, 0x60,
  0xc, 0xdb, 0x1e, 0xd8, 0x64, 0x17, 0x7, 0x7e,
  0xae, 0xb7, 0x30, 0x37, 0x9c, 0xa3, 0x28, 0x6c,
  0x57, 0x9, 0xaa, 0xfe, 0xc4, 0x6, 0x86, 0xc7,
  0x31, 0xa1, 0x2d, 0x63, 0x49, 0x9e, 0xe0, 0xb5
};

const unsigned char msg[] = {
  0xab, 0x11, 0xcc, 0xdd, 0xee, 0xff, 0xee, 0xff, 0xee, 0xdd
};

void test_sign(void) {
  uint8_t correct_res [] = {
    0x4f, 0x30, 0x16, 0xa, 0xa7, 0x6c, 0xa6, 0xde,
    0xb6, 0x28, 0xe2, 0x95, 0x7, 0xfe, 0x23, 0x5d,
    0x64, 0xc8, 0x75, 0xc, 0xdc, 0x67, 0xb7, 0x9a,
    0x81, 0xe5, 0x26, 0x5d, 0x46, 0xc7, 0x4, 0x85,
    0x3, 0x44, 0xb9, 0x97, 0x29, 0x32, 0x3d, 0x8c,
    0x44, 0xc1, 0x96, 0x15, 0xed, 0x30, 0x2d, 0x72,
    0xd4, 0x7f, 0xcc, 0x75, 0x69, 0x95, 0xaa, 0xab,
    0x1a, 0x9f, 0xb6, 0xc, 0xf3, 0xec, 0x54, 0x1 };
  unsigned long long msg_len = sizeof(msg) / sizeof(msg[0]);
  unsigned char signed_msg[32+32];
  unsigned long long signed_msg_len = sizeof(signed_msg) / sizeof(signed_msg[0]);

  int i;
  volatile int correct = 0;
  correct |= sign(signed_msg, &signed_msg_len, msg, msg_len, priv_pub_key);
  // correct |= sign_ephemeral(signed_msg, &signed_msg_len, msg, msg_len, priv_pub_key);
  // correct |= sign_unprotected(signed_msg, &signed_msg_len, msg, msg_len, priv_pub_key);

  for (i = 0; i < 64; i++) {
    if (signed_msg[i] != correct_res[i]) {
      correct |= 1;
      break;
    }
  }
  if (correct == 0) {
    send_USART_str((unsigned char *)"Test signature generation: 0 (PASS)");
  } else {
    send_USART_str((unsigned char *)"Test signature generation: FAIL");
  }
  return;
}

void test_scalarmult(void) {
  uint8_t R[32];
  uint8_t r[] = { 0xfb, 0x1, 0xc, 0x1, 0xc2, 0xdd, 0x90, 0xc0,
                  0x7d, 0xc7, 0xf5, 0x42, 0xf4, 0x3, 0x8a, 0xda,
                  0x89, 0xee, 0x1e, 0xc4, 0xd7, 0x42, 0x93, 0xde,
                  0x4f, 0x43, 0xed, 0x6d, 0x57, 0xca, 0x1c, 0xf, };
  uint8_t correct_res[] = { 0x4f, 0x30, 0x16, 0xa, 0xa7, 0x6c, 0xa6, 0xde,
                            0xb6, 0x28, 0xe2, 0x95, 0x7, 0xfe, 0x23, 0x5d,
                            0x64, 0xc8, 0x75, 0xc, 0xdc, 0x67, 0xb7, 0x9a,
                            0x81, 0xe5, 0x26, 0x5d, 0x46, 0xc7, 0x4, 0x85, };

  int i;
  volatile int correct = 0;
  correct |= crypto_scalarmult_base_curve25519(R,  r);
  correct |= ephemeral_crypto_scalarmult_base_curve25519(R,  r);
  correct |= unprotected_crypto_scalarmult_base_curve25519(R,  r);

  for (i = 0; i < 32; i++) {
    if (R[i] != correct_res[i]) {
      correct |= 1;
      break;
    }
  }
  if (correct == 0) {
    send_USART_str((unsigned char *)"Test scalarmult: 0 (PASS)");
  } else {
    send_USART_str((unsigned char *)"Test scalarmult: FAIL");
  }
  return;
}

void cycles_sign_static(void) {
  char str[100];
  unsigned long long msg_len = sizeof(msg) / sizeof(msg[0]);
  unsigned char signed_msg[32+32];
  unsigned long long signed_msg_len = sizeof(signed_msg) / sizeof(signed_msg[0]);
  int i;
  unsigned int oldcount, newcount;
  unsigned long long totalcountNumber = 0;

  // Prepare variables for device registers for counting cycles
  SCS_DEMCR |= SCS_DEMCR_TRCENA;
  DWT_CYCCNT = 0;
  DWT_CTRL |= DWT_CTRL_CYCCNTENA;

  for (i = 0; i < MAX;) {
    oldcount = DWT_CYCCNT;
    sign(signed_msg, &signed_msg_len, msg, msg_len, priv_pub_key);
    newcount = DWT_CYCCNT;
    if (newcount < oldcount) {
      sprintf(str, "Clock Overflown");
      send_USART_str((unsigned char *)str);
    } else {
      totalcountNumber += ((long long)newcount - (long long)oldcount);
      i++;
    }
  }
  sprintf(str, "Static signature generation cost: %d", (unsigned)(totalcountNumber / MAX));
  send_USART_str((unsigned char *)str);
}

void cycles_sign_ephemeral(void) {
  char str[100];
  unsigned long long msg_len = sizeof(msg) / sizeof(msg[0]);
  unsigned char signed_msg[32+32];
  unsigned long long signed_msg_len = sizeof(signed_msg) / sizeof(signed_msg[0]);
  int i;
  unsigned int oldcount, newcount;
  unsigned long long totalcountNumber = 0;

  // Prepare variables for device registers for counting cycles
  SCS_DEMCR |= SCS_DEMCR_TRCENA;
  DWT_CYCCNT = 0;
  DWT_CTRL |= DWT_CTRL_CYCCNTENA;

  for (i = 0; i < MAX;) {
    oldcount = DWT_CYCCNT;
    sign_ephemeral(signed_msg, &signed_msg_len, msg, msg_len, priv_pub_key);
    newcount = DWT_CYCCNT;
    if (newcount < oldcount) {
      sprintf(str, "Clock Overflown");
      send_USART_str((unsigned char *)str);
    } else {
      totalcountNumber += ((long long)newcount - (long long)oldcount);
      i++;
    }
  }
  sprintf(str, "Ephemeral signature generation cost: %d", (unsigned)(totalcountNumber / MAX));
  send_USART_str((unsigned char *)str);
}

void cycles_sign_unprotected(void) {
  char str[100];
  unsigned long long msg_len = sizeof(msg) / sizeof(msg[0]);
  unsigned char signed_msg[32+32];
  unsigned long long signed_msg_len = sizeof(signed_msg) / sizeof(signed_msg[0]);
  int i;
  unsigned int oldcount, newcount;
  unsigned long long totalcountNumber = 0;

  // Prepare variables for device registers for counting cycles
  SCS_DEMCR |= SCS_DEMCR_TRCENA;
  DWT_CYCCNT = 0;
  DWT_CTRL |= DWT_CTRL_CYCCNTENA;

  for (i = 0; i < MAX;) {
    oldcount = DWT_CYCCNT;
    sign_unprotected(signed_msg, &signed_msg_len, msg, msg_len, priv_pub_key);
    newcount = DWT_CYCCNT;
    if (newcount < oldcount) {
      sprintf(str, "Clock Overflown");
      send_USART_str((unsigned char *)str);
    } else {
      totalcountNumber += ((long long)newcount - (long long)oldcount);
      i++;
    }
  }
  sprintf(str, "Unprotected signature generation cost: %d", (unsigned)(totalcountNumber / MAX));
  send_USART_str((unsigned char *)str);
}

const uint8_t scalar[] = {
  0xfb, 0x1, 0xc, 0x1, 0xc2, 0xdd, 0x90, 0xc0,
  0x7d, 0xc7, 0xf5, 0x42, 0xf4, 0x3, 0x8a, 0xda,
  0x89, 0xee, 0x1e, 0xc4, 0xd7, 0x42, 0x93, 0xde,
  0x4f, 0x43, 0xed, 0x6d, 0x57, 0xca, 0x1c, 0xf, };

void cycles_scalarmult_static(void) {
  char str[100];
  uint8_t result[32];
  int i;
  unsigned int oldcount, newcount;
  unsigned long long totalcountNumber = 0;

  // Prepare variables for device registers for counting cycles
  SCS_DEMCR |= SCS_DEMCR_TRCENA;
  DWT_CYCCNT = 0;
  DWT_CTRL |= DWT_CTRL_CYCCNTENA;

  for (i = 0; i < MAX;) {
    oldcount = DWT_CYCCNT;
    crypto_scalarmult_base_curve25519(result, scalar);
    newcount = DWT_CYCCNT;
    if (newcount < oldcount) {
      sprintf(str, "Clock Overflown");
      send_USART_str((unsigned char *)str);
    } else {
      totalcountNumber += ((long long)newcount - (long long)oldcount);
      i++;
    }
  }
  sprintf(str, "Static scalar multiplication cost: %d", (unsigned)(totalcountNumber / MAX));
  send_USART_str((unsigned char *)str);
}

void cycles_scalarmult_unprotected(void) {
  char str[100];
  uint8_t result[32];
  int i;
  unsigned int oldcount, newcount;
  unsigned long long totalcountNumber = 0;

  // Prepare variables for device registers for counting cycles
  SCS_DEMCR |= SCS_DEMCR_TRCENA;
  DWT_CYCCNT = 0;
  DWT_CTRL |= DWT_CTRL_CYCCNTENA;

  for (i = 0; i < MAX;) {
    oldcount = DWT_CYCCNT;
    unprotected_crypto_scalarmult_base_curve25519(result, scalar);
    newcount = DWT_CYCCNT;
    if (newcount < oldcount) {
      sprintf(str, "Clock Overflown");
      send_USART_str((unsigned char *)str);
    } else {
      totalcountNumber += ((long long)newcount - (long long)oldcount);
      i++;
    }
  }
  sprintf(str, "Unprotected scalar multiplication cost: %d", (unsigned)(totalcountNumber / MAX));
  send_USART_str((unsigned char *)str);
}

void cycles_scalarmult_ephemeral(void) {
  char str[100];
  uint8_t result[32];
  int i;
  unsigned int oldcount, newcount;
  unsigned long long totalcountNumber = 0;

  // Prepare variables for device registers for counting cycles
  SCS_DEMCR |= SCS_DEMCR_TRCENA;
  DWT_CYCCNT = 0;
  DWT_CTRL |= DWT_CTRL_CYCCNTENA;

  for (i = 0; i < MAX;) {
    oldcount = DWT_CYCCNT;
    ephemeral_crypto_scalarmult_base_curve25519(result, scalar);
    newcount = DWT_CYCCNT;
    if (newcount < oldcount) {
      sprintf(str, "Clock Overflown");
      send_USART_str((unsigned char *)str);
    } else {
      totalcountNumber += ((long long)newcount - (long long)oldcount);
      i++;
    }
  }
  sprintf(str, "Ephemeral scalar multiplication cost: %d", (unsigned)(totalcountNumber / MAX));
  send_USART_str((unsigned char *)str);
}

int main(void) {
  clock_setup();
  gpio_setup();
  usart_setup(115200);
  rng_enable();
  //char str[100];

  send_USART_str((unsigned char *)"Program started.");

  // test_sign();
  // test_scalarmult();
  // cycles_scalarmult_unprotected();
  // cycles_scalarmult_ephemeral();
  // cycles_scalarmult_static();
  // cycles_sign_unprotected();
  // cycles_sign_ephemeral();
  cycles_sign_static();

  send_USART_str((unsigned char *)"Done!");

  while (1)
    ;

  return 0;
}
