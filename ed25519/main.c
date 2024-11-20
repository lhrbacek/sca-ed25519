#include "main.h"

#include <stdio.h>
#include <string.h>

#include "stm32wrapper.h"
#include "crypto/include/fe25519.h"
#include "crypto/include/bigint.h"
#include "crypto/include/sc25519.h"
#include "crypto/include/crypto_scalarmult.h"

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

  UN_512bitValue r = { // test vector
  { 0xb6, 0xb1, 0x9c, 0xd8, 0xe0, 0x42, 0x6f, 0x59, 0x83, 0xfa, 0x11,
    0x2d, 0x89, 0xa1, 0x43, 0xaa, 0x97, 0xda, 0xb8, 0xbc, 0x5d, 0xeb,
    0x8d, 0x5b, 0x62, 0x53, 0xc9, 0x28, 0xb6, 0x52, 0x72, 0xf4, 0x04,
    0x40, 0x98, 0xc2, 0xa9, 0x90, 0x03, 0x9c, 0xde, 0x5b, 0x6a, 0x48,
    0x18, 0xdf, 0x0b, 0xfb, 0x6e, 0x40, 0xdc, 0x5d, 0xee, 0x54, 0x24,
    0x80, 0x32, 0x96, 0x23, 0x23, 0xe7, 0x01, 0x35, 0x2d }};

  sc25519_reduce(&r);

  UN_256bitValue r_mod_l = { 0 };
  memcpy(r_mod_l.as_uint8_t, r.as_uint8_t, 32);

  to_string_256bitvalue(str, &r_mod_l);
  send_USART_str((unsigned char *)"r_mod_l:");
  send_USART_str((unsigned char *)str);

  UN_256bitValue rG = { 0 };
  crypto_scalarmult_base_curve25519(rG.as_uint8_t, r_mod_l.as_uint8_t);

  to_string_256bitvalue(str, &rG);
  send_USART_str((unsigned char *)"rG:");
  send_USART_str((unsigned char *)str);




  while (1)
    ;

  return 0;
}
