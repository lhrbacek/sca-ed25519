#include "main.h"

#include <stdio.h>

#include "stm32wrapper.h"
#include "crypto/include/fe25519.h"
#include "crypto/include/bigint.h"

int main(void) {
  clock_setup();
  gpio_setup();
  usart_setup(115200);
  rng_enable();

  send_USART_str((unsigned char *)"Program started.");

  fe25519 a1, a2, a3;
  fe25519 *x1 = &a1;
  fe25519 *x2 = &a2;
  fe25519 *x3 = &a3;

  send_USART_str((unsigned char *)"a and x initialized");

  fe25519_setone(x2);
  fe25519_setone(x3);
  fe25519_add(x1, x2, x3);

  send_USART_str((unsigned char *)"first addition done");

  char str[100];
  to_string_256bitvalue(str, x1);
  send_USART_str((unsigned char *)str);

  send_USART_str((unsigned char *)"lets init b and y");

  fe25519 b1;
  fe25519 b2 = {
    { 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 
                0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xaa }}; // L - 67

  fe25519 b3 = {
    { 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
      0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 
      0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xbb }}; // L - 50
  
  fe25519 *y1 = &b1;
  fe25519 *y2 = &b2;
  fe25519 *y3 = &b3;

  send_USART_str((unsigned char *)"b and y initialized");

  fe25519_add(y1, y2, y3);

  send_USART_str((unsigned char *)"second addition done");

  to_string_256bitvalue(str, y1);
  send_USART_str((unsigned char *)str);


  send_USART_str((unsigned char *)"Done!");

  while (1)
    ;

  return 0;
}
