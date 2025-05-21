#ifndef __TEST_H
#define __TEST_H

#include <stdint.h>

#include "crypto/include/sc25519.h"
#include "crypto/include/crypto_scalarmult.h"
//#include "crypto/include/fe25519.h"
//#include "crypto/include/randombytes.h"
#include "crypto/include/ed25519.h"

int test_scalarmult_unprotected(void);

int test_scalarmult(void);

int test_scalarmult_ephemeral(void);

int test_scalarmult_unprotected_var_in(uint8_t* R, const uint8_t* r);

int test_scalarmult_ephemeral_var_in(uint8_t* R, const uint8_t* r);

int test_scalarmult_var_in(uint8_t* R, const uint8_t* r);

int test_ed25519_sign_unprotected(void);

int test_ed25519_sign(void);

int test_ed25519_sign_ephemeral(void);

int test_ed25519_sign_unprotected_var_in(
    uint8_t *signed_msg, unsigned long long *signed_msg_len,
    uint8_t *priv_pub_key,
    uint8_t *msg, unsigned long long msg_len);

int test_ed25519_sign_var_in(
    uint8_t *signed_msg, unsigned long long *signed_msg_len,
    uint8_t *priv_pub_key,
    uint8_t *msg, unsigned long long msg_len);

int test_ed25519_sign_ephemeral_var_in(
    uint8_t *signed_msg, unsigned long long *signed_msg_len,
    uint8_t *priv_pub_key,
    uint8_t *msg, unsigned long long msg_len);

#endif
