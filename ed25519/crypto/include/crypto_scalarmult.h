#ifndef CRYPTO_SCALARMULT_H
#define CRYPTO_SCALARMULT_H

#include <stdint.h>

#include "bigint.h"
#include "fe25519.h"

#define crypto_scalarmult crypto_scalarmult_curve25519
#define crypto_scalarmult_base crypto_scalarmult_base_curve25519

#define crypto_scalarmult_BYTES 32
#define crypto_scalarmult_SCALARBYTES 32

//#define COUNT_CYCLES_EXTRA_SM
#ifdef COUNT_CYCLES_EXTRA_SM
extern unsigned long long globalcount;
#endif

/*  This a haeder for scalarmult_25519.c, this is spearate from ephemeral and
   unprotected cases, because the scalar and secret state data need to be loaded
   once before usage. Therefore scalar multiplication does not take the scalar
   as parameter from the user. */

typedef struct {
    fe25519* x;
    fe25519* y;
    fe25519* z;
} point25519;

typedef struct STProtectedStaticKey_curve25519_ {
  uint64_t r;        // Randomization value
  UN_256bitValue k;  // scalar (s * (1/r)) mod sc25519

  // blinding points
  UN_256bitValue Rx;
  UN_256bitValue Ry;
  UN_256bitValue Rz;

  UN_256bitValue Sx;
  UN_256bitValue Sy;
  UN_256bitValue Sz;
} STProtectedStaticKey_curve25519;

// Converted unprotected key to protected static key
int crypto_protectedKeyFromUnprotectedKey_scalarmult_curve25519(
    STProtectedStaticKey_curve25519* k, const uint8_t* s);

void crypto_updateProtectedKey_scalarmult_curve25519(
    STProtectedStaticKey_curve25519* p);

// Protected static scalar multiplication
int crypto_static_scalarmult_curve25519(
    uint8_t* r, const STProtectedStaticKey_curve25519* s, const uint8_t* p);

// Protected static scalar multiplication
int crypto_scalarmult_curve25519(uint8_t* r,
                                 const uint8_t* s,
                                 const uint8_t* p);

// Ephemeral scalar multiplication
int ephemeral_crypto_scalarmult_curve25519(uint8_t* r,
    const uint8_t* s,
    const uint8_t* p);


// Unprotected scalar multiplication
int unprotected_crypto_scalarmult_curve25519(uint8_t* r,
    const uint8_t* s,
    const uint8_t* p);

void update_static_key_curve25519(void);

int crypto_scalarmult_base_curve25519(uint8_t* q,
                                      const uint8_t* n
);

int ephemeral_crypto_scalarmult_base_curve25519(uint8_t* q,
    const uint8_t* n
);


int unprotected_crypto_scalarmult_base_curve25519(uint8_t* q,
    const uint8_t* n
);

void set_static_key_curve25519(const uint8_t* uRx, const uint8_t* uRy,
                               const uint8_t* uRz, const uint8_t* uSx,
                               const uint8_t* uSy, const uint8_t* uSz,
                               const uint8_t* ustatic_key,
                               const uint8_t* ublindingFactor);

extern const uint8_t g_basePointCurve25519[32];

void curve25519_addPoint(point25519* R, const point25519* P,
    const point25519* Q);

void point_conversion_ea_mp(fe25519* U, fe25519* V, fe25519* W,
                            const fe25519* x_ea, const fe25519* y_ea);

void point_conversion_mp_ea(fe25519* x_ea, fe25519* y_ea ,const fe25519* U, const fe25519* V, const fe25519* W);

int ed25519_decode(fe25519* x, fe25519* y, const uint8_t in[32]);

void ed25519_encode(uint8_t out[32], const fe25519* x, const fe25519* y);

void sc_muladd(uint8_t *s, const uint8_t *a, const uint8_t *b,
    const uint8_t *c);

#endif
