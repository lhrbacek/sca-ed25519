#include "../include/crypto_scalarmult.h"
#include "../include/fe25519.h"
#include "../include/randombytes.h"
#include "../include/sc25519.h"
#include "../../stm32wrapper.h"

// Compile switch for configuring
// Use with care: Swapping pointers results in variable time execution if stack
// resides in external memory. Added here mainly for comparison with the results
// of the AuCPace paper.
//#define DH_SWAP_BY_POINTERS

typedef struct _ST_curve25519ladderstepWorkingState {
  // The base point in affine coordinates
  fe25519 x0;

  // The two working points p, q, in projective coordinates. Possibly
  // randomized.
  fe25519 xp;
  fe25519 zp;
  fe25519 xq;
  fe25519 zq;

  UN_256bitValue r;
  UN_256bitValue s;

  int nextScalarBitToProcess;
  uint8_t previousProcessedBit;

#ifdef DH_SWAP_BY_POINTERS
  fe25519 *pXp;
  fe25519 *pZp;
  fe25519 *pXq;
  fe25519 *pZq;
#endif

} ST_curve25519ladderstepWorkingState;

// LH
static const fe25519 CON486662 = {
    {0x06, 0x6d, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

// LH
static int computeY_curve25519_affine(fe25519* y, const fe25519* x) {
  // y^2 = x^3 + 486662x^2 + x
  fe25519 tmp, x2;

  // x^3
  fe25519_square(&x2, x);
  fe25519_mul(&tmp, &x2, x);
  // 486662x^2
  fe25519_mul(&x2, &x2, &CON486662);

  fe25519_add(&tmp, &tmp, &x2);
  fe25519_add(&tmp, &tmp, x);

  return fe25519_squareroot(y, &tmp);
}

// LH
// Montgomery y-recovery Algorithm 5 in Montgomery Curves and their arithmetic
static void computeY_curve25519_projective(
    fe25519* y1, fe25519* x1, fe25519* z1,  // (x1,z1) = k*P
    const fe25519* x2, const fe25519* z2,   // (x2,z2)= (k+1)*P
    const fe25519* x, const fe25519* y      // (x,y) = P, z=1
) {
  fe25519 v1, v2, v3, v4;

  fe25519_mul(&v1, x, z1);
  fe25519_add(&v2, x1, &v1);
  fe25519_sub(&v3, x1, &v1);
  fe25519_square(&v3, &v3);
  fe25519_mul(&v3, &v3, x2);

  fe25519_add(&v1, &CON486662, &CON486662);
  fe25519_mul(&v1, &v1, z1);
  fe25519_add(&v2, &v2, &v1);
  fe25519_mul(&v4, x, x1);
  fe25519_add(&v4, &v4, z1);
  fe25519_mul(&v2, &v2, &v4);

  fe25519_mul(&v1, &v1, z1);
  fe25519_sub(&v2, &v2, &v1);
  fe25519_mul(&v2, &v2, z2);
  fe25519_sub(y1, &v2, &v3);
  fe25519_add(&v1, y, y);

  fe25519_mul(&v1, &v1, z1);
  fe25519_mul(&v1, &v1, z2);
  fe25519_mul(x1, &v1, x1);
  fe25519_mul(z1, &v1, z1);
}

const fe25519 scaling_factor_pos = {{
  0x24, 0x4b, 0x67, 0x20, 0x6a, 0x3e, 0x5b, 0xa9, 0xf8, 0x61, 0x81,
  0x9b, 0x67, 0x5, 0x17, 0x1, 0x28, 0x31, 0x38, 0xf9, 0xf2, 0x43,
  0xd5, 0xa1, 0x40, 0xb4, 0x4, 0xaf, 0xdb, 0x42, 0x68, 0xe9, }};

const fe25519 scaling_factor_neg = {{ 
  0x5b, 0xb4, 0x98, 0xdf, 0x95, 0xc1, 0xa4, 0x56, 0x7, 0x9e, 0x7e, 
  0x64, 0x98, 0xfa, 0xe8, 0xfe, 0xd7, 0xce, 0xc7, 0x6, 0xd, 0xbc, 
  0x2a, 0x5e, 0xbf, 0x4b, 0xfb, 0x50, 0x24, 0xbd, 0x97, 0x4, }};

const fe25519 scaling_factor_pos_new = {{
  0xe9, 0x68, 0x42, 0xdb, 0xaf, 0x4, 0xb4, 0x40, 0xa1, 0xd5, 0x43, 
  0xf2, 0xf9, 0x38, 0x31, 0x28, 0x1, 0x17, 0x5, 0x67, 0x9b, 0x81, 
  0x61, 0xf8, 0xa9, 0x5b, 0x3e, 0x6a, 0x20, 0x67, 0x4b, 0x24, }
};

const fe25519 scaling_factor_neg_new = {{
  0x4, 0x97, 0xbd, 0x24, 0x50, 0xfb, 0x4b, 0xbf, 0x5e, 0x2a, 0xbc, 
  0xd, 0x6, 0xc7, 0xce, 0xd7, 0xfe, 0xe8, 0xfa, 0x98, 0x64, 0x7e, 
  0x9e, 0x7, 0x56, 0xa4, 0xc1, 0x95, 0xdf, 0x98, 0xb4, 0x5b, }};

static void point_conversion_mp_ea(fe25519* x_ea, fe25519* y_ea ,const fe25519* U, const fe25519* V, const fe25519* W)
{
    // Vs = (V * Ed25519.scaling_factor_pos)
    // U_plus_W = (U + W)
    // # Montgomery trick
    // T = (Vs * U_plus_W)
    // R = pow(T, Ed25519.p - 2, Ed25519.p) # T^-1

    // x = (U * R * U_plus_W) % Ed25519.p # U / Vs = U * R*(U+W)
    // y = ((U - W) * R * Vs) % Ed25519.p # (U-W) / (U+W) = (U-W) * R*Vs

    // return x, y

    // TODO remove unnecessary reduction

    char str[100];

    fe25519 s, Vs, U_add_W, T, R, UR, U_sub_W, RVs;

    fe25519_cpy(&s, &scaling_factor_pos_new);
    fe25519_reduceCompletely(&s);

    // to_string_256bitvalue(str, &s);
    // send_USART_str((unsigned char *)"scaling_factor:");
    // send_USART_str((unsigned char *)str);

    fe25519_mul(&Vs, V, &s); // Vs = V*scaling_factor
    fe25519_reduceCompletely(&Vs);

    fe25519_add(&U_add_W, U, W);              // U_add_W = U+W
    fe25519_reduceCompletely(&U_add_W);

    fe25519_mul(&T, &Vs, &U_add_W);           // T = Vs*(U+W)
    fe25519_reduceCompletely(&T);

    fe25519_invert(&R, &T);                   // R = T^-1
    fe25519_reduceCompletely(&R);

    fe25519_mul(&UR, U, &R);                  // UR = U*R
    fe25519_reduceCompletely(&UR);
    fe25519_mul(x_ea, &UR, &U_add_W);         // x_ea = U*R*(U+W) = U/Vs
    fe25519_reduceCompletely(x_ea);

    fe25519_sub(&U_sub_W, U, W);              // U_sub_W = U-W
    fe25519_mul(&RVs, &R, &Vs);               // RVs = R*Vs
    fe25519_mul(y_ea, &U_sub_W, &RVs);        // y_ea = (U-W)*R*Vs = (U-W)/(U+W)
    fe25519_reduceCompletely(y_ea);
}

static void ed25519_encode(uint8_t out[32], const fe25519* x, const fe25519* y) {
  uint8_t ctr;

  for (ctr = 0; ctr < 32; ctr++) {
    out[ctr] = y->as_uint8_t[ctr];
  }

  uint8_t lsb_of_x = x->as_uint8_t[0] & 1;

  out[31] = (out[31] & 0x7F) | (lsb_of_x << 7);
}

// Original static_key
/*const UN_256bitValue static_key = {{0x80, 0x65, 0x74, 0xba, 0x61, 0x62, 0xcd,
   0x58, 0x49, 0x30, 0x59, 0x47, 0x36, 0x16, 0x35, 0xb6, 0xe7, 0x7d, 0x7c, 0x7a,
   0x83, 0xde, 0x38, 0xc0, 0x80, 0x74, 0xb8, 0xc9, 0x8f, 0xd4, 0x0a, 0x43}};*/

inline void curve25519_ladderstep(ST_curve25519ladderstepWorkingState *pState)
    __attribute__((always_inline));

inline void curve25519_ladderstep(ST_curve25519ladderstepWorkingState *pState) {
  // Implements the "ladd-1987-m-3" differential-addition-and-doubling formulas
  // Source: 1987 Montgomery "Speeding the Pollard and elliptic curve methods of
  // factorization", page 261,
  //         fifth and sixth displays, plus common-subexpression elimination.
  //
  // Notation from the explicit formulas database:
  // (X2,Z2) corresponds to (xp,zp),
  // (X3,Z3) corresponds to (xq,zq)
  // Result (X4,Z4) (X5,Z5) expected in (xp,zp) and (xq,zq)
  //
  // A = X2+Z2; AA = A^2; B = X2-Z2; BB = B^2; E = AA-BB; C = X3+Z3; D = X3-Z3;
  // DA = D*A; CB = C*B; t0 = DA+CB; t1 = t0^2; X5 = Z1*t1; t2 = DA-CB;
  // t3 = t2^2; Z5 = X1*t3; X4 = AA*BB; t4 = a24*E; t5 = BB+t4; Z4 = E*t5 ;
  //
  // Re-Ordered for using less temporaries.

  fe25519 t1, t2;

#ifdef DH_SWAP_BY_POINTERS
  fe25519 *b1 = pState->pXp;
  fe25519 *b2 = pState->pZp;
  fe25519 *b3 = pState->pXq;
  fe25519 *b4 = pState->pZq;
#else
  fe25519 *b1 = &pState->xp;
  fe25519 *b2 = &pState->zp;
  fe25519 *b3 = &pState->xq;
  fe25519 *b4 = &pState->zq;
#endif

  fe25519 *b5 = &t1;
  fe25519 *b6 = &t2;

  fe25519_add(b5, b1, b2);           // A = X2+Z2
  fe25519_sub(b6, b1, b2);           // B = X2-Z2
  fe25519_reduceCompletely(b6);      // LH: this reduction is needed because BB=B^2 affects X4=AA*BB
  fe25519_add(b1, b3, b4);           // C = X3+Z3
  fe25519_sub(b2, b3, b4);           // D = X3-Z3
  fe25519_mul(b3, b2, b5);           // DA= D*A
  fe25519_mul(b2, b1, b6);           // CB= C*B
  fe25519_add(b1, b2, b3);           // T0= DA+CB
  fe25519_sub(b4, b3, b2);           // T2= DA-CB
  fe25519_square(b3, b1);            // X5==T1= T0^2
  fe25519_square(b1, b4);            // T3= t2^2
  fe25519_mul(b4, b1, &pState->x0);  // Z5=X1*t3
  fe25519_square(b1, b5);            // AA=A^2
  fe25519_square(b5, b6);            // BB=B^2
  fe25519_sub(b2, b1, b5);           // E=AA-BB
  fe25519_reduceCompletely(b2);      // LH: this reduction is needed because Z4=E*t5, reduction at B=X2-Z2 is not enough, some results are still different.
  fe25519_mul(b1, b5, b1);           // X4= AA*BB
#ifdef CRYPTO_HAS_ASM_COMBINED_MPY121666ADD_FE25519
  fe25519_mpy121666add(b6, b5, b2);
#else
  fe25519_mpyWith121666(b6, b2);  // T4 = a24*E
  fe25519_add(b6, b6, b5);        // T5 = BB + t4
#endif
  fe25519_mul(b2, b6, b2);  // Z4 = E*t5
}

static void curve25519_cswap(ST_curve25519ladderstepWorkingState *state,
                             uint8_t b) {
#ifdef DH_SWAP_BY_POINTERS
  swapPointersConditionally((void **)&state->pXp, (void **)&state->pXq, b);
  swapPointersConditionally((void **)&state->pZp, (void **)&state->pZq, b);
#else
  fe25519_cswap(&state->xp, &state->xq, b);
  fe25519_cswap(&state->zp, &state->zq, b);
#endif
}

int crypto_scalarmult_curve25519(uint8_t *r, const uint8_t *s,
                                 const uint8_t *p) {
  ST_curve25519ladderstepWorkingState state;
  uint8_t i;

  // Prepare the scalar within the working state buffer.
  for (i = 0; i < 32; i++) {
    state.s.as_uint8_t[i] = s[i];
  }

  // LH: commented below because it is for ECDH
  //state.s.as_uint8_t[0] &= 248;
  //state.s.as_uint8_t[31] &= 127;
  //state.s.as_uint8_t[31] |= 64;

  // Copy the affine x-axis of the base point to the state.
  fe25519_unpack(&state.x0, p);

  // Prepare the working points within the working state struct.
  fe25519_setone(&state.zq);
  fe25519_cpy(&state.xq, &state.x0);

  fe25519_setone(&state.xp);
  fe25519_setzero(&state.zp);

  // LH add
  fe25519 yp, y0;
  if (computeY_curve25519_affine(&yp, &state.x0) != 0) {
    return 1;
  } // ### alg. step 3 ###

  //state.nextScalarBitToProcess = 254; LH, 255 in ed25519
  state.nextScalarBitToProcess = 254;

#ifdef DH_SWAP_BY_POINTERS
  // we need to initially assign the pointers correctly.
  state.pXp = &state.xp;
  state.pZp = &state.zp;
  state.pXq = &state.xq;
  state.pZq = &state.zq;
#endif

  state.previousProcessedBit = 0;

  // Process all the bits except for the last three where we explicitly double
  // the result.
  while (state.nextScalarBitToProcess >= 0) {
    uint8_t byteNo = (uint8_t)(state.nextScalarBitToProcess >> 3);
    uint8_t bitNo = (uint8_t)(state.nextScalarBitToProcess & 7);
    uint8_t bit;
    uint8_t swap;

    bit = 1 & (state.s.as_uint8_t[byteNo] >> bitNo);
    swap = bit ^ state.previousProcessedBit;
    state.previousProcessedBit = bit;
    curve25519_cswap(&state, swap);
    curve25519_ladderstep(&state);
    state.nextScalarBitToProcess--;
  }

  curve25519_cswap(&state, state.previousProcessedBit);

  // LH
  computeY_curve25519_projective(&y0, &state.xp, &state.zp, &state.xq,
                                 &state.zq, &state.x0, &yp);

  // LH
  //fe25519 zp_inv;
  //fe25519_invert(&zp_inv, &state.zp);
  //fe25519_mul(&state.xp, &state.xp, &zp_inv);
  //fe25519_reduceCompletely(&state.xp);
  //fe25519_pack(r, &state.xp);

  char str[100];

  // LH
  fe25519 x_ea, y_ea;
  point_conversion_mp_ea(&x_ea, &y_ea, &state.xp, &y0 ,&state.zp);
  fe25519_reduceCompletely(&x_ea);
  fe25519_reduceCompletely(&y_ea);

  // to_string_256bitvalue(str, &x_ea);
  // send_USART_str((unsigned char *)"x_ea:");
  // send_USART_str((unsigned char *)str);
  // to_string_256bitvalue(str, &y_ea);
  // send_USART_str((unsigned char *)"y_ea:");
  // send_USART_str((unsigned char *)str);

  ed25519_encode(r, &x_ea, &y_ea);

  return 0;
}

const uint8_t g_basePointCurve25519[32] = {9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

int crypto_scalarmult_base_curve25519(uint8_t *q, const uint8_t *n) {
  return crypto_scalarmult_curve25519(q, n, g_basePointCurve25519);
}
