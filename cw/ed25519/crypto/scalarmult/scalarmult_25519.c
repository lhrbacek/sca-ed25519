// Majority of the code is adapted from Sca25519.
// https://github.com/sca-secure-library-sca25519/sca25519

#include <limits.h>

#ifdef WITH_PERFORMANCE_BENCHMARKING

#include <stdio.h>

#endif // #ifdef WITH_PERFORMANCE_BENCHMARKING

//#include "../../stm32wrapper.h"
#include "../include/crypto_scalarmult.h"
#include "../include/fe25519.h"
#include "../include/randombytes.h"
#include "../include/sc25519.h"

#define MULTIPLICATIVE_CSWAP
#define ITOH_COUNTERMEASURE // Address randomization in first ladder (static)
#define ITOH_COUNTERMEASURE64 // Address randomization in secondladder (static)
#define SCALAR_RANDOMIZATION

// For benchmarking
#ifdef COUNT_CYCLES_EXTRA_SM
unsigned long long globalcount;
#endif

// Internal state for scalar multiplication
typedef struct _ST_curve25519ladderstepWorkingState {
  // The base point in affine coordinates
  fe25519 x0;

  // The two working points p, q, in projective coordinates. Possibly
  // randomized.
  fe25519 xp;
  fe25519 zp;
  fe25519 xq;
  fe25519 zq;

  UN_256bitValue r; // for random value
  UN_256bitValue s; // scalar

  int nextScalarBitToProcess;
  uint8_t previousProcessedBit;

} ST_curve25519ladderstepWorkingState;

// Sca-Ed25519
// (2**255 - 19) - modular_sqrt(-486664, (2**255 - 19))
// == negative root of sqrt(-486664)
// For point conversion
const fe25519 scaling_factor = {{
  0xe7, 0x81, 0xba, 0x0, 0x55, 0xfb, 0x91, 0x33, 0x7d, 0xe5, 0x82,
  0xb4, 0x2e, 0x2c, 0x5e, 0x3a, 0x81, 0xb0, 0x3, 0xfc, 0x23, 0xf7,
  0x84, 0x2d, 0x44, 0xf9, 0x5f, 0x9f, 0xb, 0x12, 0xd9, 0x70, }};

// Sca-Ed25519
// d of Edwards25519, -(121665/121666)
// From https://github.com/floodyberry/supercop/blob/master/crypto_sign/ed25519/ref/ge25519.c#L12
// For Point decoding
static const fe25519 ed25519_d = {{
  0xA3, 0x78, 0x59, 0x13, 0xCA, 0x4D, 0xEB, 0x75, 0xAB, 0xD8, 0x41,
  0x41, 0x4D, 0x0A, 0x70, 0x00, 0x98, 0xE8, 0x79, 0x77, 0x79, 0x40,
  0xC7, 0x8C, 0x73, 0xFE, 0x6F, 0x2B, 0xEE, 0x6C, 0x03, 0x52, }};

// Sca-Ed25519
// sqrt(-1) in fe25519
// From https://github.com/floodyberry/supercop/blob/master/crypto_sign/ed25519/ref/ge25519.c#L18
// For Point decoding
static const fe25519 ed25519_sqrtm1 = {{
  0xB0, 0xA0, 0x0E, 0x4A, 0x27, 0x1B, 0xEE, 0xC4, 0x78, 0xE4, 0x2F,
  0xAD, 0x06, 0x18, 0x43, 0x2F, 0xA7, 0xD7, 0xFB, 0x3D, 0x99, 0x00,
  0x4D, 0x2B, 0x0B, 0xDF, 0xC1, 0x4F, 0x80, 0x24, 0x83, 0x2B, }};

// Sca-Ed25519
// Point conversion from Montgomery projective to Edwards Affine
// Described in Point Conversion Section.
// Input: EC Point in Montgomery projective (U:V:W)
// Output: Corresponding EC Point in Edwards affine (x,y)
void point_conversion_mp_ea(fe25519* x_ea, fe25519* y_ea ,const fe25519* U, const fe25519* V, const fe25519* W)
{
  fe25519 U_add_W, T, R, UR, U_sub_W, RV;

  fe25519_add(&U_add_W, U, W);              // U_add_W = U+W
  fe25519_mul(&T, V, &U_add_W);             // T = V*(U+W)
  fe25519_invert(&R, &T);                   // R = T^-1
  fe25519_mul(&UR, U, &R);                  // UR = U*R
  fe25519_mul(x_ea, &UR, &U_add_W);         // x_ea = U*R*(U+W) = U/V
  fe25519_mul(x_ea, x_ea, &scaling_factor); // x_ea = x_ea * (-sqrt(-486664))
  fe25519_reduceCompletely(x_ea);

  fe25519_sub(&U_sub_W, U, W);              // U_sub_W = U-W
  fe25519_mul(&RV, &R, V);                  // RV = R*V
  fe25519_mul(y_ea, &U_sub_W, &RV);         // y_ea = (U-W)*R*V = (U-W)/(U+W)
  fe25519_reduceCompletely(y_ea);
}

// Sca-Ed25519
// Point conversion from from Edwards Affine to Montgomery projective
// Future work, for signature verification
void point_conversion_ea_mp(fe25519* U, fe25519* V, fe25519* W,
                            const fe25519* x_ea, const fe25519* y_ea)
{
  // (u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)
  // (U:V:W) = (u, v, 1)

  fe25519 one_plus_y, one_minus_y, x_inv;

  fe25519_setone(&one_plus_y);
  fe25519_setone(&one_minus_y);

  fe25519_sub(&one_minus_y, &one_minus_y, y_ea); // 1-y
  fe25519_add(&one_plus_y, &one_plus_y, y_ea);   // 1+y
  fe25519_invert(&one_minus_y, &one_minus_y);    // (1-y)^-1
  fe25519_mul(U, &one_plus_y, &one_minus_y);     // U = (1+y) * (1-y)^-1

  fe25519_invert(&x_inv, x_ea);                  // x^-1
  fe25519_mul(V, U, &x_inv);                     // u * x^-1
  fe25519_mul(V, V, &scaling_factor);            // V = (-sqrt(-486664))*u*x^-1

  fe25519_reduceCompletely(U);
  fe25519_reduceCompletely(V);
  fe25519_setone(W);
}

// Sca-Ed25519
// Ed25519 Point decoding
// From RFC 8032 Python, converted and modified to C
// Follows reasoning of:
// https://words.filippo.io/dispatches/edwards25519-formulas/
// Future work, for signature verification
// Input: encoded Ed25519 point
int ed25519_decode(fe25519* x, fe25519* y, const uint8_t in[32])
{
  /*
    Edwards25519: -x^2 + y^2 = 1 + d * x^2 * y^2
    We need x:     x^2 = (y^2 - 1) / (d * y^2 + 1) ~ x^2 = num / den
                   x   = sqrt(num * den^1)
                   
    There are two candidate roots.
                   x1  = num * den^3 * (num^((p-5)/8) * den^((7p-35)/8))
                   x1  = num * den^3 * (num * den^7)^((p-5)/8)
                   x2  = x1 * 2^(p-1)/4
                   x2  = x1 * sqrt(-1)
  */

  fe25519 num, den, t1, t2, t3; // num = numerator, den = denominator, tX = tmps
  fe25519_setone(&t1);

  uint8_t par = in[31] >> 7; // [...10000000], get parity bit
  fe25519_unpack(y, in);

  fe25519_square(&t2, y);            // t2 = y^2
  fe25519_mul(&t3, &ed25519_d, &t2); // t3 = d*y^2
  fe25519_sub(&num, &t2, &t1);       // num = y^2-1 (numerator)
  fe25519_add(&den, &t3, &t1);       // den = d*y^2+1 (denominator)

  // Computation of t1 = (num * den^7)^((p-5)/8)
  fe25519_square(&t2, &den);   // t2 = den^2
  fe25519_square(&t1, &t2);    // t1 = den^4 = (den^2)^2
  fe25519_mul(&t3, &t1, &t2);  // t3 = den^6 = den^4 * den^2
  fe25519_mul(&t1, &t3, &num); // t1 = num * den^6
  fe25519_mul(&t1, &t1, &den); // t1 = num * den^7
  fe25519_pow2523(&t1, &t1);   // t1 = (num * den^7)^((p-5)/8)

  // Computation of x1 = t1 * num * den^3
  fe25519_mul(&t1, &t1, &num);
  fe25519_mul(&t1, &t1, &den);
  fe25519_mul(&t1, &t1, &den);
  fe25519_mul(x, &t1, &den); // x = num * den^3 * (num * den^7)^((p-5)/8)

  /* Check whether sqrt computation gave correct result,
     multiply by sqrt(-1) if not:
     x1   = sqrt(num * den^-1)
     x1^2 = num * den^-1
     den * x1^2 = num
   */

  fe25519_square(&t1, x); // t1 used for check
  fe25519_mul(&t1, &t1, &den);
  if (fe25519_iseq_vartime(&t1, &num) == 0) {
    fe25519_mul(x, x, &ed25519_sqrtm1); // x = x1 * sqrt(-1)
  }

  // Now we have one of the two square roots, except if input was not a square
  // TODO this should not be the same as above. Should compare -num, not num?
  fe25519_square(&t1, x);
  fe25519_mul(&t1, &t1, &den);
  if (fe25519_iseq_vartime(&t1, &num) == 0) {
    return 1;
  }
    
  // Choose the desired square root according to parity:
  // This is changed from the ref SUPERCOP implementation
  // We want to negate if the sign bit doesn't match
  // if(fe25519_getparity(x) != (1-par))
  if(fe25519_getparity(x) == (1-par)) {
    fe25519_neg(x, x);
  }

  fe25519_reduceCompletely(x);

  return 0;
}

// Sca-Ed25519
// Ed25519 Point encoding
void ed25519_encode(uint8_t out[32], const fe25519* x, const fe25519* y) {
  uint8_t ctr;

  for (ctr = 0; ctr < 32; ctr++) {
    out[ctr] = y->as_uint8_t[ctr];
  }

  uint8_t lsb_of_x = x->as_uint8_t[0] & 1;

  out[31] = (out[31] & 0x7F) | (lsb_of_x << 7);
}

// Definition for assembly implemented cswap without countermeasures
// Below follows various definitions of cswaps with ot without countermeasures
extern void curve25519_cswap_asm(ST_curve25519ladderstepWorkingState* state,
                                 uint32_t* b);

#define ROTATE16(a) \
  { a = (((uint32_t)a) >> 16) | (a << 16); }

#define HAS_ASM_cSwapAndRandomize_asm

#ifdef HAS_ASM_cSwapAndRandomize_asm
extern void cSwapAndRandomize_asm(uint32_t swapData, uint32_t* pFe1,
                                  uint32_t* pFe2, uint32_t randomVal);

// let the subsequent code call the assembly function instead of the C function.
#define cSwapAndRandomize cSwapAndRandomize_asm

#else  // #ifdef HAS_ASM_cSwapAndRandomize_asm

/// swapData is expected to contain the swap status bit in bit #0
/// and fresh random data in bits #1 to #31.
/// pFe1 and pFe2 contain the pointers to the input field elements.
///
/// conditionally swaps the field elements and replaces them
/// with a random multiple.
/// Reduces the result "on-the-fly".
///
static void cSwapAndRandomize(uint32_t swapData, uint32_t* pFe1, uint32_t* pFe2,
                              uint32_t randomVal) {
  // we will implement the conditional move half-word wise by
  // generating two values with the swapBit in bit #0 and random
  // data in the upper half-word.

  uint32_t mpyMask1;
  uint32_t mpyMask2;

  // clip the randomized multipliers to 31 bits, such that during
  // reduction the result value may not overflow.
  // also clear bit #15
  uint32_t randomize_mpy = randomVal;

  // Make sure that the randomization multipliers are nonzero.
  randomize_mpy |= 1;

  // generate the "swap-multipliers".
  {
    mpyMask2 = (randomize_mpy ^ swapData) & 0xffff0001;
    mpyMask1 = swapData & 0xffff0001;
  }

  // mpyMask1 and 2 contain in bit #0 the swap status and its complement.
  // bits #1 ... 15 are zero
  // bits #16 to 31 contain random data.

  randomize_mpy &= 0x7fff7fff;

  uint32_t in1, in2;

  // First handle word #7

  in1 = pFe1[7];
  in2 = pFe2[7];

  uint32_t outA, outB;

  // conditionally swap the lower 16 bits.
  // the content of the upper 16 bits will be undefined.
  outA = in1 * mpyMask2 + in2 * mpyMask1;
  outB = in1 * mpyMask1 + in2 * mpyMask2;

  // The least significant 16 bits now contain the swapped content of
  // the most significant half-word of the input field elements
  // The upper part contains random values.

  outA &= 0xffff;
  outB &= 0xffff;

  uint64_t scaledA, scaledB;
  ROTATE16(randomize_mpy);
  scaledA = ((uint64_t)randomize_mpy) * outA;
  ROTATE16(randomize_mpy);
  scaledB = ((uint64_t)randomize_mpy) * outB;

  ROTATE16(in1);
  ROTATE16(in2);

  // conditionally swap the lower 16 bits.
  // the content of the upper 16 bits will be undefined.
  outA = in1 * mpyMask2 + in2 * mpyMask1;
  outB = in1 * mpyMask1 + in2 * mpyMask2;

  outA <<= 16;
  outB <<= 16;

  ROTATE16(randomize_mpy);
  scaledA += ((uint64_t)randomize_mpy) * outA;
  ROTATE16(randomize_mpy);
  scaledB += ((uint64_t)randomize_mpy) * outB;

  pFe1[7] = ((uint32_t)scaledA) & 0x7fffffff;
  pFe2[7] = ((uint32_t)scaledB) & 0x7fffffff;

  // reduce the upper bits of the result.
  scaledA >>= 31;
  scaledB >>= 31;
  scaledA = 19 * ((uint64_t)((uint32_t)scaledA));
  scaledB = 19 * ((uint64_t)((uint32_t)scaledB));

  // now handle the remaining words.
  int i;
  for (i = 0; i < 7; i++) {
    in1 = pFe1[i];
    in2 = pFe2[i];

    // handle the lower 16 bits of the two input words i

    outA = in1 * mpyMask2 + in2 * mpyMask1;
    outB = in1 * mpyMask1 + in2 * mpyMask2;
    outA &= 0xffff;
    outB &= 0xffff;

    ROTATE16(randomize_mpy);
    scaledA += ((uint64_t)randomize_mpy) * outA;
    ROTATE16(randomize_mpy);
    scaledB += ((uint64_t)randomize_mpy) * outB;

    // handle the upper 16 bits of the two input words i

    // first move the lower bits to the upper half and vice-versa.
    ROTATE16(in1);
    ROTATE16(in2);

    outA = in1 * mpyMask2 + in2 * mpyMask1;
    outB = in1 * mpyMask1 + in2 * mpyMask2;

    outA <<= 16;
    outB <<= 16;

    ROTATE16(randomize_mpy);
    scaledA += ((uint64_t)randomize_mpy) * outA;
    ROTATE16(randomize_mpy);
    scaledB += ((uint64_t)randomize_mpy) * outB;

    // write back the results.
    pFe1[i] = (uint32_t)scaledA;
    pFe2[i] = (uint32_t)scaledB;

    scaledA >>= 32;
    scaledB >>= 32;
  }

  // deal with the last carries for word #7
  scaledA += pFe1[7];
  scaledB += pFe2[7];

  pFe1[7] = (uint32_t)scaledA;
  pFe2[7] = (uint32_t)scaledB;
}

#endif  // #ifdef HAS_ASM_cSwapAndRandomize_asm

#define ROTATER(a, cnt) \
  { a = (((uint32_t)a) >> cnt) | (a << (32 - cnt)); }

static void maskScalarBitsWithRandomAndCswap(
    ST_curve25519ladderstepWorkingState* pState, uint32_t wordWithConditionBit,
    uint32_t bitNumber) {
  uint32_t randomDataBuffer[2] = {0, 0};
  randombytes((uint8_t*)randomDataBuffer, sizeof(randomDataBuffer));
  //
  // first combine the scalar bit with a random value which has
  // the bit at the data position cleared
  uint32_t mask = randomDataBuffer[0] & (~(1 << bitNumber));
  wordWithConditionBit ^= mask;

  // Arrange for having the condition bit at bit #0 and random data elsewhere.
  ROTATER(wordWithConditionBit, bitNumber);

  cSwapAndRandomize(wordWithConditionBit, pState->xp.as_uint32_t,
                    pState->xq.as_uint32_t, randomDataBuffer[1]);
  cSwapAndRandomize(wordWithConditionBit, pState->zp.as_uint32_t,
                    pState->zq.as_uint32_t, randomDataBuffer[1]);
}

static void curve25519_ladderstep(ST_curve25519ladderstepWorkingState* pState);

void curve25519_ladderstep(ST_curve25519ladderstepWorkingState* pState) {
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

  fe25519* b1 = &pState->xp;
  fe25519* b2 = &pState->zp;
  fe25519* b3 = &pState->xq;
  fe25519* b4 = &pState->zq;

  fe25519* b5 = &t1;
  fe25519* b6 = &t2;

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

static const fe25519 CON486662 = {
    {0x06, 0x6d, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

// Left for future work, needed in ssignature verification
void curve25519_addPoint(point25519* R, const point25519* P,
                                const point25519* Q) {
  // x3 = (y2z1 - y1z2)^2 * z1z2*(x2z1 - x1z2) - (x2z1-x1z2)^3*(a*z1z2 + x1z2 +
  // x2z1) y3 = ((2*x1z2 + x2z1) + a*z1z2) * (y2z1 - y1z2) * (x1z2 - x1z2)^2 -
  // z1z2*(y2z1 - y1z2)^3 - y1z2*(x2z1 - x1z2)^3 z3 = z1z2*(x2z1 - x1z2)^3

  // 16M + 3S + 10A
  fe25519 y2z1, y1z2, z1z2, x2z1, x1z2;
  fe25519 y2z1my1z2, x2z1mx1z2, x1z2px2z1;
  fe25519 AA, BB, CC, DD;

  fe25519_mul(&y2z1, Q->y, P->z);
  fe25519_mul(&y1z2, P->y, Q->z);
  fe25519_mul(&z1z2, P->z, Q->z);
  fe25519_mul(&x2z1, Q->x, P->z);
  fe25519_mul(&x1z2, P->x, Q->z);

  fe25519_sub(&y2z1my1z2, &y2z1, &y1z2);
  fe25519_sub(&x2z1mx1z2, &x2z1, &x1z2);
  fe25519_add(&x1z2px2z1, &x1z2, &x2z1);

  fe25519_square(&AA, &y2z1my1z2);
  fe25519_mul(&AA, &AA, &x2z1mx1z2);
  fe25519_mul(&AA, &AA, &z1z2);

  fe25519_mul(&BB, &CON486662, &z1z2);
  fe25519_add(&CC, &x1z2px2z1, &x1z2);
  fe25519_add(&CC, &CC, &BB);

  fe25519_square(&DD, &x2z1mx1z2);
  fe25519_mul(&x2z1mx1z2, &DD, &x2z1mx1z2);
  fe25519_mul(&DD, &DD, &y2z1my1z2);
  fe25519_mul(&DD, &DD, &CC);

  fe25519_add(&BB, &BB, &x2z1);
  fe25519_add(&BB, &BB, &x1z2);
  fe25519_mul(&BB, &BB, &x2z1mx1z2);

  fe25519_sub(R->x, &AA, &BB);

  fe25519_square(&AA, &y2z1my1z2);
  fe25519_mul(&AA, &AA, &y2z1my1z2);
  fe25519_mul(&AA, &AA, &z1z2);
  fe25519_sub(R->y, &DD, &AA);
  fe25519_mul(&AA, &y1z2, &x2z1mx1z2);
  fe25519_sub(R->y, R->y, &AA);

  fe25519_mul(R->z, &z1z2, &x2z1mx1z2);
}

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

#if (defined(__clang__) || defined(__GNUC__)) && defined(CORTEX_M4)

#define INCREMENT_BY_NINE(stackVariable)               \
  {                                                    \
    uint32_t scratchReg = 0;                           \
    uint32_t ptrReg = (uint32_t)&stackVariable;        \
    asm volatile(                                      \
        "LDR %[sr], [%[pr]] \n\t"                      \
        "add %[sr], %[sr], #9 \n\t"                    \
        "STR %[sr], [%[pr]]"                           \
        : [ sr ] "+r"(scratchReg), [ pr ] "+r"(ptrReg) \
        :                                              \
        : "memory");                                   \
  }

#define INCREMENT_BY_163(stackVariable)                \
  {                                                    \
    uint32_t scratchReg = 0;                           \
    uint32_t ptrReg = (uint32_t)&stackVariable;        \
    asm volatile(                                      \
        "LDR %[sr], [%[pr]] \n\t"                      \
        "add %[sr], %[sr], #163 \n\t"                  \
        "STR %[sr], [%[pr]]"                           \
        : [ sr ] "+r"(scratchReg), [ pr ] "+r"(ptrReg) \
        :                                              \
        : "memory");                                   \
  }

#else

#define INCREMENT_BY_NINE(a) \
  { a += 9; }

#define INCREMENT_BY_163(a) \
  { a += 163; }

#endif

/// This function implements algorithm 3 from the paper 
/// "SoK: SCA-Secure ECC in software - mission impossible?"
/// (https://tches.iacr.org/index.php/TCHES/article/view/9962)
/// We updated this algorithm slightly (especially the order of steps) in: 
/// "An update to the sca25519 library: mitigation card-tearing-based side-channel attacks"
/// (PLACEHOLDER: https://eprint.iacr.org/2024/)
/// Sca-Ed25519: This function contains modifications for Sca-Ed25519 project
/// This is static, protected scalar multiplication
int crypto_scalarmult_curve25519(uint8_t* r,
                                 const uint8_t* s,
                                 const uint8_t* p) {

  ST_curve25519ladderstepWorkingState state;
  uint8_t i;
  volatile uint32_t retval = -1;
  volatile uint32_t fid_counter = 0;  // for fault injection detection

  // Initialize return value with random bits
  randombytes(r, 32);

  // Sca-Ed25519: scalar storage blinding update removed

  // Copy scalar into state
  for (i = 0; i < 32; i++) {
    state.s.as_uint8_t[i] = s[i];
    INCREMENT_BY_NINE(fid_counter);
  }

  // Copy the affine x-axis of the base point to the state.
  fe25519_unpack(&state.x0, p);

  // P(1:0), Q(9:1)
  fe25519_setone(&state.xq);
  fe25519_setzero(&state.zq);
  fe25519_cpy(&state.xp, &state.x0);
  fe25519_setone(&state.zp);

  INCREMENT_BY_NINE(fid_counter);

  fe25519 yp, y0;

  // Sca-Ed25519: Point blinding removed

  if (computeY_curve25519_affine(&yp, &state.x0) != 0) {
    goto fail;
  }
  fe25519_reduceCompletely(&yp);


  // Sca-Ed25519: Removed addition of the point with blinded point
  // Sca-Ed25519: Removed 3 point doublings for X25519

  // Randomize scalar multiplicatively
  UN_512bitValue randVal;
#ifdef SCALAR_RANDOMIZATION // Scalar randomization countermeasure
  fe25519 t, Rinv, randB;
  fe25519_setzero((fe25519*)&state.r);

  do { // Sample random number until it is not zero
    randombytes(state.r.as_uint8_t, 8);
  } while (!state.r.as_64_bitValue_t[0].as_uint64_t[0]);

  randombytes(randVal.as_uint8_t, 64); // Sample scalar for randomization
  fe25519_reduceTo256Bits(&randB, &randVal);

  sc25519_mul(&t, &state.r, &randB); // Blinding for inversion

  sc25519_inverse(&t, &t);
  
  sc25519_mul(&Rinv, &t, &randB); // Unblinding the inverse
  sc25519_mul(&state.s, &state.s, &Rinv); // Blinding (randomizing) the scalar

  #else
  fe25519_setone((fe25519*)&state.r);
#endif

  // Sca-Ed25519: Storage scalar blinding removed

  INCREMENT_BY_163(fid_counter);

  // Sca-Ed25519: Removed conversion of point from projective to affine
  // not needed in our case because we did not doubled the point

  // Reinitialize coordinates
  // Prepare the working points within the working state struct.
  randombytes(randVal.as_uint8_t, 64);
  fe25519_reduceTo256Bits(&state.zq, &randVal);
  // paranoia: guarantee that the value is not zero mod p25519
  fe25519_reduceCompletely(&state.zq);
  state.zq.as_uint8_t[31] |= 128;

  fe25519_mul(&state.xq, &state.zq, &state.x0);

  fe25519_setone(&state.xp);
  fe25519_setzero(&state.zp);

  // P(1, 0), Q(x0*rand ,rand)

  // Sca-Ed25519: Change number of bits to process due to removed doubling
  state.nextScalarBitToProcess = 254;

  // Preparation for cswaps
  // Prepare scalar xor previous bit. Always operate on
  // at least 16 scalar bits together.
  for (i = 7; i >= 1; i--) {
    uint32_t word = state.s.as_uint32_t[i];
    uint32_t previousWord = state.s.as_uint32_t[i - 1];
    uint32_t temp = (word << 1) ^ word;

    state.s.as_uint16_t[2 * i + 1] = temp >> 16;
    word = (word << 16) | (previousWord >> 16);

    word ^= (word << 1);
    state.s.as_uint16_t[2 * i] = word >> 16;
  }
  state.s.as_uint32_t[0] ^= state.s.as_uint32_t[0] << 1;

#ifdef ITOH_COUNTERMEASURE // Address randomization
  UN_256bitValue itoh;
  randombytes(itoh.as_uint8_t, 32);
  // Sca-Ed25519 change:
  // itoh should be 254, itohshift 254 but shifted
  // itoh.as_uint8_t[31] &= 63;
  itoh.as_uint8_t[31] &= 127; // 0111 1111

  UN_256bitValue itohShift;
  cpy_256bitvalue(&itohShift, &itoh);

  // ### alg. step 20, orig. 19 ###
  itohShift.as_uint32_t[7] <<= 1;
  for (i = 7; i >= 1; i--) {
    uint32_t overflow;
    overflow = ((itohShift.as_uint32_t[i - 1] & (1 << 31)) >> 31);
    itohShift.as_uint32_t[i] |= overflow;
    itohShift.as_uint32_t[i - 1] <<= 1;

    state.s.as_uint32_t[i] ^= itoh.as_uint32_t[i];
  }
  state.s.as_uint32_t[0] ^= itoh.as_uint32_t[0];
#endif

#ifdef MULTIPLICATIVE_CSWAP
#else
  state.s.as_uint32_t[7] <<= 2;    // 3;
#ifdef ITOH_COUNTERMEASURE
  itoh.as_uint32_t[7] <<= 2;       // 3;
  itohShift.as_uint32_t[7] <<= 1;  // 3;
#endif
#endif

  INCREMENT_BY_163(fid_counter);

#ifdef ITOH_COUNTERMEASURE
#ifdef MULTIPLICATIVE_CSWAP
  // Sca-Ed25519 change: a[252] -> a[253]
  maskScalarBitsWithRandomAndCswap(&state, itohShift.as_uint32_t[7], 31);
#else
  //curve25519_cswap_asm(&state, &itohShift.as_uint32_t[7]);
#endif
#endif

  while (state.nextScalarBitToProcess >= 0) { // Start of Montgomery ladder
    uint8_t limbNo = 0;
    uint8_t bitNo = 0;
#ifdef MULTIPLICATIVE_CSWAP
    {
      limbNo = (uint8_t)(state.nextScalarBitToProcess >> 5);
      bitNo = state.nextScalarBitToProcess & 0x1f;

      maskScalarBitsWithRandomAndCswap(&state, state.s.as_uint32_t[limbNo],
                                       bitNo);
    }
#else
    {
      limbNo = (uint8_t)(state.nextScalarBitToProcess >> 5);
#ifdef ITOH_COUNTERMEASURE
      uint32_t temp = state.s.as_uint32_t[limbNo] ^ itoh.as_uint32_t[limbNo];
      curve25519_cswap_asm(&state, &temp);
      state.s.as_uint32_t[limbNo] <<= 1;
      itoh.as_uint32_t[limbNo] <<= 1;
#else
      curve25519_cswap_asm(&state, &state.s.as_uint32_t[limbNo]);
#endif
    }
#endif
    if (state.nextScalarBitToProcess >= 1)
    {
      curve25519_ladderstep(&state);

      INCREMENT_BY_NINE(fid_counter);

#ifdef MULTIPLICATIVE_CSWAP
#ifdef ITOH_COUNTERMEASURE
      maskScalarBitsWithRandomAndCswap(&state, itohShift.as_uint32_t[limbNo],
                                       bitNo); // ### alg. step 27, orig. 26
#endif
#else
#ifdef ITOH_COUNTERMEASURE
      curve25519_cswap_asm(&state, &itohShift.as_uint32_t[limbNo]);
#endif
#endif
    }

    state.nextScalarBitToProcess--;
  }

  // ----------------------------------------------------------

#ifdef WITH_PERFORMANCE_BENCHMARKING

#ifdef COUNT_CYCLES_EXTRA_SM
  /*Start cycle count*/
  SCS_DEMCR |= SCS_DEMCR_TRCENA;
  DWT_CYCCNT = 0;
  DWT_CTRL |= DWT_CTRL_CYCCNTENA;
  unsigned int oldcount = DWT_CYCCNT;
#endif

#endif // #ifdef WITH_PERFORMANCE_BENCHMARKING

  // Compute Y projective of multiplied point for conversion
  computeY_curve25519_projective(&y0, &state.xp, &state.zp, &state.xq,
                                 &state.zq, &state.x0, &yp);

  // Short scalar multiplication to undo multiplicative scalar blinding
  // Optimize for stack usage.
  fe25519_invert_useProvidedScratchBuffers(&state.zp, &state.zp, &state.xq,
                                           &state.zq, &state.x0);
  fe25519_mul(&state.xp, &state.xp, &state.zp);
  fe25519_reduceCompletely(&state.xp);

  fe25519_mul(&y0, &y0, &state.zp);
  fe25519_cpy(&state.x0, &state.xp); // (x0, y0)_affine = (xp, y0, zp)_projective

  // Sca-Ed25519: Addition of variables
  // to save coordinates of the point in this moment
  fe25519 new_x_aff, new_y_aff;
  fe25519_cpy(&new_x_aff, &state.x0);
  fe25519_cpy(&new_y_aff, &y0);

  // The R' = [s*r^-1]B was done,
  // now the R = [r]R' needs to be done to achieve R = [s*r^-1*r]B ~ [s]B

  // Reinitialize coordinates
  // Prepare the working points within the working state struct.
  randombytes(randVal.as_uint8_t, 64);
  fe25519_reduceTo256Bits(&state.zq, &randVal);
  // paranoia: guarantee that the value is not zero mod p25519
  fe25519_reduceCompletely(&state.zq);
  state.zq.as_uint8_t[31] |= 128;
  fe25519_mul(&state.xq, &state.zq, &state.x0);

  fe25519_setone(&state.xp);
  fe25519_setzero(&state.zp);

  // P(1, 0), Q(x0*rand ,rand)

  state.nextScalarBitToProcess = 64;
#if 1
  // Prepare scalar xor previous bit
  for (i = 2; i >= 1; i--) {
    uint32_t tmp = state.r.as_uint32_t[i] << 1;
    tmp |= state.r.as_uint32_t[i - 1] >> 31;
    state.r.as_uint32_t[i] ^= tmp;
  }

  state.r.as_uint32_t[0] ^= state.r.as_uint32_t[0] << 1;
#else
  // Prepare scalar xor previous bit. Always operate on
  // at least 16 scalar bits together.
  for (i = 2; i >= 1; i--) {
    uint32_t word = state.r.as_uint32_t[i];
    uint32_t previousWord = state.r.as_uint32_t[i - 1];
    uint32_t temp = (word << 1) ^ word;

    state.r.as_uint16_t[2 * i + 1] = temp >> 16;
    word = (word << 16) | (previousWord >> 16);

    word ^= (word << 1);
    state.r.as_uint16_t[2 * i] = word >> 16;
  }
  state.r.as_uint32_t[0] ^= state.r.as_uint32_t[0] << 1;
#endif

#ifdef ITOH_COUNTERMEASURE64
  UN_256bitValue itoh64;
  fe25519_setzero((fe25519*)&itoh64);
  randombytes(itoh64.as_uint8_t, 12);
  itoh64.as_uint8_t[2] &= 1;

  UN_256bitValue itoh64Shift;
  cpy_256bitvalue(&itoh64Shift, &itoh64);

  itoh64Shift.as_uint32_t[2] <<= 1;
  for (i = 2; i >= 1; i--) {
    uint32_t overflow;
    overflow = ((itoh64Shift.as_uint32_t[i - 1] & (1 << 31)) >> 31);
    itoh64Shift.as_uint32_t[i] |= overflow;
    itoh64Shift.as_uint32_t[i - 1] <<= 1;

    state.r.as_uint32_t[i] ^= itoh64.as_uint32_t[i];
  }
  state.r.as_uint32_t[0] ^= itoh64.as_uint32_t[0];
#endif

#ifdef MULTIPLICATIVE_CSWAP
#else
  state.r.as_uint32_t[2] <<= 31;
#ifdef ITOH_COUNTERMEASURE64
  itoh64.as_uint32_t[2] <<= 31;
  itoh64Shift.as_uint32_t[2] <<= 30;
#endif
#endif

  INCREMENT_BY_163(fid_counter);

#ifdef ITOH_COUNTERMEASURE64
#ifdef MULTIPLICATIVE_CSWAP
  maskScalarBitsWithRandomAndCswap(&state, itoh64Shift.as_uint32_t[2], 1);
#else
  curve25519_cswap_asm(&state, &itoh64Shift.as_uint32_t[2]);
#endif
#endif

  while (state.nextScalarBitToProcess >= 0) // Start of second Montgomery ladder
  {
    uint8_t limbNo = 0;
    uint8_t bitNo = 0;

#ifdef MULTIPLICATIVE_CSWAP
    {
      limbNo = (uint8_t)(state.nextScalarBitToProcess >> 5);
      bitNo = state.nextScalarBitToProcess & 0x1f;

      maskScalarBitsWithRandomAndCswap(&state, state.r.as_uint32_t[limbNo],
                                       bitNo);
    }
#else
    {
      limbNo = (uint8_t)(state.nextScalarBitToProcess >> 5);
#ifdef ITOH_COUNTERMEASURE64
      uint32_t temp = state.r.as_uint32_t[limbNo] ^ itoh64.as_uint32_t[limbNo];
      curve25519_cswap_asm(&state, &temp);
      state.r.as_uint32_t[limbNo] <<= 1;
      itoh64.as_uint32_t[limbNo] <<= 1;
#else
      curve25519_cswap_asm(&state, &state.r.as_uint32_t[limbNo]);
#endif
    }
#endif

    if (state.nextScalarBitToProcess >= 1)
    {
      curve25519_ladderstep(&state);
      INCREMENT_BY_NINE(fid_counter);

#ifdef MULTIPLICATIVE_CSWAP
#ifdef ITOH_COUNTERMEASURE64
      maskScalarBitsWithRandomAndCswap(&state, itoh64Shift.as_uint32_t[limbNo],
                                       bitNo);
#endif
#else
#ifdef ITOH_COUNTERMEASURE64
      curve25519_cswap_asm(&state, &itoh64Shift.as_uint32_t[limbNo]);
#endif
#endif
    }
    state.nextScalarBitToProcess--;
  }

#ifdef WITH_PERFORMANCE_BENCHMARKING

  //Comment out cycle counts
#ifdef COUNT_CYCLES_EXTRA_SM
  unsigned int newcount = DWT_CYCCNT;
  globalcount += (newcount - oldcount);
#endif

#endif // #ifdef WITH_PERFORMANCE_BENCHMARKING

  // ----------------------------------------------------------

  // Sca-Ed25519 the scalar multiplication is done, now we need to compute
  // all we need for conversion into Edwards affine coordinates
  computeY_curve25519_projective(&y0, &state.xp, &state.zp, &state.xq,
                                 &state.zq, &new_x_aff, &new_y_aff);

  // Sca-Ed25519: Removed point blinding
  // Sca-Ed25519: Removed conversion to Montogmery affine coordinates

  INCREMENT_BY_163(fid_counter);

  // Sca-Ed25519: Conversion to Edwards affine
  fe25519 x_ea, y_ea;
  point_conversion_mp_ea(&x_ea, &y_ea, &state.xp, &y0 ,&state.zp);

  if (fid_counter != (4 * 163 + 351 * 9))
  {
  fail:
    retval = -1;
    randombytes(state.xp.as_uint8_t, 32);
  } else {
    retval = 0;
  }

  // Sca-Ed25519: Encoding converted point
  ed25519_encode(r, &x_ea, &y_ea);

  return retval;
}

const uint8_t g_basePointCurve25519[32] = {9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

// Static scalar multiplication with fixed base point
int crypto_scalarmult_base_curve25519(uint8_t* q,
                                      const uint8_t* n
) {
  return crypto_scalarmult_curve25519(q, n, g_basePointCurve25519);
}

/// This function implements algorithm 2 from the paper 
/// "SoK: SCA-Secure ECC in software - mission impossible?"
/// (https://tches.iacr.org/index.php/TCHES/article/view/9962)
///
/// Comments such as "### alg. step 1 ###" provide to the respective line number of
/// pseudo-code used in the paper.
/// Sca-Ed25519: This function contains modifications for Sca-Ed25519 project
/// This is ephemeral scalar multiplication
int ephemeral_crypto_scalarmult_curve25519(uint8_t *r, const uint8_t *s,
  const uint8_t *p) {
  ST_curve25519ladderstepWorkingState state;
  uint8_t i;
  volatile uint8_t retval = -1;
  volatile uint32_t fid_counter = 0; // ### alg. step 1 ###

  // Initialize return value with random bits ### alg. step 2 ###
  randombytes(r, 32);

  // Prepare the scalar within the working state buffer.
  for (i = 0; i < 32; i++) {
    state.s.as_uint8_t[i] = s[i];
  }

  // Copy the affine x-coordinate of the base point to the state.
  fe25519_unpack(&state.x0, p);

  // Sca-Ed25519: Change the point P<->Q, because this implementation counts
  // that the points are swapped in removed countermeasure

  // P(1, 0), Q(9, 1)
  fe25519_setone(&state.zq);
  fe25519_cpy(&state.xq, &state.x0);

  fe25519_setone(&state.xp);
  fe25519_setzero(&state.zp);

  // Sca-Ed25519: Added for computing coordinates of the point to use in
  // final conversion
  fe25519 yp, y0;
  if (computeY_curve25519_affine(&yp, &state.x0) != 0) {
    goto fail;
  }

  // Sca-Ed25519: Removed clamping of scalar
  // ### alg. step 5 ###
  INCREMENT_BY_163(fid_counter);

  // Sca-Ed25519: Removed doublings of point

  // ### alg. step 7 ###
  INCREMENT_BY_163(fid_counter);


  // Sca-Ed25519: Removed conversion back to affine, because we are already
  // in affine dou to removed doublings

  // Reinitialize coordinates
  // Prepare the working points within the working state struct.
  // ### alg. step 12 ###
  UN_512bitValue randVal;
  randombytes(randVal.as_uint8_t, 64);
  fe25519_reduceTo256Bits(&state.zq, &randVal);
  // paranoia: guarantee that the value is not zero mod p25519
  fe25519_reduceCompletely(&state.zq);
  state.zq.as_uint8_t[31] |= 128;

  fe25519_mul(&state.xq, &state.zq, &state.x0); // ### alg. step 12 ###

  // Sca-Ed25519: Change P to Q
  fe25519_setone(&state.xp); // ### alg. step 11 ###
  fe25519_setzero(&state.zp);

  // Sca-Ed25519: Change number of ladders due to no doublings
  state.nextScalarBitToProcess = 254;

  // Prepare scalar xor previous bit. Always operate on
  // at least 16 scalar bits together. ### alg. step 13 ###
  for (i = 7; i >= 1; i--) {
    uint32_t word = state.s.as_uint32_t[i];
    uint32_t previousWord = state.s.as_uint32_t[i - 1];
    uint32_t temp = (word << 1) ^ word;

    state.s.as_uint16_t[2 * i + 1] = temp >> 16;
    word = (word << 16) | (previousWord >> 16);

    word ^= (word << 1);
    state.s.as_uint16_t[2 * i] = word >> 16;
  }
  state.s.as_uint32_t[0] ^= state.s.as_uint32_t[0] << 1;

#ifdef MULTIPLICATIVE_CSWAP
#else
  state.s.as_uint32_t[7] <<= 4;
#endif

  INCREMENT_BY_163(fid_counter); // ### alg. step 14 ###

  while (state.nextScalarBitToProcess >= 0) // ### alg. step 15 ###
  {
#ifdef MULTIPLICATIVE_CSWAP
    {
      uint8_t limbNo = (uint8_t)(state.nextScalarBitToProcess >> 5);
      uint8_t bitNo = state.nextScalarBitToProcess & 0x1f;
      maskScalarBitsWithRandomAndCswap(&state, state.s.as_uint32_t[limbNo],
              bitNo); // ### alg. step 16 and 19 ###.
    }
#else
    {
      uint8_t limbNo = (uint8_t)(state.nextScalarBitToProcess >> 5);
      curve25519_cswap_asm(&state, &state.s.as_uint32_t[limbNo]);
    }
#endif
    if (state.nextScalarBitToProcess >= 1) {
      curve25519_ladderstep(&state); // ### alg. step 17 ###

      INCREMENT_BY_NINE(fid_counter);  // ### alg. step 18 ###
    }

    state.nextScalarBitToProcess--;
  }

  // Sca-Ed25519: Removed conversion back to Edwards affine

  // Sca-Ed25519: Compute Y projective for later conversion to Edwards affine
  computeY_curve25519_projective(&y0, &state.xp, &state.zp, &state.xq,
    &state.zq, &state.x0, &yp);

  INCREMENT_BY_163(fid_counter); // ### alg. step 21 ###

  // Sca-Ed25519: Conversion from Montgomery projective to Edwards affine
  fe25519 x_ea, y_ea;
  point_conversion_mp_ea(&x_ea, &y_ea, &state.xp, &y0 ,&state.zp);
  fe25519_reduceCompletely(&x_ea);
  fe25519_reduceCompletely(&y_ea);

  // ### alg. step 22 ###
  if (fid_counter != (163 * 4 + 254 * 9)) {
  fail:
    retval = -1;
    randombytes(state.xp.as_uint8_t, 32);  // ### alg. step 23 ###
  } else {
    retval = 0;
  }
  
  // Sca-Ed25519: Encode resulting point
  ed25519_encode(r, &x_ea, &y_ea);
  return retval;
}

// Ephemeral scalar multiplication with fixed base point
int ephemeral_crypto_scalarmult_base_curve25519(uint8_t *q, const uint8_t *n) {
  return ephemeral_crypto_scalarmult_curve25519(q, n, g_basePointCurve25519);
}

// Unprotected, for unprotected scalar multiplication.
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

/// Unprotected scalar multiplication from Sca25519
/// "SoK: SCA-Secure ECC in software - mission impossible?"
/// (https://tches.iacr.org/index.php/TCHES/article/view/9962)
/// Sca_Ed25519: Contains modification for Ed25519
int unprotected_crypto_scalarmult_curve25519(uint8_t *r, const uint8_t *s,
      const uint8_t *p) {
  ST_curve25519ladderstepWorkingState state;
  uint8_t i;

  // Prepare the scalar within the working state buffer.
  for (i = 0; i < 32; i++) {
    state.s.as_uint8_t[i] = s[i];
  }

  // Sca_Ed25519: Remove scaalr clamping as in X25519

  // Copy the affine x-axis of the base point to the state.
  fe25519_unpack(&state.x0, p);

  // Prepare the working points within the working state struct.
  // P(1,0), Q(9,1)
  fe25519_setone(&state.zq);
  fe25519_cpy(&state.xq, &state.x0);

  fe25519_setone(&state.xp);
  fe25519_setzero(&state.zp);

  // Sca_Ed25519: Added computation of Y projective of base point
  // to use later in conversion of point
  fe25519 yp, y0;
  if (computeY_curve25519_affine(&yp, &state.x0) != 0) {
    return 1;
  }

  state.nextScalarBitToProcess = 254;

  #ifdef DH_SWAP_BY_POINTERS
  // we need to initially assign the pointers correctly.
  state.pXp = &state.xp;
  state.pZp = &state.zp;
  state.pXq = &state.xq;
  state.pZq = &state.zq;
  #endif

  state.previousProcessedBit = 0;

  // Start of Montgomery ladder
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

  // Sca_Ed25519: Add computation of Y projective of new resulted point
  // for conversion
  computeY_curve25519_projective(&y0, &state.xp, &state.zp, &state.xq,
        &state.zq, &state.x0, &yp);

  // Sca_Ed25519: Remove conversion from Montogmery Projective
  // to Montgomery Affine


  // Sca_Ed25519: Add point conversion from Montgomery projective
  // to Edwards affine and add encoding of resulted point
  fe25519 x_ea, y_ea;
  point_conversion_mp_ea(&x_ea, &y_ea, &state.xp, &y0 ,&state.zp);

  ed25519_encode(r, &x_ea, &y_ea);

  return 0;
}

// Unprotected scalar multiplication with fixed base point
int unprotected_crypto_scalarmult_base_curve25519(uint8_t *q, const uint8_t *n) {
  return unprotected_crypto_scalarmult_curve25519(q, n, g_basePointCurve25519);
}

#ifdef WITH_PERFORMANCE_BENCHMARKING

void cycles_cswap(void);

void cycles_cswap() {
  SCS_DEMCR |= SCS_DEMCR_TRCENA;
  DWT_CYCCNT = 0;
  DWT_CTRL |= DWT_CTRL_CYCCNTENA;

  ST_curve25519ladderstepWorkingState state;
  uint32_t wordwithbit = 10;
  uint32_t bitnum = 10;

  int i;
  unsigned int oldcount = DWT_CYCCNT;
  for (i = 0; i < 1000; i++) {
    maskScalarBitsWithRandomAndCswap(&state, wordwithbit, bitnum);
  }
  unsigned int newcount = DWT_CYCCNT - oldcount;

  char str[100];
  sprintf(str, "Cost cswap: %d", newcount / 1000);
  send_USART_str((unsigned char*)str);
}

#endif // #ifdef WITH_PERFORMANCE_BENCHMARKING
