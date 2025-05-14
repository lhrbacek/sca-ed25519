#include <limits.h>

#ifdef WITH_PERFORMANCE_BENCHMARKING

#include <stdio.h>

#endif // #ifdef WITH_PERFORMANCE_BENCHMARKING

#include "../../stm32wrapper.h"
#include "../include/crypto_scalarmult.h"
#include "../include/fe25519.h"
#include "../include/randombytes.h"
#include "../include/sc25519.h"
#include "../include/secure_storage.h"
#include "../include/ed25519.h"

#define MULTIPLICATIVE_CSWAP
#define ITOH_COUNTERMEASURE
#define ITOH_COUNTERMEASURE64

// TODO remove
// is the key updatable with respect to randomization - by default no
// static uint8_t updatable = 1;
// static uint8_t fixed = 0;
//#define UPDATABLE_STATIC_SCALAR
#define SCALAR_RANDOMIZATION

// TODO what is this
#ifdef COUNT_CYCLES_EXTRA_SM
unsigned long long globalcount;
#endif

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

} ST_curve25519ladderstepWorkingState;

// (2**255 - 19) - modular_sqrt(-486664, (2**255 - 19)) TODO
const fe25519 scaling_factor = {{
  0xe7, 0x81, 0xba, 0x0, 0x55, 0xfb, 0x91, 0x33, 0x7d, 0xe5, 0x82,
  0xb4, 0x2e, 0x2c, 0x5e, 0x3a, 0x81, 0xb0, 0x3, 0xfc, 0x23, 0xf7,
  0x84, 0x2d, 0x44, 0xf9, 0x5f, 0x9f, 0xb, 0x12, 0xd9, 0x70, }};

// TODO clean
void point_conversion_mp_ea(fe25519* x_ea, fe25519* y_ea ,const fe25519* U, const fe25519* V, const fe25519* W)
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

  //fe25519_cpy(&s, &scaling_factor_pos_new);
  //fe25519_reduceCompletely(&s);

  // to_string_256bitvalue(str, &s);
  // send_USART_str((unsigned char *)"scaling_factor:");
  // send_USART_str((unsigned char *)str);

  fe25519_mul(&Vs, V, &s); // Vs = V*scaling_factor
  //fe25519_reduceCompletely(&Vs);

  fe25519_add(&U_add_W, U, W);              // U_add_W = U+W
  //fe25519_reduceCompletely(&U_add_W);

  fe25519_mul(&T, V, &U_add_W);           // T = Vs*(U+W)
  //fe25519_reduceCompletely(&T);

  fe25519_invert(&R, &T);                   // R = T^-1
  //fe25519_reduceCompletely(&R);

  fe25519_mul(&UR, U, &R);                  // UR = U*R
  //fe25519_reduceCompletely(&UR);
  fe25519_mul(x_ea, &UR, &U_add_W);         // x_ea = U*R*(U+W) = U/Vs
  fe25519_mul(x_ea, x_ea, &scaling_factor); // TODO write it correctly in comments
  fe25519_reduceCompletely(x_ea);

  fe25519_sub(&U_sub_W, U, W);              // U_sub_W = U-W
  fe25519_mul(&RVs, &R, V);               // RVs = R*Vs
  fe25519_mul(y_ea, &U_sub_W, &RVs);        // y_ea = (U-W)*R*Vs = (U-W)/(U+W)
  fe25519_reduceCompletely(y_ea);
}

// TODO clean
// by LH from birational equivalency equation
void point_conversion_ea_mp(fe25519* U, fe25519* V, fe25519* W,
                            const fe25519* x_ea, const fe25519* y_ea)
{
  // def point_conversion_ea_ma(P: ECC.EccPoint):
  //   mu = ((1 + int(P.y)) * pow(1 - int(P.y), Ed25519.p - 2, Ed25519.p)) % Ed25519.p
  //   mv = ((1 + int(P.y)) * pow(((1 - int(P.y)) * int(P.x)), Ed25519.p - 2, Ed25519.p)) % Ed25519.p
  //   mv = mv*pow(Ed25519.scaling_factor_pos, Ed25519.p - 2, Ed25519.p) % Ed25519.p
  //   return mu, mv

  // (u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)

  fe25519 one_plus_y, one_minus_y, x_inv, s;

  fe25519_setone(&one_plus_y);
  fe25519_setone(&one_minus_y);

  fe25519_sub(&one_minus_y, &one_minus_y, y_ea); // 1-y
  fe25519_add(&one_plus_y, &one_plus_y, y_ea); // 1+y
  fe25519_invert(&one_minus_y, &one_minus_y); // (1-y)^-1
  fe25519_mul(U, &one_plus_y, &one_minus_y); // (1+y) * (1-y)^-1

  fe25519_invert(&x_inv, x_ea);
  fe25519_mul(V, U, &x_inv); // u * x^-1

  //fe25519 tmp;
  //fe25519_neg(&tmp, &scaling_factor);
  //fe25519_mul(V, V, &tmp); // sqrt(-486664) * u * x^-1
  fe25519_mul(V, V, &scaling_factor); // sqrt(-486664) * u * x^-1

  fe25519_reduceCompletely(U);
  fe25519_reduceCompletely(V);

  fe25519_setone(W);
}

// TODO move
// d of Edwards25519, -(121665/121666), from https://github.com/floodyberry/supercop/blob/master/crypto_sign/ed25519/ref/ge25519.c#L12
static const fe25519 ed25519_d = {{0xA3, 0x78, 0x59, 0x13, 0xCA, 0x4D, 0xEB, 0x75, 0xAB, 0xD8, 0x41, 0x41, 0x4D, 0x0A, 0x70, 0x00, 
  0x98, 0xE8, 0x79, 0x77, 0x79, 0x40, 0xC7, 0x8C, 0x73, 0xFE, 0x6F, 0x2B, 0xEE, 0x6C, 0x03, 0x52}};

// TODO move
// sqrt(-1) in fe25519, from https://github.com/floodyberry/supercop/blob/master/crypto_sign/ed25519/ref/ge25519.c#L18
static const fe25519 ed25519_sqrtm1 = {{0xB0, 0xA0, 0x0E, 0x4A, 0x27, 0x1B, 0xEE, 0xC4, 0x78, 0xE4, 0x2F, 0xAD, 0x06, 0x18, 0x43, 0x2F, 
  0xA7, 0xD7, 0xFB, 0x3D, 0x99, 0x00, 0x4D, 0x2B, 0x0B, 0xDF, 0xC1, 0x4F, 0x80, 0x24, 0x83, 0x2B}};

// TODO clean
// from rfc8032 python, converted and modified to c
// https://words.filippo.io/dispatches/edwards25519-formulas/
int ed25519_decode(fe25519* x, fe25519* y, const uint8_t in[32])
{
  /*
  def point_decompress(s):
    if len(s) != 32:
        raise Exception("Invalid input length for decompression")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1

    x = recover_x(y, sign)
    if x is None:
        return None
    else:
        return ECC.EccPoint(x, y, curve='Ed25519')

    def recover_x(y, sign):
      p = Ed25519.p
      if y >= p:
          return None
      x2 = (y*y-1) * modp_inv(int.from_bytes(Ed25519.d_bytes, byteorder='big')*y*y+1)
      if x2 == 0:
          if sign:
              return None
          else:
              return 0

      # Compute square root of x2
      x = pow(x2, (p+3) // 8, p)
      if (x*x - x2) % p != 0:
          x = x * modp_sqrt_m1 % p
      if (x*x - x2) % p != 0:
          return None

      if (x & 1) != sign:
          x = p - x
      return x
  */

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

  //unsigned char str[100];
  //send_USART_str((unsigned char *)"---------------decode()-----");

  fe25519 num, den, t1, t2, t3; // num = numerator, den = denominator, tX = tmps
  fe25519_setone(&t1);

  uint8_t par = in[31] >> 7; // [...10000000], get parity bit
  fe25519_unpack(y, in);

  //to_string_256bitvalue(str, (UN_256bitValue*)y);
  //send_USART_str((unsigned char *)"verify(): ed25519_decode(): y:");
  //send_USART_str((unsigned char *)str);

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
  //to_string_256bitvalue(str, (UN_256bitValue*)x);
  //send_USART_str((unsigned char *)"verify(): ed25519_decode(): x1:");
  //send_USART_str((unsigned char *)str);

  fe25519_square(&t1, x); // t1 used for check
  fe25519_mul(&t1, &t1, &den);
  if (fe25519_iseq_vartime(&t1, &num) == 0) {
    fe25519_mul(x, x, &ed25519_sqrtm1); // x = x1 * sqrt(-1)
    //to_string_256bitvalue(str, (UN_256bitValue*)x);
    //send_USART_str((unsigned char *)"verify(): ed25519_decode(): x2:");
    //send_USART_str((unsigned char *)str);
  }

  /* 4. Now we have one of the two square roots, except if input was not a square */
  // TODO this should not be the same as above. check! should compare -num, not num
  fe25519_square(&t1, x);
  fe25519_mul(&t1, &t1, &den);
  if (fe25519_iseq_vartime(&t1, &num) == 0)
    return 1;

  // fe25519 x_tmp1, x_tmp2;
  // fe25519_cpy(&x_tmp1, x);

  /* 5. Choose the desired square root according to parity: */ 
  // This is changed from the ref SUPERCOP implementation
  // We want to negate if the sign bit doesn't match
  // if(fe25519_getparity(x) != (1-par))
  if(fe25519_getparity(x) == (1-par)) {
    fe25519_neg(x, x);

    // fe25519 t;
    // int i;
    // for(i=0;i<32;i++) t.as_uint8_t[i]=x->as_uint8_t[i];
    // fe25519_setzero(&x_tmp2);
    // fe25519_sub(&x_tmp2, &x_tmp2, &t);

    // fe25519_reduceCompletely(&x_tmp1);
    // fe25519_reduceCompletely(&x_tmp2);

  }

  fe25519_reduceCompletely(x);


  // to_string_256bitvalue(str, (UN_256bitValue*)&x_tmp1);
  // send_USART_str((unsigned char *)"verify(): ed25519_decode(): after neg: x_tmp1:");
  // send_USART_str((unsigned char *)str);
  //to_string_256bitvalue(str, (UN_256bitValue*)&x);
  //send_USART_str((unsigned char *)"verify(): ed25519_decode(): after neg and reduce: x:");
  //send_USART_str((unsigned char *)str);
  //send_USART_str((unsigned char *)"------------------------------");
     

  return 0;
}

// LH
void ed25519_encode(uint8_t out[32], const fe25519* x, const fe25519* y) {
  uint8_t ctr;

  for (ctr = 0; ctr < 32; ctr++) {
    out[ctr] = y->as_uint8_t[ctr];
  }

  uint8_t lsb_of_x = x->as_uint8_t[0] & 1;

  out[31] = (out[31] & 0x7F) | (lsb_of_x << 7);
}

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


// TODO comment why needed
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
/// We refer to this paper using "orig." here.
/// We updated this algorithm slightly (especially the order of steps) in: 
/// "An update to the sca25519 library: mitigation card-tearing-based side-channel attacks"
/// (PLACEHOLDER: https://eprint.iacr.org/2024/)
/// The "alg. step" comments refer to this modified version of the algorithm. 
///
/// Comments such as "### alg. step 1 ###" provide to the respective line number of
/// pseudo-code used in the paper.
int crypto_scalarmult_curve25519(uint8_t* r,
                                 const uint8_t* s,
                                 const uint8_t* p) {
  ST_curve25519ladderstepWorkingState state;
  uint8_t i;
  volatile uint32_t retval = -1;
  volatile uint32_t fid_counter = 0;  // for fault injection detection ### alg. step 1 ###

  // Initialize return value with random bits
  randombytes(r, 32); // ### alg. step 1 (also 1 in orig.) ###

  char str[100];

/* Lukasz update:*/
  // LH comment, no scalar storage blinding or point blinding
  // update the key and the secret state data
  //update_static_key_curve25519(); // ### alg. step 2, orig. 49-51


  // LH comment, no scalar blinding secret storage
  // Prepare the scalar within the working state buffer.
  // for (i = 0; i < 32; i++) {
  //   state.s.as_uint8_t[i] = static_key.as_uint8_t[i];
  //   INCREMENT_BY_NINE(fid_counter);
  // } // ### alg. step 3, originally 2 ###
  for (i = 0; i < 32; i++) {
    state.s.as_uint8_t[i] = s[i];
    INCREMENT_BY_NINE(fid_counter);
  }

  // Copy the affine x-axis of the base point to the state.
  fe25519_unpack(&state.x0, p); // ### alg. step 15, orig. 14 ###
  fe25519 x_base_affine; // TODO
  fe25519_unpack(&x_base_affine, p);

  // ### alg. step 16, step 15 ###
  fe25519_setone(&state.xq);
  fe25519_setzero(&state.zq);
  fe25519_cpy(&state.xp, &state.x0);
  fe25519_setone(&state.zp);

  INCREMENT_BY_NINE(fid_counter);

  fe25519 yp, y0;

  // LH comment, no point blinding
  // point25519 P, R;
  // P.x = &state.xp;
  // P.y = &yp;
  // P.z = &state.zp;
  // R.x = &Rx;
  // R.y = &Ry;
  // R.z = &Rz;

  if (computeY_curve25519_affine(&yp, &state.x0) != 0) {
    goto fail;
  } // ### alg. step 4, orig. 3 ###
  fe25519_reduceCompletely(&yp);


  //to_string_256bitvalue(str, &state.x0); // TODO remove
  //send_USART_str((unsigned char*)"scamult: state.x0: ");
  //send_USART_str(str);    
  //to_string_256bitvalue(str, &yp); // TODO remove
  //send_USART_str((unsigned char*)"scamult: y_ma: ");
  //send_USART_str(str);                  // TODO remove
  
  // LH comment
  // curve25519_addPoint(&P, &P, &R); // ### alg. step 6, orig. 5 ###

  // LH comment
  // Double 3 times before we start ### alg. step 7, orig. 6 ###
  // curve25519_doublePoint(&P, &P);
  // curve25519_doublePoint(&P, &P);
  // curve25519_doublePoint(&P, &P);

  // Randomize scalar multiplicatively
  UN_512bitValue randVal;
#ifdef SCALAR_RANDOMIZATION
  fe25519 t, Rinv, randB;
  fe25519_setzero((fe25519*)&state.r);

  // ### alg. step 8, orig. step 7 ###
  do {
    randombytes(state.r.as_uint8_t, 8);
  } while (!state.r.as_64_bitValue_t[0].as_uint64_t[0]);
  //! fe25519_iszero(&state.r)



  //char str[100];                        // TODO remove
  //to_string_256bitvalue(str, &state.s); // TODO remove
  //send_USART_str(str);                  // TODO remove

  // for (int i = 0; i < 8; i++) {         // TODO remove
  //   state.r.as_uint8_t[i] = 0x05;
  // }
  //to_string_256bitvalue(str, &state.r); // TODO remove
  //send_USART_str(str);                  // TODO remove


  randombytes(randVal.as_uint8_t, 64);


  // for (int i = 0; i < 64; i++) {        // TODO remove
  //   randVal.as_uint8_t[i] = 0x03;
  // }


  fe25519_reduceTo256Bits(&randB, &randVal); // ### alg. step 9, orig. 8 ###
  //to_string_256bitvalue(str, &randB);   // TODO remove
  //send_USART_str(str);                  // TODO remove


  sc25519_mul(&t, &state.r, &randB); // ### alg. step 10, orig. 9 ###
  //to_string_256bitvalue(str, &t);       // TODO remove
  //send_USART_str(str);                  // TODO remove


  // ### alg. step 11, orig. 10 ###
  //uint8_t helper_share0[32];
  //uint8_t helper_share1[32];
  //hash_masked(r, randB.as_uint8_t, 32, helper_share0, helper_share1);
  //hash_masked(r, randB.as_uint8_t, 32, helper_share0, helper_share1);
  sc25519_inverse(&t, &t);
  //to_string_256bitvalue(str, &t);       // TODO remove
  //send_USART_str(str);                  // TODO remove
  
  
  sc25519_mul(&Rinv, &t, &randB);
  //to_string_256bitvalue(str, &Rinv);    // TODO remove
  //send_USART_str(str);                  // TODO remove

  // sc25519 new_s, zero;               // TODO remove
  // fe25519_setzero(&zero);            // TODO remove
  sc25519_mul(&state.s, &state.s, &Rinv); // // ### alg. step 12, orig. 11 ###
  //sc_muladd(new_s.as_uint8_t, state.s.as_uint8_t, Rinv.as_uint8_t, zero.as_uint8_t); // TODO remove
  //cpy_256bitvalue(&state.s, &new_s);  // TODO remove

  //to_string_256bitvalue(str, &new_s); // TODO remove
  //to_string_256bitvalue(str, &state.s); // TODO remove
  //send_USART_str(str);                  // TODO remove


  #else
  fe25519_setone((fe25519*)&state.r);
#endif

  // LH comment, no scalar storage blinding
  // new re-rand ### alg. step 13, orig. 12 ###
  //sc25519_mul(&state.s, &state.s, &blindingFactor);

  INCREMENT_BY_163(fid_counter); // ### alg. step 14, orig. 13 ###

  // LH comment because the doubling is also commented
  // Optimize for stack usage when implementing  ### alg. step 14 ###

  // fe25519_invert_useProvidedScratchBuffers(&state.zp, &state.zp, &state.xq,
  //                                          &state.zq, &state.x0);
  // fe25519_mul(&state.xp, &state.xp, &state.zp);
  // fe25519_reduceCompletely(&state.xp);

  // fe25519_mul(&yp, &yp, &state.zp);

  // fe25519_cpy(&state.x0, &state.xp);

  //  ### alg. step 17, orig. 16 ###
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

  // LH 254
  // state.nextScalarBitToProcess = 253;  // 252;
  state.nextScalarBitToProcess = 254;

  // ### alg. step 18, orig. 17 ###
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

#ifdef ITOH_COUNTERMEASURE
  // ### alg. step 19, orig. 18 ###
  UN_256bitValue itoh;
  randombytes(itoh.as_uint8_t, 32);
  // LH, itoh should be 254, itohshift 254 but shifted
  //itoh.as_uint8_t[31] &= 63;  // 31;//15
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
  // LH comment change a[252] -> a[253]
  // ### alg. step 22, orig. 21 ###
  maskScalarBitsWithRandomAndCswap(&state, itohShift.as_uint32_t[7], 31);
#else
  //curve25519_cswap_asm(&state, &itohShift.as_uint32_t[7]);
#endif
#endif

  // ### alg. step 23, orig. 22 ###
  while (state.nextScalarBitToProcess >= 0) {
    uint8_t limbNo = 0;
    uint8_t bitNo = 0;
#ifdef MULTIPLICATIVE_CSWAP
    {
      limbNo = (uint8_t)(state.nextScalarBitToProcess >> 5);
      bitNo = state.nextScalarBitToProcess & 0x1f;
      // ### alg. step 23, orig. 22 and [XXX]###

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
    // LH TODO why not >= 0 ???
    if (state.nextScalarBitToProcess >= 1)  // ### alg. step 25, orig. 24
    {
      curve25519_ladderstep(&state); // alg. step 26, orig. 25

      INCREMENT_BY_NINE(fid_counter); // alg. step 28, orig. 27

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

  // ### alg. step 29, orig. 28
  computeY_curve25519_projective(&y0, &state.xp, &state.zp, &state.xq,
                                 &state.zq, &state.x0, &yp);

  // ### alg. step 30, orig. 29
  // Short scalar multiplication to undo multiplicative scalar blinding
  // Optimize for stack usage.
  fe25519_invert_useProvidedScratchBuffers(&state.zp, &state.zp, &state.xq,
                                           &state.zq, &state.x0);
  fe25519_mul(&state.xp, &state.xp, &state.zp);
  fe25519_reduceCompletely(&state.xp);

  fe25519_mul(&y0, &y0, &state.zp);
  fe25519_cpy(&state.x0, &state.xp); // (x0, y0)_affine = (xp, y0, zp)_projective

  // LH
  fe25519 new_x_aff, new_y_aff;
  fe25519_cpy(&new_x_aff, &state.x0);
  fe25519_cpy(&new_y_aff, &y0);


  // ### alg. step 32, orig. 31
  // Reinitialize coordinates
  // Prepare the working points within the working state struct.
  randombytes(randVal.as_uint8_t, 64);
  fe25519_reduceTo256Bits(&state.zq, &randVal);
  // paranoia: guarantee that the value is not zero mod p25519
  fe25519_reduceCompletely(&state.zq);
  state.zq.as_uint8_t[31] |= 128;
  fe25519_mul(&state.xq, &state.zq, &state.x0);

  // ### alg. step 31, orig. 30
  fe25519_setone(&state.xp);
  fe25519_setzero(&state.zp);

  // P(1, 0), Q(x0*rand ,rand)

  state.nextScalarBitToProcess = 64;
#if 1
  // Prepare scalar xor previous bit
  // ### alg. step 34 and 35, orig. 33 and 34
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
  // ### alg. step 33, orig. 32
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
  // ### alg. step 37, orig. 36
  maskScalarBitsWithRandomAndCswap(&state, itoh64Shift.as_uint32_t[2], 1);
#else
  curve25519_cswap_asm(&state, &itoh64Shift.as_uint32_t[2]);
#endif
#endif

  while (state.nextScalarBitToProcess >= 0) // ### alg. step 38, orig. 37
  {
    uint8_t limbNo = 0;
    uint8_t bitNo = 0;

#ifdef MULTIPLICATIVE_CSWAP
    {
      limbNo = (uint8_t)(state.nextScalarBitToProcess >> 5);
      bitNo = state.nextScalarBitToProcess & 0x1f;

      // ### alg. step 39, orig. 38
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

    if (state.nextScalarBitToProcess >= 1) // ### alg. step 40, orig. 39
    {
      curve25519_ladderstep(&state); // ### alg. step 41, orig. 40
      INCREMENT_BY_NINE(fid_counter); // ### alg. step 43, orig. 42

#ifdef MULTIPLICATIVE_CSWAP
#ifdef ITOH_COUNTERMEASURE64
      maskScalarBitsWithRandomAndCswap(&state, itoh64Shift.as_uint32_t[limbNo],
                                       bitNo); // ### alg. step 42, orig. 41
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
  // Compute y1
  // computeY_curve25519_projective(&y0, &state.xp, &state.zp, &state.xq,
  //                                &state.zq, &state.x0, &yp); // ### alg. step 43
  // computeY_curve25519_projective(&y0, &state.xp, &state.zp, &state.xq,
  //                                &state.zq, &x_base_affine, &yp); // ### alg. step 43
  computeY_curve25519_projective(&y0, &state.xp, &state.zp, &state.xq,
                                 &state.zq, &new_x_aff, &new_y_aff); // ### alg. step 43

  // LH comment, no point blinding
  // point25519 A;
  // fe25519 Ay;
  // A.x = &Sx;
  // A.y = &Ay;
  // A.z = &Sz;
  // P.x = &state.xp;
  // P.y = &yp;
  // P.z = &state.zp;
  // fe25519_cpy(A.y, &Sy);
  // fe25519_neg(A.y, A.y);
  // curve25519_addPoint(&P, &P, &A); // ### alg. step 45, orig. 44

  // LH comment
  // Optimize for stack usage for ### alg. step 46, orig. 45
  // fe25519_invert_useProvidedScratchBuffers(&state.zp, &state.zp, &state.xq,
  //                                          &state.zq, &state.x0);
  // fe25519_mul(&state.xp, &state.xp, &state.zp);
  // fe25519_reduceCompletely(&state.xp);
  INCREMENT_BY_163(fid_counter);

  // LH
  fe25519 x_ea, y_ea;
  point_conversion_mp_ea(&x_ea, &y_ea, &state.xp, &y0 ,&state.zp);
  //fe25519_reduceCompletely(&x_ea);
  //fe25519_reduceCompletely(&y_ea);

  // if (fid_counter != (4 * 163 + 350 * 9)) // ### alg. step 48, orig. 47
  if (fid_counter != (4 * 163 + 351 * 9)) // ### alg. step 48, orig. 47
  {
  fail:
    retval = -1;
    randombytes(state.xp.as_uint8_t, 32); // ### alg. step 49, orig. 48
  } else {
    retval = 0;
  }
  // LH
  //fe25519_pack(r, &state.xp);
  ed25519_encode(r, &x_ea, &y_ea);

  //to_string_256bitvalue(str, &x_ea); // TODO remove
  //send_USART_str((unsigned char*)"scamult: x_ea:");
  //send_USART_str(str);
  //to_string_256bitvalue(str, &y_ea); // TODO remove
  //send_USART_str((unsigned char*)"scamult: y_ea:");
  //send_USART_str(str); 

/*
  These original update is moved to the beginning
  // update the key and the secret state data
  update_static_key_curve25519(); // ### orig. alg. step 49-51
*/
  return retval;
}

const uint8_t g_basePointCurve25519[32] = {9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

int crypto_scalarmult_base_curve25519(uint8_t* q,
                                      const uint8_t* n
) {
  return crypto_scalarmult_curve25519(q, n, g_basePointCurve25519);
}



/// EPHEMERAL
/// This function implements algorithm 2 from the paper 
/// "SoK: SCA-Secure ECC in software - mission impossible?"
/// (https://tches.iacr.org/index.php/TCHES/article/view/9962)
///
/// Comments such as "### alg. step 1 ###" provide to the respective line number of
/// pseudo-code used in the paper.
int ephemeral_crypto_scalarmult_curve25519(uint8_t *r, const uint8_t *s,
  const uint8_t *p) {
  ST_curve25519ladderstepWorkingState state;
  uint8_t i;
  volatile uint8_t retval = -1;
  // Fault injection detection counter ### alg. step 1 ###
  volatile uint32_t fid_counter = 0;

  // Initialize return value with random bits ### alg. step 2 ###
  randombytes(r, 32);

  // Prepare the scalar within the working state buffer.
  for (i = 0; i < 32; i++) {
    state.s.as_uint8_t[i] = s[i];
  }

  // Copy the affine x-coordinate of the base point to the state.
  fe25519_unpack(&state.x0, p);

  // LH needed change, TODO why
  // fe25519_setone(&state.xq);
  // fe25519_setzero(&state.zq);
  // fe25519_cpy(&state.xp, &state.x0);
  // fe25519_setone(&state.zp);

  fe25519_setone(&state.zq);
  fe25519_cpy(&state.xq, &state.x0);

  fe25519_setone(&state.xp);
  fe25519_setzero(&state.zp);

  // LH add
  fe25519 yp, y0;
  if (computeY_curve25519_affine(&yp, &state.x0) != 0) {
    return 1;
  }

  // LH: commented below because it is for ECDH
  // Clamp scalar ### alg. step 3 ###
  //state.s.as_uint8_t[31] &= 127;
  //state.s.as_uint8_t[31] |= 64;

  // LH: commented below because it is for ECDH
  // ### alg. step 4 ###
  //shiftRightOne(&state.s);
  //shiftRightOne(&state.s);
  //shiftRightOne(&state.s);

  // ### alg. step 5 ###
  INCREMENT_BY_163(fid_counter);

  // LH: commented below because it is for ECDH
  // Double 3 times before we start. ### alg. step 6 ###
  //curve25519_doublePointP(&state);
  //curve25519_doublePointP(&state);
  //curve25519_doublePointP(&state);

  // ### alg. step 7 ###
  INCREMENT_BY_163(fid_counter);

  // LH TODO print 
  // if (!fe25519_iszero(&state.zp))   // ### alg. step 8 ###
  // {
  //   goto fail; // ### alg. step 9 ###
  // }

  // LH comment because the doubling is also commented
  // Optimize for stack usage when implementing  ### alg. step 10 ###
  // fe25519_invert_useProvidedScratchBuffers(&state.zp, &state.zp, &state.xq,
  //                                          &state.zq, &state.x0);
  //fe25519_invert(&state.zp, &state.zp);
  //fe25519_mul(&state.xp, &state.xp, &state.zp);
  //fe25519_reduceCompletely(&state.xp);

  //fe25519_cpy(&state.x0, &state.xp);

  // Reinitialize coordinates, LH change P to Q
  // Prepare the working points within the working state struct.
  // ### alg. step 12 ###
  UN_512bitValue randVal;
  randombytes(randVal.as_uint8_t, 64);
  fe25519_reduceTo256Bits(&state.zq, &randVal);
  // paranoia: guarantee that the value is not zero mod p25519
  fe25519_reduceCompletely(&state.zq);
  state.zq.as_uint8_t[31] |= 128; // LH TODO what is this????

  fe25519_mul(&state.xq, &state.zq, &state.x0);  // ### alg. step 12 ###

  // LH change P to Q
  fe25519_setone(&state.xp);  // ### alg. step 11 ###
  fe25519_setzero(&state.zp);

  // Perform ladderstep for first bit that is always 1
  //curve25519_ladderstep(&state); // LH TODO what is this????

  // LH, 254 because first 3 bits are not always zero
  //state.nextScalarBitToProcess = 251;
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
              bitNo);  // ### alg. step 16 and 19 ###.
    }
#else
    {
      uint8_t limbNo = (uint8_t)(state.nextScalarBitToProcess >> 5);
      curve25519_cswap_asm(&state, &state.s.as_uint32_t[limbNo]);
    }
#endif
    if (state.nextScalarBitToProcess >= 1) {
      curve25519_ladderstep(&state);  // ### alg. step 17 ###

      INCREMENT_BY_NINE(fid_counter);  // ### alg. step 18 ###
    }

    state.nextScalarBitToProcess--;
  }

  // Optimize for stack usage when implementing ### alg. step 20 ###
  //fe25519_invert_useProvidedScratchBuffers(&state.zp, &state.zp, &state.xq,
  //                                         &state.zq, &state.x0);
  //fe25519_mul(&state.xp, &state.xp, &state.zp);
  //fe25519_reduceCompletely(&state.xp);

  // LH
  computeY_curve25519_projective(&y0, &state.xp, &state.zp, &state.xq,
    &state.zq, &state.x0, &yp);

  INCREMENT_BY_163(fid_counter); // ### alg. step 21 ###

  // LH
  fe25519 x_ea, y_ea;
  point_conversion_mp_ea(&x_ea, &y_ea, &state.xp, &y0 ,&state.zp);
  fe25519_reduceCompletely(&x_ea);
  fe25519_reduceCompletely(&y_ea);

  // char str[100];
  // to_string_256bitvalue(str, &x_ea);
  // send_USART_str((unsigned char *)"x_ea:");
  // send_USART_str((unsigned char *)str);
  // to_string_256bitvalue(str, &y_ea);
  // send_USART_str((unsigned char *)"y_ea:");
  // send_USART_str((unsigned char *)str);

  // ### alg. step 22 ###
  // LH
  //if (fid_counter != (163 * 4 + 251 * 9)) {
  if (fid_counter != (163 * 4 + 254 * 9)) {
    fail:
    retval = -1;
    randombytes(state.xp.as_uint8_t, 32);  // ### alg. step 23 ###
  } else {
    retval = 0;
  }
  // LH
  //fe25519_pack(r, &state.xp);
  ed25519_encode(r, &x_ea, &y_ea);
  return retval;
}

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

int unprotected_crypto_scalarmult_curve25519(uint8_t *r, const uint8_t *s,
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

  // unsigned char str[100];
  // to_string_256bitvalue(str, &state.x0); // TODO remove
  // send_USART_str((unsigned char*)"scamult: state.x0: ");
  // send_USART_str(str);    
  // to_string_256bitvalue(str, &yp); // TODO remove
  // send_USART_str((unsigned char*)"scamult: y_ma: ");
  // send_USART_str(str);                  // TODO remove

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


  // LH
  fe25519 x_ea, y_ea;
  point_conversion_mp_ea(&x_ea, &y_ea, &state.xp, &y0 ,&state.zp);
  //fe25519_reduceCompletely(&x_ea);
  //fe25519_reduceCompletely(&y_ea);

  // to_string_256bitvalue(str, &x_ea);
  // send_USART_str((unsigned char *)"x_ea:");
  // send_USART_str((unsigned char *)str);
  // to_string_256bitvalue(str, &y_ea);
  // send_USART_str((unsigned char *)"y_ea:");
  // send_USART_str((unsigned char *)str);

  ed25519_encode(r, &x_ea, &y_ea);

  return 0;
}

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

