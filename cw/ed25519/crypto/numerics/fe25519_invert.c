#include "../include/fe25519.h"

// Note, that r and x are allowed to overlap!
void fe25519_invert(fe25519* r, const fe25519* x) {
  fe25519 t0;
  fe25519 t1;
  fe25519 t2;

  fe25519_invert_useProvidedScratchBuffers(r, x, &t0, &t1, &t2);
}

// Use this function if optimizing for stack consumption.
// Note, that r and x are allowed to overlap!
void fe25519_invert_useProvidedScratchBuffers(fe25519* r, const fe25519* x,
                                              fe25519* t0, fe25519* t1,
                                              fe25519* t2) {
  fe25519* z11 = r;  // store z11 in r (in order to save one temporary).
  fe25519* z2_10_0 = t1;
  fe25519* z2_50_0 = t2;
  fe25519* z2_100_0 = z2_10_0;

  uint8_t i;

  {
    fe25519* z2 = z2_50_0;

    /* 2 */ fe25519_square(z2, x);
    /* 4 */ fe25519_square(t0, z2);
    /* 8 */ fe25519_square(t0, t0);
    /* 9 */ fe25519_mul(z2_10_0, t0, x);
    /* 11 */ fe25519_mul(z11, z2_10_0, z2);

    // z2 is dead.
  }

  /* 22 */ fe25519_square(t0, z11);
  /* 2^5 - 2^0 = 31 */ fe25519_mul(z2_10_0, t0, z2_10_0);

  /* 2^6 - 2^1 */ fe25519_square(t0, z2_10_0);
  /* 2^7 - 2^2 */ fe25519_square(t0, t0);
  /* 2^8 - 2^3 */ fe25519_square(t0, t0);
  /* 2^9 - 2^4 */ fe25519_square(t0, t0);
  /* 2^10 - 2^5 */ fe25519_square(t0, t0);
  /* 2^10 - 2^0 */ fe25519_mul(z2_10_0, t0, z2_10_0);

  /* 2^11 - 2^1 */ fe25519_square(t0, z2_10_0);

  /* 2^20 - 2^10 */ for (i = 1; i < 10; i++) { fe25519_square(t0, t0); }
  /* 2^20 - 2^0 */ fe25519_mul(z2_50_0, t0, z2_10_0);

  /* 2^21 - 2^1 */ fe25519_square(t0, z2_50_0);

  /* 2^40 - 2^20 */ for (i = 1; i < 20; i++) { fe25519_square(t0, t0); }
  /* 2^40 - 2^0 */ fe25519_mul(t0, t0, z2_50_0);

  /* 2^41 - 2^1 */ fe25519_square(t0, t0);

  /* 2^50 - 2^10 */ for (i = 1; i < 10; i++) { fe25519_square(t0, t0); }
  /* 2^50 - 2^0 */ fe25519_mul(z2_50_0, t0, z2_10_0);

  /* 2^51 - 2^1 */ fe25519_square(t0, z2_50_0);

  /* 2^100 - 2^50 */ for (i = 1; i < 50; i++) { fe25519_square(t0, t0); }
  /* 2^100 - 2^0 */ fe25519_mul(z2_100_0, t0, z2_50_0);

  /* 2^101 - 2^1 */ fe25519_square(t0, z2_100_0);

  /* 2^200 - 2^100 */ for (i = 1; i < 100; i++) { fe25519_square(t0, t0); }
  /* 2^200 - 2^0 */ fe25519_mul(t0, t0, z2_100_0);

  /* 2^250 - 2^50 */ for (i = 0; i < 50; i++) { fe25519_square(t0, t0); }
  /* 2^250 - 2^0 */ fe25519_mul(t0, t0, z2_50_0);

  /* 2^255 - 2^5 */ for (i = 0; i < 5; i++) { fe25519_square(t0, t0); }
  /* 2^255 - 21 */ fe25519_mul(r, t0, z11);
}

/*
 * From mirror of the SUPERCOP.
 * URL: https://github.com/floodyberry/supercop/blob/master/crypto_sign/ed25519/ref/fe25519.c
 * ---
 * Returns z^((p-5)/8) = z^(2^252-3)
 * Used to compute square roots since we have p=5 (mod 8); see Cohen and Frey.
 * Used in ed25519_decode for example.
 */
void fe25519_pow2523(fe25519 *r, const fe25519 *x)
{
	fe25519 z2;
	fe25519 z9;
	fe25519 z11;
	fe25519 z2_5_0;
	fe25519 z2_10_0;
	fe25519 z2_20_0;
	fe25519 z2_50_0;
	fe25519 z2_100_0;
	fe25519 t;
	uint8_t i;
		
	/* 2 */ fe25519_square(&z2,x);
	/* 4 */ fe25519_square(&t,&z2);
	/* 8 */ fe25519_square(&t,&t);
	/* 9 */ fe25519_mul(&z9,&t,x);
	/* 11 */ fe25519_mul(&z11,&z9,&z2);
	/* 22 */ fe25519_square(&t,&z11);
	/* 2^5 - 2^0 = 31 */ fe25519_mul(&z2_5_0,&t,&z9);

	/* 2^6 - 2^1 */ fe25519_square(&t,&z2_5_0);
	/* 2^10 - 2^5 */ for (i = 1;i < 5;i++) { fe25519_square(&t,&t); }
	/* 2^10 - 2^0 */ fe25519_mul(&z2_10_0,&t,&z2_5_0);

	/* 2^11 - 2^1 */ fe25519_square(&t,&z2_10_0);
	/* 2^20 - 2^10 */ for (i = 1;i < 10;i++) { fe25519_square(&t,&t); }
	/* 2^20 - 2^0 */ fe25519_mul(&z2_20_0,&t,&z2_10_0);

	/* 2^21 - 2^1 */ fe25519_square(&t,&z2_20_0);
	/* 2^40 - 2^20 */ for (i = 1;i < 20;i++) { fe25519_square(&t,&t); }
	/* 2^40 - 2^0 */ fe25519_mul(&t,&t,&z2_20_0);

	/* 2^41 - 2^1 */ fe25519_square(&t,&t);
	/* 2^50 - 2^10 */ for (i = 1;i < 10;i++) { fe25519_square(&t,&t); }
	/* 2^50 - 2^0 */ fe25519_mul(&z2_50_0,&t,&z2_10_0);

	/* 2^51 - 2^1 */ fe25519_square(&t,&z2_50_0);
	/* 2^100 - 2^50 */ for (i = 1;i < 50;i++) { fe25519_square(&t,&t); }
	/* 2^100 - 2^0 */ fe25519_mul(&z2_100_0,&t,&z2_50_0);

	/* 2^101 - 2^1 */ fe25519_square(&t,&z2_100_0);
	/* 2^200 - 2^100 */ for (i = 1;i < 100;i++) { fe25519_square(&t,&t); }
	/* 2^200 - 2^0 */ fe25519_mul(&t,&t,&z2_100_0);

	/* 2^201 - 2^1 */ fe25519_square(&t,&t);
	/* 2^250 - 2^50 */ for (i = 1;i < 50;i++) { fe25519_square(&t,&t); }
	/* 2^250 - 2^0 */ fe25519_mul(&t,&t,&z2_50_0);

	/* 2^251 - 2^1 */ fe25519_square(&t,&t);
	/* 2^252 - 2^2 */ fe25519_square(&t,&t);
	/* 2^252 - 3 */ fe25519_mul(r,&t,x);
}
