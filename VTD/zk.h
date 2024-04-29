#ifndef __ZK_H__
#define __ZK_H__
#include <stdint.h>
#include <gmp.h>

void ZK_setup(uint64_t lambda, mpz_t* crs_range);
void ZK_prover(mpz_t* pi_range_i, mpz_t crs_range, mpz_t* Z_i, mpz_t a, mpz_t b, mpz_t* T, mpz_t x_i, mpz_t r_i);
void ZK_verify();

#endif
