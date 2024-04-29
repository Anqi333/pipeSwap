#ifndef __VTD_H__
#define __VTD_H__

#include <stdint.h>
#include <gmp.h>

void VTD_setup(uint64_t lambda, mpz_t* crs_range);

void VTD_commit(mpz_t* commitment, const mpz_t* crs_range, const mpz_t* message);

void VTD_verify(const mpz_t* commitment, const mpz_t* crs_range, const mpz_t* message);

#endif
#pragma once
