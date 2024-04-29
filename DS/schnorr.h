#ifndef SCHNORR_H
#define SCHNORR_H

#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <windows.h>

#define MESSAGE_LENGTH 32
#define BN_LEN 32  

typedef struct {
    EC_POINT* g;  
    BIGNUM* q;    
} PublicParameters;

typedef struct {
    BIGNUM* sk;  
    EC_POINT* pk;  
} KeyPair;

typedef struct {
    BIGNUM* r;  
    BIGNUM* s;  
} Signature;


KeyPair generate_keypair(EC_GROUP* group, PublicParameters* pp);


void compute_h_schnorr(const EC_GROUP* group, const EC_POINT* pk1_pk2, const EC_POINT* g_k_Y, const unsigned char* m, int m_len, unsigned char* result);


Signature* Sign(const char* m, KeyPair* keypair, PublicParameters* pp, BN_CTX* ctx);


int Vrfy(const char* m, KeyPair* keypair, Signature* sig, PublicParameters* pp, BN_CTX* ctx);


Signature* pSign(const unsigned char* m, int m_len, const EC_POINT* Y, KeyPair* keypair1, KeyPair* keypair2, PublicParameters* pp, BN_CTX* ctx);


int pVrfy(const char* m, const EC_POINT* Y, const Signature* sig, KeyPair* keypair1, KeyPair* keypair2, PublicParameters* pp, BN_CTX* ctx);


Signature* JSign(const char* m, KeyPair* keypair1, KeyPair* keypair2, PublicParameters* pp, BN_CTX* ctx);


int JVrfy(const char* m, KeyPair* keypair1, KeyPair* keypair2, Signature* sig, PublicParameters* pp, BN_CTX* ctx);


Signature* Adapt(Signature* sig_tilde, BIGNUM* y, BN_CTX* ctx);


BIGNUM* Ext(Signature* sig, Signature* sig_tilde, EC_POINT* Y, BN_CTX* ctx);


int c_size(Signature* sig);


void schnorr_test();

#endif  // SCHNORR_H
