#ifndef ECDSA_H
#define ECDSA_H

#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#define MESSAGE_LENGTH 32
#define MSG_LEN 250

// Public parameters for ECDSA
typedef struct {
    EC_GROUP* group;
    EC_POINT* g;
    BIGNUM* q;
} PublicParameters;

// Keypair for ECDSA
typedef struct {
    BIGNUM* sk;  // private key
    EC_POINT* pk;  // public key
} KeyPair;

// Signature for ECDSA
typedef struct {
    BIGNUM* r;
    BIGNUM* s;
} Signature;

// Pre-signature for ECDSA
typedef struct {
    BIGNUM* r;
    BIGNUM* s;
    BIGNUM* K;
} Pre_Signature;

// Function declarations for ECDSA operations
KeyPair generate_keypair(EC_GROUP* group, PublicParameters* pp);

Signature* Sign(const char* m, KeyPair* keypair, PublicParameters* pp, BN_CTX* ctx);

int Vrfy(const char* m, KeyPair* keypair, Signature* sig, PublicParameters* pp, BN_CTX* ctx);

Signature* JSign(const char* m, EC_GROUP* group, KeyPair* keypair1, KeyPair* keypair2, PublicParameters* pp, BN_CTX* ctx);

int JVrfy(const char* m, EC_GROUP* group, KeyPair* keypair1, KeyPair* keypair2, Signature* sig, PublicParameters* pp, BN_CTX* ctx);

Pre_Signature* PSign(const char* m, EC_GROUP* group, KeyPair* keypair1, KeyPair* keypair2, const EC_POINT* Y, PublicParameters* pp, BN_CTX* ctx);

int PVrfy(const char* m, EC_GROUP* group, KeyPair* keypair1, KeyPair* keypair2, Pre_Signature* pre_sig, const EC_POINT* Y, PublicParameters* pp, BN_CTX* ctx);

Signature* Adapt(Pre_Signature* pre_sig, BIGNUM* y, PublicParameters* pp, BN_CTX* ctx);

#endif  // ECDSA_H
