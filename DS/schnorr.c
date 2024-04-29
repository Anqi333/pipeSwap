#include "schnorr.h"

KeyPair generate_keypair(EC_GROUP* group, PublicParameters* pp) {
    KeyPair keypair;
    keypair.sk = BN_new();
    keypair.pk = EC_POINT_new(group);

    // Generate a random big number in the range [1, q-1] as the private key sk
    BN_rand_range(keypair.sk, pp->q);

    // Compute the public key pk = g^sk
    EC_POINT_mul(group, keypair.pk, keypair.sk, NULL, NULL, NULL);

    return keypair;
}

void compute_h_schnorr(const EC_GROUP* group, const EC_POINT* pk1_pk2, const EC_POINT* g_k_Y, const unsigned char* m, int m_len, unsigned char* result) {
    unsigned char buffer[BN_LEN];
    int len;

    // Use the SHA256_CTX structure to save the context of the hash
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    // Add pk1_pk2
    len = EC_POINT_point2oct(group, pk1_pk2, POINT_CONVERSION_COMPRESSED, buffer, BN_LEN, NULL);
    SHA256_Update(&sha256, buffer, len);

    // Add g_k_Y
    len = EC_POINT_point2oct(group, g_k_Y, POINT_CONVERSION_COMPRESSED, buffer, BN_LEN, NULL);
    SHA256_Update(&sha256, buffer, len);

    // Add m
    SHA256_Update(&sha256, m, m_len);

    // Compute the final hash value
    SHA256_Final(result, &sha256);
}

Signature* Sign(const char* m, KeyPair* keypair, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    Signature* sig = (Signature*)malloc(sizeof(Signature));
    sig->r = BN_new();
    sig->s = BN_new();

    BIGNUM* k = BN_new();
    BIGNUM* r = BN_new();
    BIGNUM* sk1_plus_sk2 = BN_new();
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT* g_k = EC_POINT_new(group);

    // generate random k in Z_q
    BN_rand_range(k, pp->q);

    // compute g^k
    EC_POINT_mul(group, g_k, k, NULL, NULL, ctx);

    // compute r = H(pk || g^k || m)
    unsigned char r_str[BN_LEN];
    compute_h_schnorr(group, keypair->pk, g_k, m, strlen(m), r_str);
    BN_bin2bn(r_str, BN_LEN, r);

    // compute s = k + r*sk
    BIGNUM* r_mul_sk = BN_new();
    BN_mul(r_mul_sk, r, keypair->sk, ctx);
    BN_add(sig->s, k, r_mul_sk);

    BN_free(k);
    BN_free(r);
    EC_POINT_free(g_k);
    EC_GROUP_free(group);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("Sign exc time: %f ms\n", elapsedTime);

    return sig;
}

int Vrfy(const char* m, KeyPair* keypair, Signature* sig, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    int result = 0;

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT* hash_input = EC_POINT_new(group);
    EC_POINT* g_s = EC_POINT_new(group);
    EC_POINT* neg_r = EC_POINT_new(group);

    // compute g^s
    EC_POINT_mul(group, g_s, sig->s, NULL, NULL, ctx);

    // compute pk^(-r)
    EC_POINT_invert(group, neg_r, ctx);
    EC_POINT_mul(group, neg_r, NULL, keypair->pk, sig->r, ctx);

    // compute g^s * pk^(-r)
    EC_POINT_add(group, hash_input, g_s, neg_r, ctx);

    // compute r' = H(pk || g^s * pk^(-r) || m)
    unsigned char r_prime_str[BN_LEN];
    compute_h_schnorr(group, keypair->pk, hash_input, m, strlen(m), r_prime_str);

    // convert r' to BIGNUM
    BIGNUM* r_prime = BN_new();
    BN_bin2bn(r_prime_str, BN_LEN, r_prime);

    // check if r = r'
    result = BN_cmp(sig->r, r_prime) == 0;

    EC_GROUP_free(group);
    EC_POINT_free(hash_input);
    EC_POINT_free(g_s);
    EC_POINT_free(neg_r);
    BN_free(r_prime);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("Vrify exc time: %f ms\n", elapsedTime);

    return result;
}

Signature* pSign(const unsigned char* m, int m_len, const EC_POINT* Y, KeyPair* keypair1, KeyPair* keypair2, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    Signature* sig = (Signature*)malloc(sizeof(Signature));
    sig->r = BN_new();
    sig->s = BN_new();

    BIGNUM* k = BN_new();
    BIGNUM* r = BN_new();
    BIGNUM* sk1_plus_sk2 = BN_new();
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT* g_k = EC_POINT_new(group);
    EC_POINT* g_k_mul_Y = EC_POINT_new(group);
    EC_POINT* pk1_mul_pk2 = EC_POINT_new(group);

    // Generate random k in Z_q
    BN_rand_range(k, pp->q);

    // Compute g^k
    EC_POINT_mul(group, g_k, k, NULL, NULL, ctx);

    // Compute g^k * Y
    EC_POINT_mul(group, g_k_mul_Y, NULL, g_k, BN_value_one(), ctx);
    EC_POINT_add(group, g_k_mul_Y, g_k_mul_Y, Y, ctx);

    // Compute pk1 * pk2
    EC_POINT_mul(group, pk1_mul_pk2, NULL, keypair1->pk, keypair2->sk, ctx);

    // Compute r = H(pk1*pk2 || g^k*Y || m)
    unsigned char r_str[BN_LEN];
    compute_h_schnorr(group, pk1_mul_pk2, g_k_mul_Y, m, m_len, r_str);
    BN_bin2bn(r_str, BN_LEN, r);

    // Compute sk1 + sk2
    BN_add(sk1_plus_sk2, keypair1->sk, keypair2->sk);

    // Compute s = k + r*(sk1 + sk2)
    BIGNUM* r_mul_sk = BN_new();
    BN_mul(r_mul_sk, r, sk1_plus_sk2, ctx);
    BN_add(sig->s, k, r_mul_sk);

    // Free the memory
    BN_free(k);
    BN_free(r);
    BN_free(sk1_plus_sk2);
    EC_POINT_free(g_k);
    EC_POINT_free(g_k_mul_Y);
    EC_POINT_free(pk1_mul_pk2);
    EC_GROUP_free(group);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("pSign exc time: %f ms\n", elapsedTime);

    return sig;
}

int pVrfy(const char* m, const EC_POINT* Y, const Signature* sig, KeyPair* keypair1, KeyPair* keypair2, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);

    // Compute pk1 * pk2
    EC_POINT* pk1_mul_pk2 = EC_POINT_new(group);
    EC_POINT_mul(group, pk1_mul_pk2, NULL, keypair1->pk, keypair2->sk, ctx);

    // Compute g^s
    EC_POINT* g_s = EC_POINT_new(group);
    EC_POINT_mul(group, g_s, NULL, pp->g, sig->s, ctx);

    // Compute (pk1 * pk2)^(-r)
    EC_POINT* pk1_pk2_neg_r = EC_POINT_new(group);
    EC_POINT_mul(group, pk1_pk2_neg_r, NULL, pk1_mul_pk2, BN_mod_inverse(NULL, sig->r, pp->q, ctx), ctx);

    // Compute Y^r
    EC_POINT* Y_r = EC_POINT_new(group);
    EC_POINT_mul(group, Y_r, NULL, Y, sig->r, ctx);

    // Compute g^s * (pk1 * pk2)^(-r) * Y^r
    EC_POINT* hash_input = EC_POINT_new(group);
    EC_POINT_mul(group, hash_input, NULL, g_s, BN_value_one(), ctx);
    EC_POINT_add(group, hash_input, hash_input, pk1_pk2_neg_r, ctx);
    EC_POINT_add(group, hash_input, hash_input, Y_r, ctx);

    // Compute hash
    unsigned char r_prime_str[BN_LEN];
    compute_h_schnorr(group, pk1_mul_pk2, hash_input, m, strlen(m), r_prime_str);
    BIGNUM* r_prime = BN_new();
    BN_bin2bn(r_prime_str, BN_LEN, r_prime);

    // Compare r and r'
    int result = BN_cmp(sig->r, r_prime);

    // Clean up
    EC_GROUP_free(group);
    EC_POINT_free(pk1_mul_pk2);
    EC_POINT_free(g_s);
    EC_POINT_free(pk1_pk2_neg_r);
    EC_POINT_free(Y_r);
    EC_POINT_free(hash_input);
    BN_free(r_prime);
    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("pVry exc time: %f ms\n", elapsedTime);

    return result == 0 ? 1 : 0;
}

Signature* JSign(const char* m, KeyPair* keypair1, KeyPair* keypair2, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    Signature* sig = (Signature*)malloc(sizeof(Signature));
    sig->r = BN_new();
    sig->s = BN_new();

    BIGNUM* k = BN_new();
    BIGNUM* r = BN_new();
    BIGNUM* sk1_plus_sk2 = BN_new();
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT* g_k = EC_POINT_new(group);

    KeyPair keypair;
    keypair.sk = BN_new();
    keypair.pk = EC_POINT_new(group);

    BN_add(keypair.sk, keypair1->sk, keypair2->sk);
    EC_POINT_add(group, keypair.pk, keypair1->pk, keypair2->pk, NULL);

    // generate random k in Z_q
    BN_rand_range(k, pp->q);

    // compute g^k
    EC_POINT_mul(group, g_k, k, NULL, NULL, ctx);

    // compute r = H(pk1*pk2 || g^k || m)
    unsigned char r_str[BN_LEN];
    compute_h_schnorr(group, keypair.pk, g_k, m, strlen(m), r_str);
    BN_bin2bn(r_str, BN_LEN, r);

    // compute s = k + r*(sk1 + sk2)
    BIGNUM* r_mul_sk = BN_new();
    BN_mul(r_mul_sk, r, keypair.sk, ctx);
    BN_add(sig->s, k, r_mul_sk);

    BN_free(k);
    BN_free(r);
    EC_POINT_free(g_k);
    EC_GROUP_free(group);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("JSign exc time: %f ms\n", elapsedTime);

    return sig;
}

int JVrfy(const char* m, KeyPair* keypair1, KeyPair* keypair2, Signature* sig, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    int result = 0;

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT* hash_input = EC_POINT_new(group);
    EC_POINT* g_s = EC_POINT_new(group);
    EC_POINT* neg_r = EC_POINT_new(group);

    KeyPair keypair;
    keypair.sk = BN_new();
    keypair.pk = EC_POINT_new(group);

    BN_add(keypair.sk, keypair1->sk, keypair2->sk);
    EC_POINT_add(group, keypair.pk, keypair1->pk, keypair2->pk, NULL);

    // compute g^s
    EC_POINT_mul(group, g_s, sig->s, NULL, NULL, ctx);

    // compute (pk1 * pk2)^(-r)
    EC_POINT_invert(group, neg_r, ctx);
    EC_POINT_mul(group, neg_r, NULL, keypair.pk, sig->r, ctx);

    // compute g^s * (pk1 * pk2)^(-r)
    EC_POINT_add(group, hash_input, g_s, neg_r, ctx);

    // compute r' = H(pk1*pk2 || g^s * (pk1 * pk2)^(-r) || m)
    unsigned char r_prime_str[BN_LEN];
    compute_h_schnorr(group, keypair.pk, hash_input, m, strlen(m), r_prime_str);

    // convert r' to BIGNUM
    BIGNUM* r_prime = BN_new();
    BN_bin2bn(r_prime_str, BN_LEN, r_prime);

    // check if r = r'
    result = BN_cmp(sig->r, r_prime) == 0;

    EC_GROUP_free(group);
    EC_POINT_free(hash_input);
    EC_POINT_free(g_s);
    EC_POINT_free(neg_r);
    BN_free(r_prime);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("JVrify exc time: %f ms\n", elapsedTime);

    return result;
}

Signature* Adapt(Signature* sig_tilde, BIGNUM* y, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    Signature* sig = (Signature*)malloc(sizeof(Signature));
    sig->r = BN_new();
    sig->s = BN_new();

    // copy r from sig_tilde
    BN_copy(sig->r, sig_tilde->r);

    // compute s = s_tilde + y
    BN_add(sig->s, sig_tilde->s, y);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("Ada exc time: %f ms\n", elapsedTime);

    return sig;
}

BIGNUM* Ext(Signature* sig, Signature* sig_tilde, EC_POINT* Y, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    BIGNUM* y_prime = BN_new();
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT* Y_prime = EC_POINT_new(group);

    // compute y_prime = s - s_tilde
    BN_sub(y_prime, sig->s, sig_tilde->s);

    // compute Y_prime = g^{y_prime}
    EC_POINT_mul(group, Y_prime, y_prime, NULL, NULL, ctx);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("Ext exc time: %f ms\n", elapsedTime);

    // if Y_prime = Y, return y_prime, else return NULL
    if (EC_POINT_cmp(group, Y_prime, Y, ctx) == 0) {
        return y_prime;
    }
    else {
        BN_free(y_prime);
        return NULL;
    }
}

int c_size(Signature* sig) {
    int r_size = BN_num_bytes(sig->r);
    int s_size = BN_num_bytes(sig->s);
    return r_size + s_size;
}

void schnorr_test() {
    unsigned char message[MESSAGE_LENGTH];
    if (RAND_bytes(message, sizeof(message)) != 1) {
        printf("Error generating random message.\n");
        return 1;
    }

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    PublicParameters pp;

    pp.g = EC_POINT_new(group);
    pp.q = BN_new();

    const EC_POINT* generator = EC_GROUP_get0_generator(group);
    EC_POINT_copy(pp.g, generator);
    EC_GROUP_get_order(group, pp.q, NULL);

    BIGNUM* y = BN_new();
    EC_POINT* Y = EC_POINT_new(group);
    BN_rand_range(y, pp.q);
    EC_POINT_mul(group, Y, y, NULL, NULL, NULL);

    printf("-------------------------------------------\n");
    printf("Experiment for Schnorr Signature:\n");
    printf("\n");
    //KGen
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);

    QueryPerformanceCounter(&start);
    KeyPair keypair0 = generate_keypair(group, &pp);
    QueryPerformanceCounter(&end);

    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("KGen exc time: %f ms\n", elapsedTime);

    // Sign
    BN_CTX* ctx = BN_CTX_new();
    Signature* sig0 = Sign(message, &keypair0, &pp, ctx);
    BN_CTX_free(ctx);
    //printf("Size of sig: %d bytes\n", c_size(sig0));

    // Vry
    BN_CTX* ctx0 = BN_CTX_new();
    int* result0 = Vrfy(message, &keypair0, sig0, &pp, ctx0);
    BN_CTX_free(ctx0);

    printf("-------------------------------------------\n");
    printf("Experiment for 2PC_Schnorr Signature:\n");
    printf("\n");
    KeyPair keypair1 = generate_keypair(group, &pp);
    KeyPair keypair2 = generate_keypair(group, &pp);

    // JSign
    BN_CTX* ctx1 = BN_CTX_new();
    Signature* j_sig = JSign(message, &keypair1, &keypair2, &pp, ctx1);
    BN_CTX_free(ctx1);
    //printf("Size of j_sig: %d bytes\n", c_size(j_sig));

    // JVry
    BN_CTX* ctx2 = BN_CTX_new();
    int* result2 = JVrfy(message, &keypair1, &keypair2, j_sig, &pp, ctx2);
    BN_CTX_free(ctx2);

    printf("-------------------------------------------\n");
    printf("Experiment for Adapt_Schnorr Signature:\n");
    printf("\n");
    // PSign
    BN_CTX* ctx3 = BN_CTX_new();
    Signature* pre_sig = pSign(message, sizeof(message), Y, &keypair1, &keypair2, &pp, ctx3);
    BN_CTX_free(ctx3);
    //printf("Size of pre_sig: %d bytes\n", c_size(pre_sig));

    // Pvry
    BN_CTX* ctx4 = BN_CTX_new();
    int* result1 = pVrfy(message, Y, pre_sig, &keypair1, &keypair2, &pp, ctx4);
    BN_CTX_free(ctx4);

    // Adapt
    BN_CTX* ctx5 = BN_CTX_new();
    Signature* sig = Adapt(pre_sig, y, ctx5);
    BN_CTX_free(ctx5);
    //printf("Size of sig: %d bytes\n", c_size(sig));

    // Ext
    BN_CTX* ctx6 = BN_CTX_new();
    BIGNUM* y1 = Ext(sig, pre_sig, Y, ctx6);
    BN_CTX_free(ctx6);
    BN_free(y1);


    // Don't forget to free the memory
    BN_free(sig->r);
    BN_free(sig->s);
    free(sig);

    BN_free(pre_sig->r);
    BN_free(pre_sig->s);
    free(pre_sig);

    BN_free(sig0->r);
    BN_free(sig0->s);
    free(sig0);

    EC_POINT_free(Y);
    BN_free(y);
    EC_POINT_free(keypair2.pk);
    BN_free(keypair2.sk);
    EC_POINT_free(keypair1.pk);
    BN_free(keypair1.sk);
    EC_POINT_free(keypair0.pk);
    BN_free(keypair0.sk);

    BN_free(pp.q);
    EC_POINT_free(pp.g);
    EC_GROUP_free(group);
}

