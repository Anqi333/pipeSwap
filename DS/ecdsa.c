#include "ecdsa.h"

KeyPair e_generate_keypair(EC_GROUP* group, PublicParameters* pp) {
    KeyPair keypair;
    keypair.sk = BN_new();
    keypair.pk = EC_POINT_new(group);

    // Generate a random big number in the range [1, q-1] as the private key sk
    BN_rand_range(keypair.sk, pp->q);

    // Compute the public key pk = g^sk
    EC_POINT_mul(group, keypair.pk, keypair.sk, NULL, NULL, NULL);

    return keypair;
}

Signature* e_Sign(const char* m, KeyPair* keypair, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    Signature* sig = (Signature*)malloc(sizeof(Signature));
    sig->r = BN_new();
    sig->s = BN_new();

    BIGNUM* k = BN_new();
    BIGNUM* k_inverse = BN_new();
    BIGNUM* hash_m = BN_new();
    BIGNUM* r_sk = BN_new();
    EC_POINT* g_k = EC_POINT_new(pp->group);
    BIGNUM* x_coord = BN_new();
    BIGNUM* y_coord = BN_new();  // We won't actually use this, but it's needed for the function call

    // generate random k in Z_q
    BN_rand_range(k, pp->q);

    // compute g^k
    EC_POINT_mul(pp->group, g_k, k, NULL, NULL, ctx);

    // compute f(g^k) = x-coordinate of g^k
    EC_POINT_get_affine_coordinates_GFp(pp->group, g_k, x_coord, y_coord, ctx);
    BN_copy(sig->r, x_coord);

    // compute k^-1
    BN_mod_inverse(k_inverse, k, pp->q, ctx);

    // compute H(m)
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)m, strlen(m), hash);
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, hash_m);

    // compute r*sk
    BN_mul(r_sk, sig->r, keypair->sk, ctx);

    // compute s = k^-1 * (H(m) + r*sk)
    BIGNUM* temp = BN_new();
    BN_add(temp, hash_m, r_sk);
    BN_mul(sig->s, k_inverse, temp, ctx);

    BN_free(k);
    BN_free(k_inverse);
    BN_free(hash_m);
    BN_free(r_sk);
    EC_POINT_free(g_k);
    BN_free(x_coord);
    BN_free(y_coord);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("Sign exc time: %f ms\n", elapsedTime);

    return sig;
}

int e_Vrfy(const char* m, KeyPair* keypair, Signature* sig, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    int result = 0;

    // Compute s^{-1}
    BIGNUM* s_inv = BN_new();
    BN_mod_inverse(s_inv, sig->s, pp->q, ctx);

    // Compute s^{-1} * H(m)
    BIGNUM* s_inv_mul_Hm = BN_new();
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)m, strlen(m), hash);
    BIGNUM* Hm = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL);
    BN_mod_mul(s_inv_mul_Hm, s_inv, Hm, pp->q, ctx);

    // Compute s^{-1} * r
    BIGNUM* s_inv_mul_r = BN_new();
    BN_mod_mul(s_inv_mul_r, s_inv, sig->r, pp->q, ctx);

    // Compute g^{s^{-1} * H(m)}
    EC_POINT* g_s_inv_mul_Hm = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, g_s_inv_mul_Hm, s_inv_mul_Hm, NULL, NULL, ctx);

    // Compute pk^{s^{-1} * r}
    EC_POINT* pk_s_inv_mul_r = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, pk_s_inv_mul_r, NULL, keypair->pk, s_inv_mul_r, ctx);

    // Compute g^{s^{-1} * H(m)} * pk^{s^{-1} * r}
    EC_POINT* verification = EC_POINT_new(pp->group);
    EC_POINT_add(pp->group, verification, g_s_inv_mul_Hm, pk_s_inv_mul_r, ctx);

    // Compute f(verification) as the x-coordinate of verification
    BIGNUM* x_coordinate = BN_new();
    EC_POINT_get_affine_coordinates_GFp(pp->group, verification, x_coordinate, NULL, ctx);

    // Check if r is equal to f(verification)
    if (BN_cmp(sig->r, x_coordinate) == 0) {
        result = 1;
    }

    // Free memory
    BN_free(s_inv);
    BN_free(s_inv_mul_Hm);
    BN_free(Hm);
    BN_free(s_inv_mul_r);
    EC_POINT_free(g_s_inv_mul_Hm);
    EC_POINT_free(pk_s_inv_mul_r);
    EC_POINT_free(verification);
    BN_free(x_coordinate);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("Vrfy exc time: %f ms\n", elapsedTime);

    return result;
}

Signature* e_JSign(const char* m, EC_GROUP* group, KeyPair* keypair1, KeyPair* keypair2, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    KeyPair keypair;
    keypair.sk = BN_new();
    keypair.pk = EC_POINT_new(group);
    BN_add(keypair.sk, keypair1->sk, keypair2->sk);
    EC_POINT_add(group, keypair.pk, keypair1->pk, keypair2->pk, NULL);

    Signature* sig = (Signature*)malloc(sizeof(Signature));
    sig->r = BN_new();
    sig->s = BN_new();

    BIGNUM* k = BN_new();
    BIGNUM* k_inverse = BN_new();
    BIGNUM* hash_m = BN_new();
    BIGNUM* r_sk = BN_new();
    EC_POINT* g_k = EC_POINT_new(pp->group);
    BIGNUM* x_coord = BN_new();
    BIGNUM* y_coord = BN_new(); 

    // generate random k in Z_q
    BN_rand_range(k, pp->q);

    // compute g^k
    EC_POINT_mul(pp->group, g_k, k, NULL, NULL, ctx);

    // compute f(g^k) = x-coordinate of g^k
    EC_POINT_get_affine_coordinates_GFp(pp->group, g_k, x_coord, y_coord, ctx);
    BN_copy(sig->r, x_coord);

    // compute k^-1
    BN_mod_inverse(k_inverse, k, pp->q, ctx);

    // compute H(m)
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)m, strlen(m), hash);
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, hash_m);

    // compute r*sk
    BN_mul(r_sk, sig->r, keypair.sk, ctx);

    // compute s = k^-1 * (H(m) + r*sk)
    BIGNUM* temp = BN_new();
    BN_add(temp, hash_m, r_sk);
    BN_mul(sig->s, k_inverse, temp, ctx);

    BN_free(k);
    BN_free(k_inverse);
    BN_free(hash_m);
    BN_free(r_sk);
    EC_POINT_free(g_k);
    BN_free(x_coord);
    BN_free(y_coord);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("JSign exc time: %f ms\n", elapsedTime);

    return sig;
}

int e_JVrfy(const char* m, EC_GROUP* group, KeyPair* keypair1, KeyPair* keypair2, Signature* sig, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    int result = 0;

    KeyPair keypair;
    keypair.sk = BN_new();
    keypair.pk = EC_POINT_new(group);
    BN_add(keypair.sk, keypair1->sk, keypair2->sk);
    EC_POINT_add(group, keypair.pk, keypair1->pk, keypair2->pk, NULL);

    // Compute s^{-1}
    BIGNUM* s_inv = BN_new();
    BN_mod_inverse(s_inv, sig->s, pp->q, ctx);

    // Compute s^{-1} * H(m)
    BIGNUM* s_inv_mul_Hm = BN_new();
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)m, strlen(m), hash);
    BIGNUM* Hm = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL);
    BN_mod_mul(s_inv_mul_Hm, s_inv, Hm, pp->q, ctx);

    // Compute s^{-1} * r
    BIGNUM* s_inv_mul_r = BN_new();
    BN_mod_mul(s_inv_mul_r, s_inv, sig->r, pp->q, ctx);

    // Compute g^{s^{-1} * H(m)}
    EC_POINT* g_s_inv_mul_Hm = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, g_s_inv_mul_Hm, s_inv_mul_Hm, NULL, NULL, ctx);

    // Compute pk^{s^{-1} * r}
    EC_POINT* pk_s_inv_mul_r = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, pk_s_inv_mul_r, NULL, keypair.pk, s_inv_mul_r, ctx);

    // Compute g^{s^{-1} * H(m)} * pk^{s^{-1} * r}
    EC_POINT* verification = EC_POINT_new(pp->group);
    EC_POINT_add(pp->group, verification, g_s_inv_mul_Hm, pk_s_inv_mul_r, ctx);

    // Compute f(verification) as the x-coordinate of verification
    BIGNUM* x_coordinate = BN_new();
    EC_POINT_get_affine_coordinates_GFp(pp->group, verification, x_coordinate, NULL, ctx);

    // Check if r is equal to f(verification)
    if (BN_cmp(sig->r, x_coordinate) == 0) {
        result = 1;
    }

    // Free memory
    BN_free(s_inv);
    BN_free(s_inv_mul_Hm);
    BN_free(Hm);
    BN_free(s_inv_mul_r);
    EC_POINT_free(g_s_inv_mul_Hm);
    EC_POINT_free(pk_s_inv_mul_r);
    EC_POINT_free(verification);
    BN_free(x_coordinate);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("JVrfy exc time: %f ms\n", elapsedTime);

    return result;
}

Pre_Signature* e_PSign(const char* m, EC_GROUP* group, KeyPair* keypair1, KeyPair* keypair2, const EC_POINT* Y, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    KeyPair keypair;
    keypair.sk = BN_new();
    keypair.pk = EC_POINT_new(group);
    BN_add(keypair.sk, keypair1->sk, keypair2->sk);
    EC_POINT_add(group, keypair.pk, keypair1->pk, keypair2->pk, NULL);

    Pre_Signature* pre_sig = (Pre_Signature*)malloc(sizeof(Pre_Signature));
    pre_sig->r = BN_new();
    pre_sig->s = BN_new();
    pre_sig->K = EC_POINT_new(pp->group);

    // Generate random k in Z_q
    BIGNUM* k = BN_new();
    BN_rand_range(k, pp->q);

    // Compute g^k
    EC_POINT* g_k = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, g_k, k, NULL, NULL, ctx);

    // Compute Y^k
    EC_POINT* Y_k = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, Y_k, NULL, Y, k, ctx);

    // Compute r = f(K)
    BIGNUM* x_coord = BN_new();
    BIGNUM* y_coord = BN_new();
    if (EC_POINT_get_affine_coordinates_GFp(pp->group, Y_k, x_coord, y_coord, ctx)) {
        // Compute r = x_coord mod q
        BN_mod(pre_sig->r, x_coord, pp->q, ctx);
    }
    else {
        // Handle error
        printf("Error computing f(K)\n");
        exit(1);
    }

    // Compute H(m)
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)m, strlen(m), hash);
    BIGNUM* Hm = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL);

    // Compute k^(-1)
    BIGNUM* k_inv = BN_new();
    BN_mod_inverse(k_inv, k, pp->q, ctx);

    // Compute s = k^(-1) * (H(m) + r*sk)
    BIGNUM* temp = BN_new();
    BN_mod_mul(temp, pre_sig->r, keypair.sk, pp->q, ctx);  // temp = r*sk
    BN_add(temp, Hm, temp);  // temp = H(m) + r*sk
    BN_mod_mul(pre_sig->s, k_inv, temp, pp->q, ctx);  // s = k^(-1) * temp

    // Copy Y_k to K
    EC_POINT_copy(pre_sig->K, Y_k);

    // Free allocated memory
    BN_free(k);
    EC_POINT_free(g_k);
    EC_POINT_free(Y_k);
    BN_free(Hm);
    BN_free(k_inv);
    BN_free(temp);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("PSign exc time: %f ms\n", elapsedTime);

    return pre_sig;
}

int e_PVrfy(const char* m, EC_GROUP* group, KeyPair* keypair1, KeyPair* keypair2, Pre_Signature* pre_sig, const EC_POINT* Y, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    KeyPair keypair;
    keypair.sk = BN_new();
    keypair.pk = EC_POINT_new(group);
    BN_add(keypair.sk, keypair1->sk, keypair2->sk);
    EC_POINT_add(group, keypair.pk, keypair1->pk, keypair2->pk, NULL);

    int result = 0;

    // Compute s_inv = s^-1 mod q
    BIGNUM* s_inv = BN_new();
    BN_mod_inverse(s_inv, pre_sig->s, pp->q, ctx);

    // Compute H(m)
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)m, strlen(m), hash);
    BIGNUM* Hm = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL);

    // Compute u = H(m) * s_inv mod q
    BIGNUM* u = BN_new();
    BN_mod_mul(u, Hm, s_inv, pp->q, ctx);

    // Compute v = r * s_inv mod q
    BIGNUM* v = BN_new();
    BN_mod_mul(v, pre_sig->r, s_inv, pp->q, ctx);

    // Compute g^u
    EC_POINT* g_u = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, g_u, u, NULL, NULL, ctx);

    // Compute pk^v
    EC_POINT* pk_v = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, pk_v, NULL, keypair.pk, v, ctx);

    // Compute K' = g^u * pk^v
    EC_POINT* K_prime = EC_POINT_new(pp->group);
    EC_POINT_add(pp->group, K_prime, g_u, pk_v, ctx);

    // Compute f(K')
    BIGNUM* x_coord = BN_new();
    BIGNUM* y_coord = BN_new();
    if (EC_POINT_get_affine_coordinates_GFp(pp->group, K_prime, x_coord, y_coord, ctx)) {
        // Compute f_K_prime = x_coord mod q
        BIGNUM* f_K_prime = BN_new();
        BN_mod(f_K_prime, x_coord, pp->q, ctx);

        // Check if r == f(K')
        if (BN_cmp(pre_sig->r, f_K_prime) == 0) {
            result = 1;
        }

        BN_free(f_K_prime);
    }
    else {
        // Handle error
        printf("Error computing f(K')\n");
        exit(1);
    }

    // Free memory
    BN_free(s_inv);
    BN_free(Hm);
    BN_free(u);
    BN_free(v);
    EC_POINT_free(g_u);
    EC_POINT_free(pk_v);
    EC_POINT_free(K_prime);
    BN_free(x_coord);
    BN_free(y_coord);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("PVry exc time: %f ms\n", elapsedTime);

    return result;
}

Signature* e_Adapt(Pre_Signature* pre_sig, BIGNUM* y, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    Signature* sig = (Signature*)malloc(sizeof(Signature));
    sig->r = BN_new();
    sig->s = BN_new();

    // Compute y_inv = y^-1 mod q
    BIGNUM* y_inv = BN_new();
    BN_mod_inverse(y_inv, y, pp->q, ctx);

    // Compute s = s_tilde * y_inv mod q
    BN_mod_mul(sig->s, pre_sig->s, y_inv, pp->q, ctx);

    // Copy r from pre_sig to sig
    BN_copy(sig->r, pre_sig->r);

    // Free memory
    BN_free(y_inv);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("Ada exc time: %f ms\n", elapsedTime);

    return sig;
}

BIGNUM* e_Ext(Signature* sig, Pre_Signature* pre_sig, EC_POINT* Y, PublicParameters* pp, BN_CTX* ctx) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    BIGNUM* y_prime = NULL;

    // Compute s_inv = s^-1 mod q
    BIGNUM* s_inv = BN_new();
    BN_mod_inverse(s_inv, sig->s, pp->q, ctx);

    // Compute y_prime = s_inv * s_tilde mod q
    y_prime = BN_new();
    BN_mod_mul(y_prime, s_inv, pre_sig->s, pp->q, ctx);

    // Compute Y_prime = g^y_prime
    EC_POINT* Y_prime = EC_POINT_new(pp->group);
    EC_POINT_mul(pp->group, Y_prime, y_prime, NULL, NULL, ctx);

    // If Y != Y_prime, set y_prime to NULL
    if (EC_POINT_cmp(pp->group, Y, Y_prime, ctx) != 0) {
        BN_free(y_prime);
        y_prime = NULL;
    }

    // Free memory
    BN_free(s_inv);
    EC_POINT_free(Y_prime);

    QueryPerformanceCounter(&end);
    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("Ext exc time: %f ms\n", elapsedTime);

    return y_prime;
}

int e_c_size(Signature* sig) {
    int r_size = BN_num_bytes(sig->r);
    int s_size = BN_num_bytes(sig->s);
    return r_size + s_size;
}

int e_c_pre_size(Pre_Signature* pre_sig) {
    int r_size = BN_num_bytes(pre_sig->r);
    int s_size = BN_num_bytes(pre_sig->s);
    int K_size = BN_num_bytes(pre_sig->K);
    return (r_size + s_size + K_size);
}

void ecdsa_test() {
    unsigned char message[MESSAGE_LENGTH];
    if (RAND_bytes(message, sizeof(message)) != 1) {
        printf("Error generating random message.\n");
        return 1;
    }

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    PublicParameters pp;

    pp.group = group;
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
    printf("Experiment for ECDSA Signature:\n");
    printf("\n");
    //KGen
    LARGE_INTEGER frequency;
    LARGE_INTEGER start, end;
    double elapsedTime;
    QueryPerformanceFrequency(&frequency);

    QueryPerformanceCounter(&start);
    KeyPair keypair0 = e_generate_keypair(group, &pp);
    QueryPerformanceCounter(&end);

    elapsedTime = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    printf("KGen exc time: %f ms\n", elapsedTime);

    //Sign
    BN_CTX* ctx = BN_CTX_new();
    Signature* sig = e_Sign(message, &keypair0, &pp, ctx);
    BN_CTX_free(ctx);

    //Vrfy
    BN_CTX* ctx0 = BN_CTX_new();
    int result = e_Vrfy(message, &keypair0, sig, &pp, ctx0);
    BN_CTX_free(ctx0);

    printf("-------------------------------------------\n");
    printf("Experiment for 2PC_ECDSA Signature:\n");
    printf("\n");
    KeyPair keypair1 = e_generate_keypair(group, &pp);
    KeyPair keypair2 = e_generate_keypair(group, &pp);
    // JSign
    BN_CTX* ctx1 = BN_CTX_new();
    Signature* j_sig = e_JSign(message, group, &keypair1, &keypair2, &pp, ctx1);
    //printf("Size of j_sig: %d bytes\n", e_c_size(j_sig));
    BN_CTX_free(ctx1);

    // JVry
    BN_CTX* ctx2 = BN_CTX_new();
    int result1 = e_JVrfy(message, group, &keypair1, &keypair2, j_sig, &pp, ctx2);
    BN_CTX_free(ctx2);

    printf("-------------------------------------------\n");
    printf("Experiment for Adapt_ECDSA Signature:\n");
    printf("\n");
    // PSign
    BN_CTX* ctx3 = BN_CTX_new();
    Pre_Signature* pre_sig = e_PSign(message, group, &keypair1, &keypair2, Y, &pp, ctx3);
    //printf("Size of pre_sig: %d bytes\n", e_c_pre_size(pre_sig));
    BN_CTX_free(ctx3);

    // PVry
    BN_CTX* ctx4 = BN_CTX_new();
    int result2 = e_PVrfy(message, group, &keypair1, &keypair2, pre_sig, Y, &pp, ctx4);
    BN_CTX_free(ctx4);

    // Adapt
    BN_CTX* ctx5 = BN_CTX_new();
    Signature* sig1 = e_Adapt(pre_sig, y, &pp, ctx5);
    //printf("Size of sig: %d bytes\n", e_c_size(sig1));
    BN_CTX_free(ctx5);

    // Ext
    BN_CTX* ctx6 = BN_CTX_new();
    BIGNUM* y1 = e_Ext(sig1, pre_sig, Y, &pp, ctx6);
    BN_CTX_free(ctx6);
    BN_free(y1);

    BN_free(sig1->r);
    BN_free(sig1->s);
    free(sig1);

    BN_free(pre_sig->K);
    BN_free(pre_sig->r);
    BN_free(pre_sig->s);
    free(pre_sig);

    BN_free(j_sig->r);
    BN_free(j_sig->s);
    free(j_sig);

    BN_free(sig->r);
    BN_free(sig->s);
    free(sig);

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