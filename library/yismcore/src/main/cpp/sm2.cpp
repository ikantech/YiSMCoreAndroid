//
// Created by saint on 2020-07-16.
//

#include <cstring>
#include "sm2.h"
#include "YiCryptoTypes.h"

namespace yiim {

    EC_GROUP * EC_GROUP_new_sm2() {
        EC_GROUP *group = NULL;
        EC_POINT *P = NULL;
        BN_CTX *ctx = NULL;
        BIGNUM *p = NULL, *a = NULL, *b = NULL, *x = NULL, *y = NULL, *order =
                NULL;

        unsigned char params[192] = {
                /* no seed */

                /* p */
                0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                /* a */
                0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc,
                /* b */
                0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34, 0x4d, 0x5a, 0x9e, 0x4b,
                0xcf, 0x65, 0x09, 0xa7, 0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab, 0x8f, 0x92,
                0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0x0e, 0x93,
                /* x */
                0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19, 0x5f, 0x99, 0x04, 0x46,
                0x6a, 0x39, 0xc9, 0x94, 0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66, 0x0b, 0xe1,
                0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7,
                /* y */
                0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c, 0x59, 0xbd, 0xce, 0xe3,
                0x6b, 0x69, 0x21, 0x53, 0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40,
                0x02, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0,
                /* order */
                0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6, 0x05, 0x2b,
                0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5, 0x41, 0x23,
        };

        int seed_len = 0;
        int param_len = 32;
        int ok = 0;

        if ((ctx = BN_CTX_new()) == NULL) {
            goto err;
        }

        if ((p = BN_bin2bn(params + 0 * param_len, param_len, NULL)) == NULL
            || (a = BN_bin2bn(params + 1 * param_len, param_len, NULL)) == NULL
            || (b = BN_bin2bn(params + 2 * param_len, param_len, NULL)) == NULL) {
            goto err;
        }

        if ((group = EC_GROUP_new_curve_GFp(p, a, b, ctx)) == NULL) {
            goto err;
        }

//    EC_GROUP_set_curve_name(group, curve.nid);

        if ((P = EC_POINT_new(group)) == NULL) {
            goto err;
        }

        if ((x = BN_bin2bn(params + 3 * param_len, param_len, NULL)) == NULL
            || (y = BN_bin2bn(params + 4 * param_len, param_len, NULL)) == NULL) {
            goto err;
        }
        if (!EC_POINT_set_affine_coordinates(group, P, x, y, ctx)) {
            goto err;
        }
        if ((order = BN_bin2bn(params + 5 * param_len, param_len, NULL)) == NULL
            || !BN_set_word(x, (BN_ULONG)1)) {
            goto err;
        }
        if (!EC_GROUP_set_generator(group, P, order, x)) {
            goto err;
        }
        if (seed_len) {
            if (!EC_GROUP_set_seed(group, params - seed_len, seed_len)) {
                goto err;
            }
        }
        ok = 1;
        err:
        if (!ok) {
            EC_GROUP_free(group);
            group = NULL;
        }
        EC_POINT_free(P);
        BN_CTX_free(ctx);
        BN_free(p);
        BN_free(a);
        BN_free(b);
        BN_free(order);
        BN_free(x);
        BN_free(y);
        return group;
    }

    int sm2_setup_by_privkey(const EC_GROUP * group, EC_KEY * ecKey,
            const unsigned char *privKey, int key_len) {
        YiErrorCode ret = ERR_UNKNOWN;
        EC_POINT * ecPoint = NULL;
        do {
            EC_KEY_set_group(ecKey, group);

            if((ecPoint = EC_POINT_new(EC_KEY_get0_group(ecKey))) == NULL) {
                ret = ERR_ILLEGAL_KEY;
                break;
            }

            if(!EC_KEY_oct2priv(ecKey, privKey, key_len)) {
                ret = ERR_ILLEGAL_KEY;
                break;
            }

            if(EC_POINT_mul(EC_KEY_get0_group(ecKey), ecPoint, EC_KEY_get0_private_key(ecKey), NULL, NULL, NULL) == 0 ) {
                ret = ERR_ILLEGAL_KEY;
                break;
            }

            if(EC_KEY_set_public_key(ecKey, ecPoint) == 0) {
                ret = ERR_ILLEGAL_KEY;
                break;
            }

            if(EC_KEY_check_key(ecKey) == 0) {
                ret = ERR_ILLEGAL_KEY;
                break;
            }
            ret = ERR_OK;
        }while(0);
        if(NULL != ecPoint) {
            EC_POINT_free(ecPoint);
        }
        return ret;
    }

    int sm2_setup_by_pubkey(const EC_GROUP * group, EC_KEY * ecKey,
            const unsigned char *pubKey, int key_len) {
        YiErrorCode ret = ERR_UNKNOWN;
        do {
            EC_KEY_set_group(ecKey, group);

            if(!EC_KEY_oct2key(ecKey, pubKey, key_len, BN_CTX_new())) {
                ret = ERR_ILLEGAL_KEY;
                break;
            }

            if(!EC_KEY_check_key(ecKey)) {
                ret = ERR_ILLEGAL_KEY;
                break;
            }

            ret = ERR_OK;
        }while(0);
        return ret;
    }

    int sm2_gen_keypair(const EC_GROUP * group, EC_KEY * ecKey, unsigned char *out) {
        YiErrorCode ret = ERR_UNKNOWN;
        do {
            EC_KEY_set_group(ecKey, group);

            if(EC_KEY_generate_key(ecKey) == 0) {
                ret = ERR_GEN_KEYPAIR_FAILED;
                break;
            }

            if(NULL != out) {
                // get private key
                const BIGNUM *privateKey = EC_KEY_get0_private_key(ecKey);
                if (NULL == privateKey) {
                    ret = ERR_GEN_KEYPAIR_FAILED;
                    break;
                }
                BN_bn2binpad(privateKey, out, 32);
            }

            if(NULL != out) {
                // get public key
                const EC_POINT *point = EC_KEY_get0_public_key(ecKey);
                if (NULL == point) {
                    ret = ERR_GEN_KEYPAIR_FAILED;
                    break;
                }

                size_t pub_buf_len = 0;
                pub_buf_len = EC_POINT_point2oct(EC_KEY_get0_group(ecKey), point,
                                                 POINT_CONVERSION_HYBRID, out + 32, 65, BN_CTX_new());

                if (pub_buf_len == 0 || pub_buf_len != 65) {
                    ret = ERR_GEN_KEYPAIR_FAILED;
                    break;
                }
                out[32] -= 0x04;
            }

            ret = ERR_OK;
        }while(0);

        return ret;
    }

    static size_t ec_field_size(const EC_GROUP *group)
    {
        /* Is there some simpler way to do this? */
        BIGNUM *p = BN_new();
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        size_t field_size = 0;

        if (p == NULL || a == NULL || b == NULL)
            goto done;

        if (!EC_GROUP_get_curve(group, p, a, b, NULL))
            goto done;
        field_size = (BN_num_bits(p) + 7) / 8;

        done:
        BN_free(p);
        BN_free(a);
        BN_free(b);

        return field_size;
    }

    int sm2_encrypt(const EC_KEY *key,
                              const EVP_MD *digest,
                              const uint8_t *msg,
                              size_t msg_len, unsigned char * out)
    {
        int ret = ERR_CRYPT_FAILED;
        size_t i;
        BN_CTX *ctx = NULL;
        BIGNUM *k = NULL;
        BIGNUM *x1 = NULL;
        BIGNUM *y1 = NULL;
        BIGNUM *x2 = NULL;
        BIGNUM *y2 = NULL;
        EVP_MD_CTX *hash = EVP_MD_CTX_new();
        const EC_GROUP *group = EC_KEY_get0_group(key);
        const BIGNUM *order = EC_GROUP_get0_order(group);
        const EC_POINT *P = EC_KEY_get0_public_key(key);
        EC_POINT *kG = NULL;
        EC_POINT *kP = NULL;
        uint8_t *msg_mask = NULL;
        uint8_t *x2y2 = NULL;
        uint8_t *C3 = NULL;
        size_t field_size;
        const int C3_size = EVP_MD_size(digest);

        if (hash == NULL || C3_size <= 0) {
            goto done;
        }

        field_size = ec_field_size(group);
        if (field_size == 0) {
            goto done;
        }

        kG = EC_POINT_new(group);
        kP = EC_POINT_new(group);
        ctx = BN_CTX_new();
        if (kG == NULL || kP == NULL || ctx == NULL) {
            goto done;
        }

        BN_CTX_start(ctx);
        k = BN_CTX_get(ctx);
        x1 = BN_CTX_get(ctx);
        x2 = BN_CTX_get(ctx);
        y1 = BN_CTX_get(ctx);
        y2 = BN_CTX_get(ctx);

        if (y2 == NULL) {
            goto done;
        }

        x2y2 = (uint8_t *)OPENSSL_zalloc(2 * field_size);
        C3 = (uint8_t *)OPENSSL_zalloc(C3_size);

        if (x2y2 == NULL || C3 == NULL) {
            goto done;
        }

        if (!BN_priv_rand_range(k, order)) {
            goto done;
        }

        if (!EC_POINT_mul(group, kG, k, NULL, NULL, ctx)
            || !EC_POINT_get_affine_coordinates(group, kG, x1, y1, ctx)
            || !EC_POINT_mul(group, kP, NULL, P, k, ctx)
            || !EC_POINT_get_affine_coordinates(group, kP, x2, y2, ctx)) {
            goto done;
        }

        if (BN_bn2binpad(x2, x2y2, field_size) < 0
            || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0) {
            goto done;
        }

        msg_mask = (uint8_t *)OPENSSL_zalloc(msg_len);
        if (msg_mask == NULL) {
            goto done;
        }

        /* X9.63 with no salt happens to match the KDF used in SM2 */
        if (!ECDH_KDF_X9_62(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0,
                            digest)) {
            goto done;
        }

        for (i = 0; i != msg_len; ++i)
            msg_mask[i] ^= msg[i];

        if (EVP_DigestInit(hash, digest) == 0
            || EVP_DigestUpdate(hash, x2y2, field_size) == 0
            || EVP_DigestUpdate(hash, msg, msg_len) == 0
            || EVP_DigestUpdate(hash, x2y2 + field_size, field_size) == 0
            || EVP_DigestFinal(hash, C3, NULL) == 0) {
            goto done;
        }

        out[0] = 0x04;
        BN_bn2binpad(x1, out + 1, 32);
        BN_bn2binpad(y1, out + 33, 32);
        memcpy(out + 65, msg_mask, msg_len);
        memcpy(out + 65 + msg_len, C3, C3_size);

        ret = ERR_OK;

        done:
        OPENSSL_free(msg_mask);
        OPENSSL_free(x2y2);
        OPENSSL_free(C3);
        EVP_MD_CTX_free(hash);
        BN_CTX_free(ctx);
        EC_POINT_free(kG);
        EC_POINT_free(kP);
        return ret;
    }

    int sm2_decrypt(const EC_KEY *key,
                              const EVP_MD *digest,
                              const uint8_t *ciphertext,
                              size_t ciphertext_len, unsigned char * out)
    {
        int ret = ERR_CRYPT_FAILED;
        int i;
        BN_CTX *ctx = NULL;
        const EC_GROUP *group = EC_KEY_get0_group(key);
        EC_POINT *C1 = NULL;
        BIGNUM * x1 = NULL;
        BIGNUM * y1 = NULL;
        BIGNUM *x2 = NULL;
        BIGNUM *y2 = NULL;
        uint8_t *x2y2 = NULL;
        uint8_t *computed_C3 = NULL;
        const size_t field_size = ec_field_size(group);
        const int hash_size = EVP_MD_size(digest);
        uint8_t *msg_mask = NULL;
        const uint8_t *C2 = NULL;
        const uint8_t *C3 = NULL;
        int msg_len = 0;
        EVP_MD_CTX *hash = NULL;

        if (field_size == 0 || hash_size <= 0)
            goto done;

        msg_len = ciphertext_len - 97;
        C2 = ciphertext + 65;
        C3 = ciphertext + 65 + msg_len;

        ctx = BN_CTX_new();
        if (ctx == NULL) {
            goto done;
        }

        BN_CTX_start(ctx);
        x2 = BN_CTX_get(ctx);
        y2 = BN_CTX_get(ctx);
        x1 = BN_CTX_get(ctx);
        y1 = BN_CTX_get(ctx);

        BN_bin2bn(ciphertext + 1, 32, x1);
        BN_bin2bn(ciphertext + 33, 32, y1);

        if (y2 == NULL) {
            goto done;
        }

        msg_mask = (uint8_t *)OPENSSL_zalloc(msg_len);
        x2y2 = (uint8_t *)OPENSSL_zalloc(2 * field_size);
        computed_C3 = (uint8_t *)OPENSSL_zalloc(hash_size);

        if (msg_mask == NULL || x2y2 == NULL || computed_C3 == NULL) {
            goto done;
        }

        C1 = EC_POINT_new(group);
        if (C1 == NULL) {
            goto done;
        }

        if (!EC_POINT_set_affine_coordinates(group, C1, x1, y1, ctx)
            || !EC_POINT_mul(group, C1, NULL, C1, EC_KEY_get0_private_key(key), ctx)
            || !EC_POINT_get_affine_coordinates(group, C1, x2, y2, ctx)) {
            goto done;
        }

        if (BN_bn2binpad(x2, x2y2, field_size) < 0
            || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0
            || !ECDH_KDF_X9_62(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0,
                               digest)) {
            goto done;
        }

        for (i = 0; i != msg_len; ++i)
            out[i] = C2[i] ^ msg_mask[i];

        hash = EVP_MD_CTX_new();
        if (hash == NULL) {
            goto done;
        }

        if (!EVP_DigestInit(hash, digest)
            || !EVP_DigestUpdate(hash, x2y2, field_size)
            || !EVP_DigestUpdate(hash, out, msg_len)
            || !EVP_DigestUpdate(hash, x2y2 + field_size, field_size)
            || !EVP_DigestFinal(hash, computed_C3, NULL)) {
            goto done;
        }

        if (CRYPTO_memcmp(computed_C3, C3, hash_size) != 0) {
            goto done;
        }

        ret = ERR_OK;

        done:
        OPENSSL_free(msg_mask);
        OPENSSL_free(x2y2);
        OPENSSL_free(computed_C3);
        EC_POINT_free(C1);
        BN_CTX_free(ctx);
        EVP_MD_CTX_free(hash);

        return ret;
    }

    static int ec_field_inverse_mod_ord(const EC_GROUP *group, BIGNUM *r,
                                        const BIGNUM *x, BN_CTX *ctx)
    {
        BIGNUM *e = NULL;
        BN_CTX *new_ctx = NULL;
        int ret = 0;

        BN_MONT_CTX * mont_data = EC_GROUP_get_mont_data(group);
        const BIGNUM * order = EC_GROUP_get0_order(group);
        if (mont_data == NULL)
            return 0;

        if (ctx == NULL && (ctx = new_ctx = BN_CTX_secure_new()) == NULL)
            return 0;

        BN_CTX_start(ctx);
        if ((e = BN_CTX_get(ctx)) == NULL)
            goto err;

        /*-
         * We want inverse in constant time, therefore we utilize the fact
         * order must be prime and use Fermats Little Theorem instead.
         */
        if (!BN_set_word(e, 2))
            goto err;
        if (!BN_sub(e, order, e))
            goto err;
        /*-
         * Exponent e is public.
         * No need for scatter-gather or BN_FLG_CONSTTIME.
         */
        if (!BN_mod_exp_mont(r, x, e, order, ctx, mont_data))
            goto err;

        ret = 1;

        err:
        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);
        return ret;
    }

    static int yi_sm2_compute_z_digest(uint8_t *out,
                                       const EVP_MD *digest,
                                       const uint8_t *id,
                                       const size_t id_len,
                                       const EC_KEY *key)
    {
        int rc = 0;
        const EC_GROUP *group = EC_KEY_get0_group(key);
        BN_CTX *ctx = NULL;
        EVP_MD_CTX *hash = NULL;
        BIGNUM *p = NULL;
        BIGNUM *a = NULL;
        BIGNUM *b = NULL;
        BIGNUM *xG = NULL;
        BIGNUM *yG = NULL;
        BIGNUM *xA = NULL;
        BIGNUM *yA = NULL;
        int p_bytes = 0;
        uint8_t *buf = NULL;
        uint16_t entl = 0;
        uint8_t e_byte = 0;

        hash = EVP_MD_CTX_new();
        ctx = BN_CTX_new();
        if (hash == NULL || ctx == NULL) {
            goto done;
        }

        p = BN_CTX_get(ctx);
        a = BN_CTX_get(ctx);
        b = BN_CTX_get(ctx);
        xG = BN_CTX_get(ctx);
        yG = BN_CTX_get(ctx);
        xA = BN_CTX_get(ctx);
        yA = BN_CTX_get(ctx);

        if (yA == NULL) {
            goto done;
        }

        if (!EVP_DigestInit(hash, digest)) {
            goto done;
        }

        /* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */

        if (id_len >= (UINT16_MAX / 8)) {
            /* too large */
            goto done;
        }

        entl = (uint16_t)(8 * id_len);

        e_byte = entl >> 8;
        if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
            goto done;
        }
        e_byte = entl & 0xFF;
        if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
            goto done;
        }

        if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
            goto done;
        }

        if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
            goto done;
        }

        p_bytes = BN_num_bytes(p);
        buf = (uint8_t *)OPENSSL_zalloc(p_bytes);
        if (buf == NULL) {
            goto done;
        }

        if (BN_bn2binpad(a, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(b, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EC_POINT_get_affine_coordinates(group,
                                                EC_GROUP_get0_generator(group),
                                                xG, yG, ctx)
            || BN_bn2binpad(xG, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(yG, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EC_POINT_get_affine_coordinates(group,
                                                EC_KEY_get0_public_key(key),
                                                xA, yA, ctx)
            || BN_bn2binpad(xA, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(yA, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EVP_DigestFinal(hash, out, NULL)) {
            goto done;
        }

        rc = 1;

        done:
        OPENSSL_free(buf);
        BN_CTX_free(ctx);
        EVP_MD_CTX_free(hash);
        return rc;
    }

    static BIGNUM *sm2_compute_msg_hash(const EVP_MD *digest,
                                        const EC_KEY *key,
                                        const uint8_t *id,
                                        const size_t id_len,
                                        const uint8_t *msg, size_t msg_len)
    {
        EVP_MD_CTX *hash = EVP_MD_CTX_new();
        const int md_size = EVP_MD_size(digest);
        uint8_t *z = NULL;
        BIGNUM *e = NULL;

        if (md_size < 0) {
            goto done;
        }

        z = (uint8_t *)OPENSSL_zalloc(md_size);
        if (hash == NULL || z == NULL) {
            goto done;
        }

        if (!yi_sm2_compute_z_digest(z, digest, id, id_len, key)) {
            /* SM2err already called */
            goto done;
        }

        if (!EVP_DigestInit(hash, digest)
            || !EVP_DigestUpdate(hash, z, md_size)
            || !EVP_DigestUpdate(hash, msg, msg_len)
            /* reuse z buffer to hold H(Z || M) */
            || !EVP_DigestFinal(hash, z, NULL)) {
            goto done;
        }

        e = BN_bin2bn(z, md_size, NULL);

        done:
        OPENSSL_free(z);
        EVP_MD_CTX_free(hash);
        return e;
    }

    static int sm2_sig_gen(const EC_KEY *key, const BIGNUM *e, unsigned char * out)
    {
        const BIGNUM *dA = EC_KEY_get0_private_key(key);
        const EC_GROUP *group = EC_KEY_get0_group(key);
        const BIGNUM *order = EC_GROUP_get0_order(group);
        EC_POINT *kG = NULL;
        BN_CTX *ctx = NULL;
        BIGNUM *k = NULL;
        BIGNUM *rk = NULL;
        BIGNUM *r = NULL;
        BIGNUM *s = NULL;
        BIGNUM *x1 = NULL;
        BIGNUM *tmp = NULL;
        int ret = 0;

        kG = EC_POINT_new(group);
        ctx = BN_CTX_new();
        if (kG == NULL || ctx == NULL) {
            goto done;
        }

        BN_CTX_start(ctx);
        k = BN_CTX_get(ctx);
        rk = BN_CTX_get(ctx);
        x1 = BN_CTX_get(ctx);
        tmp = BN_CTX_get(ctx);
        if (tmp == NULL) {
            goto done;
        }

        /*
         * These values are returned and so should not be allocated out of the
         * context
         */
        r = BN_new();
        s = BN_new();

        if (r == NULL || s == NULL) {
            goto done;
        }

        for (;;) {
            if (!BN_priv_rand_range(k, order)) {
                goto done;
            }

            if (!EC_POINT_mul(group, kG, k, NULL, NULL, ctx)
                || !EC_POINT_get_affine_coordinates(group, kG, x1, NULL,
                                                    ctx)
                || !BN_mod_add(r, e, x1, order, ctx)) {
                goto done;
            }

            /* try again if r == 0 or r+k == n */
            if (BN_is_zero(r))
                continue;

            if (!BN_add(rk, r, k)) {
                goto done;
            }

            if (BN_cmp(rk, order) == 0)
                continue;

            if (!BN_add(s, dA, BN_value_one())
                || !ec_field_inverse_mod_ord(group, s, s, ctx)
                || !BN_mod_mul(tmp, dA, r, order, ctx)
                || !BN_sub(tmp, k, tmp)
                || !BN_mod_mul(s, s, tmp, order, ctx)) {
                goto done;
            }
            break;
        }
        ret = 1;
        BN_bn2binpad(r, out, 32);
        BN_bn2binpad(s, out + 32, 32);

        done:
        BN_free(r);
        BN_free(s);

        BN_CTX_free(ctx);
        EC_POINT_free(kG);
        return ret;
    }

    static int sm2_sig_verify(const EC_KEY *key, const uint8_t *sig,
                              const BIGNUM *e)
    {
        int ret = 0;
        const EC_GROUP *group = EC_KEY_get0_group(key);
        const BIGNUM *order = EC_GROUP_get0_order(group);
        BN_CTX *ctx = NULL;
        EC_POINT *pt = NULL;
        BIGNUM *t = NULL;
        BIGNUM *x1 = NULL;
        BIGNUM *r = NULL;
        BIGNUM *s = NULL;

        ctx = BN_CTX_new();
        pt = EC_POINT_new(group);
        if (ctx == NULL || pt == NULL) {
            goto done;
        }

        BN_CTX_start(ctx);
        t = BN_CTX_get(ctx);
        r = BN_CTX_get(ctx);
        s = BN_CTX_get(ctx);
        x1 = BN_CTX_get(ctx);
        if (x1 == NULL) {
            goto done;
        }

        /*
         * B1: verify whether r' in [1,n-1], verification failed if not
         * B2: verify whether s' in [1,n-1], verification failed if not
         * B3: set M'~=ZA || M'
         * B4: calculate e'=Hv(M'~)
         * B5: calculate t = (r' + s') modn, verification failed if t=0
         * B6: calculate the point (x1', y1')=[s']G + [t]PA
         * B7: calculate R=(e'+x1') modn, verification pass if yes, otherwise failed
         */

        BN_bin2bn(sig, 32, r);
        BN_bin2bn(sig + 32, 32, s);

        if (BN_cmp(r, BN_value_one()) < 0
            || BN_cmp(s, BN_value_one()) < 0
            || BN_cmp(order, r) <= 0
            || BN_cmp(order, s) <= 0) {
            goto done;
        }

        if (!BN_mod_add(t, r, s, order, ctx)) {
            goto done;
        }

        if (BN_is_zero(t)) {
            goto done;
        }

        if (!EC_POINT_mul(group, pt, s, EC_KEY_get0_public_key(key), t, ctx)
            || !EC_POINT_get_affine_coordinates(group, pt, x1, NULL, ctx)) {
            goto done;
        }

        if (!BN_mod_add(t, e, x1, order, ctx)) {
            goto done;
        }

        if (BN_cmp(r, t) == 0)
            ret = 1;

        done:
        EC_POINT_free(pt);
        BN_CTX_free(ctx);
        return ret;
    }

    int sm2_do_sign(const EC_KEY *key,
                              const EVP_MD *digest,
                              const uint8_t *id,
                              const size_t id_len,
                              const uint8_t *msg, size_t msg_len, unsigned char * out)
    {
        BIGNUM *e = NULL;
        int ret = 0;

        e = sm2_compute_msg_hash(digest, key, id, id_len, msg, msg_len);
        if (e == NULL) {
            /* SM2err already called */
            goto done;
        }

        ret = sm2_sig_gen(key, e, out);

        done:
        BN_free(e);
        return ret;
    }

    int sm2_do_verify(const EC_KEY *key,
                                const EVP_MD *digest,
                                const uint8_t *sig,
                                const uint8_t *id,
                                const size_t id_len,
                                const uint8_t *msg, size_t msg_len)
    {
        BIGNUM *e = NULL;
        int ret = 0;

        e = sm2_compute_msg_hash(digest, key, id, id_len, msg, msg_len);
        if (e == NULL) {
            /* SM2err already called */
            goto done;
        }

        ret = sm2_sig_verify(key, sig, e);

        done:
        BN_free(e);
        return ret;
    }
}