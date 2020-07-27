#include <jni.h>
#include <string>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include "YiCryptoTypes.h"
#include "sm2.h"
#include "rsa.h"

using namespace yiim;

typedef union {
    JNIEnv* env;
    void* venv;
} UnionJNIEnvToVoid;

static EC_GROUP * default_ec_group = NULL;

extern "C"
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    UnionJNIEnvToVoid global;

    global.venv = NULL;

    if (vm->GetEnv(&global.venv, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    // create ec group
    default_ec_group = EC_GROUP_new_sm2();

    return JNI_VERSION_1_6;
}

extern "C"
JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void* reserved) {
    JNIEnv* env = NULL;

    if (vm->GetEnv((void**) &env, JNI_VERSION_1_6) != JNI_OK) {
        return;
    }

    // destroy ec group
    if(NULL != default_ec_group) {
        EC_GROUP_free(default_ec_group);
        default_ec_group = NULL;
    }
}

static const EVP_MD * getEVPMDByNid(int algorithm) {
    const EVP_MD * digest = NULL;
    if(algorithm == NID_md5) {
        digest = EVP_md5();
    }else if(algorithm == NID_sha1) {
        digest = EVP_sha1();
    }else if(algorithm == NID_sha224) {
        digest = EVP_sha224();
    } else if(algorithm == NID_sha256) {
        digest = EVP_sha256();
    }else if(algorithm == NID_sha384) {
        digest = EVP_sha384();
    }else if(algorithm == NID_sha512) {
        digest = EVP_sha512();
    }else if(algorithm == NID_sha3_224) {
        digest = EVP_sha3_224();
    }else if(algorithm == NID_sha3_256) {
        digest = EVP_sha3_256();
    }else if(algorithm == NID_sha3_384) {
        digest = EVP_sha3_384();
    }else if(algorithm == NID_sha3_512) {
        digest = EVP_sha3_512();
    }else if(algorithm == NID_sm3) {
        digest = EVP_sm3();
    }else if(algorithm == NID_blake2s256) {
        digest = EVP_blake2s256();
    }else if(algorithm == NID_blake2b512) {
        digest = EVP_blake2b512();
    }
    return digest;
}

extern "C"
JNIEXPORT jlong JNICALL
Java_net_yiim_yismcore_NativeSupport__1createDigestCtx(JNIEnv *env, jclass type, jint algorithm) {
    const EVP_MD * digest = getEVPMDByNid(algorithm);
    if(NULL == digest) return 0;

    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    int ret = EVP_DigestInit(hash, digest);
    if(!ret) {
        EVP_MD_CTX_free(hash);
        return 0;
    }
    return (jlong) hash;
}

extern "C"
JNIEXPORT void JNICALL
Java_net_yiim_yismcore_NativeSupport__1destroyDigestCtx(JNIEnv *env, jclass type, jlong ptr) {
    EVP_MD_CTX *hash = (EVP_MD_CTX *)ptr;
    EVP_MD_CTX_free(hash);
}

extern "C"
JNIEXPORT jint JNICALL
Java_net_yiim_yismcore_NativeSupport__1digestUpdate(JNIEnv *env, jclass type, jlong ptr,
                                                    jbyteArray input_, jint offset, jint len) {
    jbyte *input = env->GetByteArrayElements(input_, NULL);

    EVP_MD_CTX *hash = (EVP_MD_CTX *)ptr;
    if(!EVP_DigestUpdate(hash, ((const unsigned char *)input) + offset, len)) {
        return ERR_DIGEST_UPDATE_FAILED;
    }

    env->ReleaseByteArrayElements(input_, input, 0);
    return 0;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_net_yiim_yismcore_NativeSupport__1digestFinal(JNIEnv *env, jclass type, jlong ptr) {
    EVP_MD_CTX *hash = (EVP_MD_CTX *)ptr;
    unsigned  char buf[65] = {0};
    unsigned int outlen = 0;
    if(!EVP_DigestFinal(hash, buf + 1, &outlen)) {
        buf[0] = ERR_DIGEST_FAILED;
        outlen = 1;
    }
    jbyteArray array = env->NewByteArray(outlen + 1);
    env->SetByteArrayRegion(array, 0, outlen + 1, (const jbyte *) buf);
    return array;
}

// cipher

extern "C"
JNIEXPORT jlong JNICALL
Java_net_yiim_yismcore_NativeSupport__1createCipherCtx(JNIEnv *env, jclass type) {
    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    return (jlong) ctx;
}

extern "C"
JNIEXPORT void JNICALL
Java_net_yiim_yismcore_NativeSupport__1destroyCipherCtx(JNIEnv *env, jclass type, jlong ptr) {
    EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *) ptr;
    EVP_CIPHER_CTX_free(ctx);
}

extern "C"
JNIEXPORT jint JNICALL
Java_net_yiim_yismcore_NativeSupport__1cipherInit(JNIEnv *env, jclass type, jlong ptr,
                                                  jbyteArray keyBytes_, jbyteArray ivBytes_,
                                                  jboolean noPadding, jboolean forEncryption,
                                                  jint algorithm) {
    jbyte *keyBytes = env->GetByteArrayElements(keyBytes_, NULL);
    jbyte *ivBytes = env->GetByteArrayElements(ivBytes_, NULL);

    EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *) ptr;
    const EVP_CIPHER * cipher = NULL;
    int ret = 0;
    switch (algorithm) {
        case 2:
            cipher = EVP_aes_128_ecb();
            break;
        case 3:
            cipher = EVP_aes_192_ecb();
            break;
        case 4:
            cipher = EVP_aes_256_ecb();
            break;
        case 5:
            cipher = EVP_aes_128_cbc();
            break;
        case 6:
            cipher = EVP_aes_192_cbc();
            break;
        case 7:
            cipher = EVP_aes_256_cbc();
            break;
        case 14:
            cipher = EVP_des_ecb();
            break;
        case 15:
            cipher = EVP_des_cbc();
            break;
        case 18:
            cipher = EVP_des_ede_ecb();
            break;
        case 19:
            cipher = EVP_des_ede3_ecb();
            break;
        case 20:
            cipher = EVP_des_ede_cbc();
            break;
        case 21:
            cipher = EVP_des_ede3_cbc();
            break;
        case 26:
            cipher = EVP_sm4_ecb();
            break;
        case 27:
            cipher = EVP_sm4_cbc();
            break;
        default:
            ret = ERR_NO_SUCH_ALGORITHM;
            break;
    }
    if(ret == 0) {
        ret = EVP_CipherInit(ctx, cipher, (const unsigned char *) keyBytes,
                             (const unsigned char *) ivBytes, forEncryption ? 1 : 0);
        if (ret) {
            ret = EVP_CIPHER_CTX_set_padding(ctx, noPadding ? 0 : 1);
        }
    }else {
        goto cleanup;
    }
    if(ret) {
        ret = ERR_OK;
    }else {
        ret = ERR_ALGORITHM_INIT_FAILED;
    }

cleanup:
    env->ReleaseByteArrayElements(keyBytes_, keyBytes, 0);
    env->ReleaseByteArrayElements(ivBytes_, ivBytes, 0);

    return ret;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_net_yiim_yismcore_NativeSupport__1cipherUpdate(JNIEnv *env, jclass type, jlong ptr,
                                                    jbyteArray input_, jint offset, jint len) {
    jbyte *input = env->GetByteArrayElements(input_, NULL);

    EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *) ptr;
    int outlen = len + EVP_CIPHER_CTX_block_size(ctx);
    unsigned char * buf = (unsigned char *) malloc(outlen + 1);

    int ret = EVP_CipherUpdate(ctx, buf + 1, &outlen,
            ((const unsigned char *) input) + offset, len);
    if(!ret) {
        outlen = 1;
        buf[0] = ERR_CRYPT_FAILED;
    }else {
        buf[0] = 0;
    }

    jbyteArray array = env->NewByteArray(outlen + 1);
    env->SetByteArrayRegion(array, 0, outlen + 1, (const jbyte *) buf);

    free(buf);

    env->ReleaseByteArrayElements(input_, input, 0);
    return array;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_net_yiim_yismcore_NativeSupport__1cipherFinal(JNIEnv *env, jclass type, jlong ptr) {

    EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *) ptr;
    int outlen = EVP_CIPHER_CTX_block_size(ctx);
    unsigned char * buf = (unsigned char *) malloc(outlen + 1);

    int ret = EVP_CipherFinal_ex(ctx, buf + 1, &outlen);
    if(!ret) {
        outlen = 1;
        buf[0] = ERR_CRYPT_FAILED;
    }else {
        buf[0] = 0;
    }

    jbyteArray array = env->NewByteArray(outlen + 1);
    env->SetByteArrayRegion(array, 0, outlen + 1, (const jbyte *) buf);

    free(buf);

    return array;
}

extern "C"
JNIEXPORT jlong JNICALL
Java_net_yiim_yismcore_NativeSupport__1createHmacCtx(JNIEnv *env, jclass type, jint algorithm,
                                                     jbyteArray keyBytes_) {
    const EVP_MD * digest = getEVPMDByNid(algorithm);
    if(NULL == digest) return 0;

    jbyte *keyBytes = env->GetByteArrayElements(keyBytes_, NULL);
    HMAC_CTX * ctx = HMAC_CTX_new();
    if(!HMAC_Init_ex(ctx, keyBytes, env->GetArrayLength(keyBytes_), digest, NULL)) {
        HMAC_CTX_free(ctx);
        ctx = NULL;
        goto cleanup;
    }
cleanup:
    env->ReleaseByteArrayElements(keyBytes_, keyBytes, 0);
    return (jlong)ctx;
}

extern "C"
JNIEXPORT void JNICALL
Java_net_yiim_yismcore_NativeSupport__1destroyHmacCtx(JNIEnv *env, jclass type, jlong ptr) {
    HMAC_CTX * ctx = (HMAC_CTX *)ptr;
    HMAC_CTX_free(ctx);
}

extern "C"
JNIEXPORT jint JNICALL
Java_net_yiim_yismcore_NativeSupport__1hmacUpdate(JNIEnv *env, jclass type, jlong ptr,
                                                  jbyteArray input_, jint offset, jint len) {
    jbyte *input = env->GetByteArrayElements(input_, NULL);

    int ret = ERR_OK;
    HMAC_CTX * ctx = (HMAC_CTX *)ptr;
    if(!HMAC_Update(ctx, ((const unsigned char *)input) + offset, len)) {
        ret = ERR_HMAC_UPDATE_FAILED;
    }

    env->ReleaseByteArrayElements(input_, input, 0);
    return ret;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_net_yiim_yismcore_NativeSupport__1hmacFinal(JNIEnv *env, jclass type, jlong ptr) {
    unsigned char buf[65] = {0};
    HMAC_CTX * ctx = (HMAC_CTX *)ptr;
    unsigned  int outlen = 0;
    if(!HMAC_Final(ctx, buf + 1, &outlen)) {
        outlen = 1;
        buf[0] = ERR_HMAC_FAILED;
    }

    jbyteArray array = env->NewByteArray(outlen + 1);
    env->SetByteArrayRegion(array, 0, outlen + 1, (const jbyte *) buf);

    return array;
}

extern "C"
JNIEXPORT jlong JNICALL
Java_net_yiim_yismcore_NativeSupport__1createSM2Ctx(JNIEnv *env, jclass type) {
    return (long)EC_KEY_new();
}

extern "C"
JNIEXPORT void JNICALL
Java_net_yiim_yismcore_NativeSupport__1destroySM2Ctx(JNIEnv *env, jclass type, jlong ptr) {
    EC_KEY * ecKey = (EC_KEY *)ptr;
    EC_KEY_free(ecKey);
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_net_yiim_yismcore_NativeSupport__1sm2CtxInit(JNIEnv *env, jclass type, jlong ptr,
                                                  jboolean isPrivate, jbyteArray keyBytes_) {
    jbyte *keyBytes = env->GetByteArrayElements(keyBytes_, NULL);
    int keyLen = env->GetArrayLength(keyBytes_);
    int retCode;
    EC_KEY * ecKey = (EC_KEY *)ptr;

    unsigned char buf[66];
    size_t outlen = 0;

    if(isPrivate) {
        retCode = sm2_setup_by_privkey(default_ec_group, ecKey, (const unsigned char *)keyBytes, keyLen);
    }else {
        retCode = sm2_setup_by_pubkey(default_ec_group, ecKey, (const unsigned char *)keyBytes, keyLen);
    }

    if(retCode == ERR_OK) {
        do {
            // get public key
            const EC_POINT * point = EC_KEY_get0_public_key(ecKey);
            if (NULL == point) {
                retCode = ERR_ILLEGAL_KEY;
                break;
            }

            size_t pub_buf_len = 0;
            pub_buf_len = EC_POINT_point2oct(EC_KEY_get0_group(ecKey), point,
                                             POINT_CONVERSION_HYBRID, buf + 1, 65, BN_CTX_new());

            if (pub_buf_len == 0 || pub_buf_len != 65) {
                retCode = ERR_ILLEGAL_KEY;
                break;
            }

            buf[1] -= 0x04;
            outlen = 65;
        }while(0);
    }

    if(retCode != ERR_OK) {
        outlen = 1;
    }
    buf[0] = (unsigned char)(retCode & 0x0FF);

    jbyteArray array = env->NewByteArray(outlen + 1);
    env->SetByteArrayRegion(array, 0, outlen + 1, (const jbyte *) buf);

    env->ReleaseByteArrayElements(keyBytes_, keyBytes, 0);

    return array;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_net_yiim_yismcore_NativeSupport__1sm2GenKeypair(JNIEnv *env, jclass type, jlong ptr) {
    unsigned char buf[98];
    size_t outlen = 0;
    EC_KEY * ecKey = (EC_KEY *)ptr;

    int retCode = sm2_gen_keypair(default_ec_group, ecKey, buf + 1);
    if(retCode != 0) {
        outlen = 1;
    }else {
        outlen = 97;
    }
    buf[0] = (unsigned char)(retCode & 0x0FF);

    jbyteArray array = env->NewByteArray(outlen + 1);
    env->SetByteArrayRegion(array, 0, outlen + 1, (const jbyte *) buf);

    return array;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_net_yiim_yismcore_NativeSupport__1sm2Crypt(JNIEnv *env, jclass type, jlong ptr,
                                                jboolean forEncryption, jint mdtype,
                                                jbyteArray input_) {
    jbyte *input = env->GetByteArrayElements(input_, NULL);
    int iLen = env->GetArrayLength(input_);

    EC_KEY * ecKey = (EC_KEY *)ptr;
    unsigned char * buf = (unsigned char *) malloc(iLen + 98);
    int outlen = 1;
    int retCode = ERR_OK;

    const EVP_MD * digest = getEVPMDByNid(mdtype);
    if(NULL == digest)  {
        retCode = ERR_ILLEGAL_PARAMS;
    }else {
        if (forEncryption) {
            retCode = sm2_encrypt(ecKey, digest, (const uint8_t *) input, iLen, buf + 1);
            if(retCode == ERR_OK) {
                outlen = iLen + 97;
            }
        } else {
            retCode = sm2_decrypt(ecKey, digest, (const uint8_t *) input, iLen, buf + 1);
            if(retCode == ERR_OK) {
                outlen = iLen - 97;
            }
        }
    }
    buf[0] = (unsigned char)(retCode & 0x0FF);

    jbyteArray array = env->NewByteArray(outlen + 1);
    env->SetByteArrayRegion(array, 0, outlen + 1, (const jbyte *) buf);

    free(buf);

    env->ReleaseByteArrayElements(input_, input, 0);
    return  array;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_net_yiim_yismcore_NativeSupport__1sm2SignOrVerify(JNIEnv *env, jclass type, jlong ptr,
                                                       jint mdtype, jbyteArray userId_,
                                                       jbyteArray bytes_, jbyteArray signData_) {
    jbyte *userId = env->GetByteArrayElements(userId_, NULL);
    jbyte *bytes = env->GetByteArrayElements(bytes_, NULL);
    int idLen = env->GetArrayLength(userId_);
    int iLen = env->GetArrayLength(bytes_);
    EC_KEY * ecKey = (EC_KEY *)ptr;
    int outlen = 1;
    unsigned char buf[65] = {0};
    int retCode = ERR_OK;

    const EVP_MD * digest = getEVPMDByNid(mdtype);
    if(NULL == digest)  {
        retCode = ERR_ILLEGAL_PARAMS;
    }else {
        if(signData_ == NULL) {
            if(sm2_do_sign(ecKey, digest, (const uint8_t *) userId, idLen,
                              (const uint8_t *) bytes, iLen, buf + 1)) {
                outlen = 64;
            }else {
                retCode = ERR_SIGN_FAILED;
            }
        }else{
            jbyte *signData = env->GetByteArrayElements(signData_, NULL);
            if (!sm2_do_verify(ecKey, digest, (const uint8_t *) signData,
                    (const uint8_t *) userId, idLen,
                    (const uint8_t *) bytes, iLen)) {
                retCode = ERR_VERIFY_FAILED;
            }
            env->ReleaseByteArrayElements(signData_, signData, 0);
        }
    }
    buf[0] = (unsigned char)(retCode & 0x0FF);

    jbyteArray array = env->NewByteArray(outlen + 1);
    env->SetByteArrayRegion(array, 0, outlen + 1, (const jbyte *) buf);

    env->ReleaseByteArrayElements(userId_, userId, 0);
    env->ReleaseByteArrayElements(bytes_, bytes, 0);
    return array;
}

extern "C"
JNIEXPORT jlong JNICALL
Java_net_yiim_yismcore_NativeSupport__1createRSACtx(JNIEnv *env, jclass type) {
    RSA *rsa = RSA_new();
    return (jlong) rsa;
}

extern "C"
JNIEXPORT void JNICALL
Java_net_yiim_yismcore_NativeSupport__1destroyRSACtx(JNIEnv *env, jclass type, jlong ptr) {
    RSA *rsa = (RSA *)ptr;
    RSA_free(rsa);
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_net_yiim_yismcore_NativeSupport__1rsaGenKeypair(JNIEnv *env, jclass type, jlong ptr,
                                                     jint publicExponent, jint strength) {
    RSA *rsa = (RSA *)ptr;
    int retCode = ERR_GEN_KEYPAIR_FAILED;

    BIGNUM * e = BN_new();
    unsigned char * buf = (unsigned char *) malloc(
            sizeof(unsigned char) * ((strength / 4 + 2) * 8));
    size_t outlen = 0;

    do {
        if(!BN_set_word(e, publicExponent)) {
            break;
        }
        if(!RSA_generate_key_ex(rsa, strength, e, NULL)) {
            break;
        }

        retCode = rsa_export(rsa, 1, buf + 1, &outlen);
        if(retCode != ERR_OK) {
            retCode = ERR_GEN_KEYPAIR_FAILED;
            outlen = 1;
        }
    }while(0);
    buf[0] = (unsigned char)(retCode & 0x0FF);

    jbyteArray array = env->NewByteArray(outlen + 1);
    env->SetByteArrayRegion(array, 0, outlen + 1, (const jbyte *) buf);

    BN_free(e);
    free(buf);
    return array;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_net_yiim_yismcore_NativeSupport__1rsaCtxInit(JNIEnv *env, jclass type, jlong ptr,
                                                  jboolean isPrivate, jbyteArray nBytes_,
                                                  jbyteArray eBytes_, jbyteArray dBytes_,
                                                  jbyteArray pBytes_, jbyteArray qBytes_) {
    RSA *rsa = (RSA *)ptr;
    int retCode = ERR_ILLEGAL_KEY;
    size_t outlen = 0;
    int nLen = env->GetArrayLength(nBytes_);

    jbyte *nBytes = env->GetByteArrayElements(nBytes_, NULL);
    jbyte *eBytes = env->GetByteArrayElements(eBytes_, NULL);

    unsigned char *buf = (unsigned char *) malloc(
            sizeof(unsigned char) * ((nLen + 2) * 8));

    BIGNUM * n = BN_new();
    BIGNUM * e = BN_new();
    BIGNUM * d = NULL;
    BIGNUM * p = NULL;
    BIGNUM * q = NULL;
    BIGNUM * dp = NULL;
    BIGNUM * dq = NULL;
    BIGNUM * qinv = NULL;
    BIGNUM * tmp = NULL;
    BN_CTX * ctx = NULL;

    BN_bin2bn((const unsigned char *) nBytes,
            nLen, n);
    BN_bin2bn((const unsigned char *) eBytes,
              env->GetArrayLength(eBytes_), e);

    if(isPrivate) {
        jbyte *dBytes = env->GetByteArrayElements(dBytes_, NULL);
        jbyte *pBytes = env->GetByteArrayElements(pBytes_, NULL);
        jbyte *qBytes = env->GetByteArrayElements(qBytes_, NULL);

        d = BN_secure_new();
        p = BN_secure_new();
        q = BN_secure_new();
        dp = BN_secure_new();
        dq = BN_secure_new();
        qinv = BN_secure_new();
        tmp = BN_secure_new();
        ctx = BN_CTX_new();

        BN_bin2bn((const unsigned char *) dBytes,
                  env->GetArrayLength(dBytes_), d);
        BN_bin2bn((const unsigned char *) pBytes,
                  env->GetArrayLength(pBytes_), p);
        BN_bin2bn((const unsigned char *) qBytes,
                  env->GetArrayLength(qBytes_), q);

        do {
            if (!RSA_set0_key(rsa, n, e, d)) {
                break;
            }

            if (!RSA_set0_factors(rsa, p, q)) {
                break;
            }

            // p - 1
            if (!BN_sub(tmp, p, BN_value_one())) {
                break;
            }

            // d mod (p - 1)
            if (!BN_mod(dp, d, tmp, ctx)) {
                break;
            }

            BN_clear(tmp);
            // q - 1
            if (!BN_sub(tmp, q, BN_value_one())) {
                break;
            }

            // d mod (q - 1)
            if (!BN_mod(dq, d, tmp, ctx)) {
                break;
            }

            if(!BN_mod_inverse(qinv, q, p, ctx)) {
                break;
            }

            if(!RSA_set0_crt_params(rsa, dp, dq, qinv)) {
                break;
            }

            if(RSA_check_key(rsa) != 1) {
                break;
            }
            retCode = ERR_OK;
        }while (0);

        env->ReleaseByteArrayElements(dBytes_, dBytes, 0);
        env->ReleaseByteArrayElements(pBytes_, pBytes, 0);
        env->ReleaseByteArrayElements(qBytes_, qBytes, 0);
    }else {
        if(RSA_set0_key(rsa, n, e, NULL)) {
            retCode = ERR_OK;
        }
    }

    if(retCode == ERR_OK) {
        retCode = rsa_export(rsa, isPrivate ? 1 : 0, buf + 1, &outlen);
        if (retCode != ERR_OK) {
            retCode = ERR_ILLEGAL_KEY;
            outlen = 1;
        }
    }else {
        outlen = 1;
        BN_free(n);
        BN_free(e);
        BN_free(d);
        BN_free(p);
        BN_free(q);
        BN_free(dp);
        BN_free(dq);
        BN_free(qinv);
    }
    BN_free(tmp);
    BN_CTX_free(ctx);

    buf[0] = (unsigned char)(retCode & 0x0FF);

    jbyteArray array = env->NewByteArray(outlen + 1);
    env->SetByteArrayRegion(array, 0, outlen + 1, (const jbyte *) buf);

    env->ReleaseByteArrayElements(nBytes_, nBytes, 0);
    env->ReleaseByteArrayElements(eBytes_, eBytes, 0);

    free(buf);

    return array;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_net_yiim_yismcore_NativeSupport__1rsaCtxInitFromPem(JNIEnv *env, jclass type, jlong ptr,
                                                         jboolean isPrivate, jstring pemKey_,
                                                         jboolean pkcs1) {
    const char *pemKey = env->GetStringUTFChars(pemKey_, 0);
    int pemLen = env->GetStringLength(pemKey_);
    RSA *rsa = (RSA *)ptr;
    RSA * src = NULL;
    int nLen = 0;
    size_t outlen = 0;
    int retCode = ERR_ILLEGAL_KEY;

    BIO * keybio = BIO_new_mem_buf((const unsigned char *)pemKey, pemLen);
    if(isPrivate) {
        src = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
    }else {
        if(pkcs1) {
            src = PEM_read_bio_RSAPublicKey(keybio, NULL, NULL, NULL);
        }else {
            src = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
        }
    }
    rsa_dup_ctx(rsa, src);
    nLen = RSA_size(rsa);

    unsigned char * buf = (unsigned char *) malloc(
            sizeof(unsigned char) * ((nLen + 2) * 8));
    do {
        if(isPrivate && !RSA_check_key(rsa)) {
            outlen = 1;
            break;
        }

        retCode = rsa_export(rsa, isPrivate ? 1 : 0, buf + 1, &outlen);
        if (retCode != ERR_OK) {
            outlen = 1;
            break;
        }
    }while(0);
    buf[0] = (unsigned char)(retCode & 0x0FF);

    jbyteArray array = env->NewByteArray(outlen + 1);
    env->SetByteArrayRegion(array, 0, outlen + 1, (const jbyte *) buf);
    free(buf);
    RSA_free(src);
    BIO_free_all(keybio);
    env->ReleaseStringUTFChars(pemKey_, pemKey);

    return array;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_net_yiim_yismcore_NativeSupport__1rsaCtxToPem(JNIEnv *env, jclass type, jlong ptr,
                                                   jboolean isPrivate, jboolean pkcs1) {

    RSA *rsa = (RSA *)ptr;
    BIO * keybio = BIO_new(BIO_s_mem());
    size_t outlen = 0;

    if(isPrivate) {
        if(pkcs1) {
            PEM_write_bio_RSAPrivateKey(keybio, rsa, NULL, NULL, 0, NULL, NULL);
        }else {
            EVP_PKEY * pkey = EVP_PKEY_new();
            EVP_PKEY_set1_RSA(pkey, rsa);
            PEM_write_bio_PrivateKey(keybio, pkey, NULL, NULL, 0, NULL, NULL);
            EVP_PKEY_free(pkey);
        }
    }else {
        if(pkcs1) {
            PEM_write_bio_RSAPublicKey(keybio, rsa);
        }else {
            PEM_write_bio_RSA_PUBKEY(keybio, rsa);
        }
    }

    int nLen = RSA_size(rsa);
    unsigned char * buf = (unsigned char *) malloc(
            sizeof(unsigned char) * ((nLen + 2) * 8));

    if(!BIO_read_ex(keybio, buf + 1, ((nLen + 2) * 8 - 1), &outlen)) {
        buf[0] = ERR_ILLEGAL_KEY;
        outlen = 1;
    }else {
        buf[0] = ERR_OK;
    }

    jbyteArray array = env->NewByteArray(outlen + 1);
    env->SetByteArrayRegion(array, 0, outlen + 1, (const jbyte *) buf);
    free(buf);
    BIO_free_all(keybio);
    return array;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_net_yiim_yismcore_NativeSupport__1rsaCrypt(JNIEnv *env, jclass type, jlong ptr,
                                                jboolean isPrivate, jboolean forEncryption,
                                                jint paddingType, jint mdType, jbyteArray input_) {
    jbyte *input = env->GetByteArrayElements(input_, NULL);
    RSA *rsa = (RSA *)ptr;
    EVP_PKEY * pkey = EVP_PKEY_new();
    EVP_PKEY_CTX * pkeyCtx = NULL;
    size_t outlen = RSA_size(rsa);

    unsigned char * buf = (unsigned char *) malloc(
            sizeof(unsigned char) * (outlen + 1));
    int retCode = ERR_OK;

    do {
        const EVP_MD * digest = getEVPMDByNid(mdType);
        if(NULL == digest) {
            retCode = ERR_ILLEGAL_PARAMS;
            break;
        }

        if(EVP_PKEY_set1_RSA(pkey, rsa) <= 0) {
            retCode = ERR_ILLEGAL_PARAMS;
            break;
        }

        if((pkeyCtx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
            retCode = ERR_ILLEGAL_PARAMS;
            break;
        }

        if (forEncryption) {
            if (EVP_PKEY_encrypt_init(pkeyCtx) <= 0) {
                retCode = ERR_CRYPT_FAILED;
                break;
            }

            if (EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, paddingType) <= 0) {
                retCode = ERR_ILLEGAL_PARAMS;
                break;
            }

            if(paddingType == RSA_PKCS1_OAEP_PADDING) {
                if (EVP_PKEY_CTX_set_rsa_oaep_md(pkeyCtx, digest) <= 0) {
                    retCode = ERR_ILLEGAL_PARAMS;
                    break;
                }

                if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkeyCtx, digest) <= 0) {
                    retCode = ERR_ILLEGAL_PARAMS;
                    break;
                }
            }

            if (EVP_PKEY_encrypt(pkeyCtx, buf + 1, &outlen,
                    (const unsigned char *) input, env->GetArrayLength(input_)) <= 0) {
                retCode = ERR_CRYPT_FAILED;
                break;
            }
        } else {
            if (EVP_PKEY_decrypt_init(pkeyCtx) <= 0) {
                retCode = ERR_CRYPT_FAILED;
                break;
            }

            if (EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, paddingType) <= 0) {
                retCode = ERR_ILLEGAL_PARAMS;
                break;
            }

            if(paddingType == RSA_PKCS1_OAEP_PADDING) {
                if (EVP_PKEY_CTX_set_rsa_oaep_md(pkeyCtx, digest) <= 0) {
                    retCode = ERR_ILLEGAL_PARAMS;
                    break;
                }

                if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkeyCtx, digest) <= 0) {
                    retCode = ERR_ILLEGAL_PARAMS;
                    break;
                }
            }

            if (EVP_PKEY_decrypt(pkeyCtx, buf + 1, &outlen,
                                 (const unsigned char *) input, env->GetArrayLength(input_)) <= 0) {
                retCode = ERR_CRYPT_FAILED;
                break;
            }
        }
    }while(0);
    buf[0] = (unsigned char)(retCode & 0x0FF);
    if(retCode != ERR_OK) {
        outlen = 1;
    }

    jbyteArray array = env->NewByteArray(outlen + 1);
    env->SetByteArrayRegion(array, 0, outlen + 1, (const jbyte *) buf);

    free(buf);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkeyCtx);
    env->ReleaseByteArrayElements(input_, input, 0);

    return array;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_net_yiim_yismcore_NativeSupport__1rsaSignOrVerify(JNIEnv *env, jclass type, jlong ptr,
                                                       jboolean isPrivate, jint paddingType,
                                                       jint mdType,jbyteArray mdBytes_,
                                                       jbyteArray signData_) {
    jbyte *mdBytes = env->GetByteArrayElements(mdBytes_, NULL);

    RSA *rsa = (RSA *)ptr;
    EVP_PKEY * pkey = EVP_PKEY_new();
    EVP_PKEY_CTX * pkeyCtx = NULL;
    size_t outlen = RSA_size(rsa);

    unsigned char * buf = (unsigned char *) malloc(
            sizeof(unsigned char) * (outlen + 1));
    int retCode = ERR_OK;

    do {
        const EVP_MD * digest = getEVPMDByNid(mdType);
        if(NULL == digest) {
            retCode = ERR_ILLEGAL_PARAMS;
            break;
        }

        if (EVP_PKEY_assign(pkey, paddingType == 1 ? EVP_PKEY_RSA_PSS : EVP_PKEY_RSA, rsa) <= 0) {
            retCode = ERR_ILLEGAL_PARAMS;
            break;
        }

        // up ref
        RSA_up_ref(rsa);

        if((pkeyCtx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
            retCode = ERR_ILLEGAL_PARAMS;
            break;
        }

        if(signData_ == NULL) {
            if (EVP_PKEY_sign_init(pkeyCtx) <= 0) {
                retCode = ERR_ILLEGAL_PARAMS;
                break;
            }
            if (EVP_PKEY_CTX_set_signature_md(pkeyCtx, digest) <= 0) {
                retCode = ERR_ILLEGAL_PARAMS;
                break;
            }
            if (paddingType == 1 &&
                EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyCtx, EVP_MD_size(digest)) <= 0) {
                retCode = ERR_ILLEGAL_PARAMS;
                break;
            }
            int mdLen = env->GetArrayLength(mdBytes_);
            if (EVP_PKEY_sign(pkeyCtx, buf + 1, &outlen, (const unsigned char *)mdBytes, mdLen) <= 0) {
                retCode = ERR_SIGN_FAILED;
                break;
            }
        }else {
            jbyte *signData = env->GetByteArrayElements(signData_, NULL);

            if (EVP_PKEY_verify_init(pkeyCtx) <= 0) {
                retCode = ERR_ILLEGAL_PARAMS;
                break;
            }
            if (EVP_PKEY_CTX_set_signature_md(pkeyCtx, digest) <= 0) {
                retCode = ERR_ILLEGAL_PARAMS;
                break;
            }
            if (paddingType == 1 &&
                EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyCtx, EVP_MD_size(digest)) <= 0) {
                retCode = ERR_ILLEGAL_PARAMS;
                break;
            }
            if (EVP_PKEY_verify(pkeyCtx, (const unsigned char *) signData,
                                env->GetArrayLength(signData_), (const unsigned char *)mdBytes,
                              env->GetArrayLength(mdBytes_)) <= 0) {
                retCode = ERR_VERIFY_FAILED;
            }

            env->ReleaseByteArrayElements(signData_, signData, 0);
        }
    }while(0);
    buf[0] = (unsigned char)(retCode & 0x0FF);
    if(retCode != ERR_OK) {
        outlen = 1;
    }

    jbyteArray array = env->NewByteArray(outlen + 1);
    env->SetByteArrayRegion(array, 0, outlen + 1, (const jbyte *) buf);

    free(buf);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkeyCtx);
    env->ReleaseByteArrayElements(mdBytes_, mdBytes, 0);
    return array;
}