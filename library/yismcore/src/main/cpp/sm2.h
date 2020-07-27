//
// Created by saint on 2020-07-16.
//

#ifndef YISMCORE_SM2_H
#define YISMCORE_SM2_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

namespace yiim {
    EC_GROUP * EC_GROUP_new_sm2();

    int sm2_setup_by_privkey(const EC_GROUP * group, EC_KEY * ecKey,
                             const unsigned char *privKey, int key_len);
    int sm2_setup_by_pubkey(const EC_GROUP * group, EC_KEY * ecKey,
                            const unsigned char *pubKey, int key_len);

    int sm2_gen_keypair(const EC_GROUP * group, EC_KEY * ecKey, unsigned char *out);

    int sm2_encrypt(const EC_KEY *key,
                    const EVP_MD *digest,
                    const uint8_t *msg,
                    size_t msg_len, unsigned char * out);

    int sm2_decrypt(const EC_KEY *key,
                    const EVP_MD *digest,
                    const uint8_t *ciphertext,
                    size_t ciphertext_len, unsigned char * out);

    int sm2_do_sign(const EC_KEY *key,
                    const EVP_MD *digest,
                    const uint8_t *id,
                    const size_t id_len,
                    const uint8_t *msg, size_t msg_len, unsigned char * out);

    int sm2_do_verify(const EC_KEY *key,
                      const EVP_MD *digest,
                      const uint8_t *sig,
                      const uint8_t *id,
                      const size_t id_len,
                      const uint8_t *msg, size_t msg_len);
}


#endif //YISMCORE_SM2_H
