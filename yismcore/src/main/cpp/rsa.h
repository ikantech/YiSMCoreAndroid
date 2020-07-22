//
// Created by saint on 2020-07-16.
//

#ifndef YISMCORE_RSA_H
#define YISMCORE_RSA_H

#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

namespace yiim {
    int rsa_export(RSA * rsa, int isPrivate, unsigned char * out, size_t * outlen);
    void rsa_dup_ctx(RSA * dist, const RSA * src);
}


#endif //YISMCORE_RSA_H
