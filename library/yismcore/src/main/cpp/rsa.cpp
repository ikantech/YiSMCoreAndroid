//
// Created by saint on 2020-07-16.
//

#include "rsa.h"
#include "YiCryptoTypes.h"

namespace yiim {
    static int export_bn(const BIGNUM * p, unsigned char * out, size_t * outlen) {
        int olen = BN_num_bytes(p);

        out[(*outlen)++] = (unsigned char) ((olen >> 8) & 0x0FF);
        out[(*outlen)++] = (unsigned char) (olen & 0x0FF);

        return BN_bn2binpad(p, out + *outlen, olen);
    }

    int rsa_export(RSA * rsa, int isPrivate, unsigned char * out, size_t * outlen) {
        int ret = ERR_ILLEGAL_KEY;
        *outlen = 0;
        int olen = 0;

        do {
            // n
            if(( olen = export_bn(RSA_get0_n(rsa), out, outlen) ) == 0) {
                break;
            }
            *outlen += olen;

            // e
            if(( olen = export_bn(RSA_get0_e(rsa), out, outlen) ) == 0) {
                break;
            }
            *outlen += olen;

            if(isPrivate) {
                // d
                if(( olen = export_bn(RSA_get0_d(rsa), out, outlen) ) == 0) {
                    break;
                }
                *outlen += olen;

                // p
                if(( olen = export_bn(RSA_get0_p(rsa), out, outlen) ) == 0) {
                    break;
                }
                *outlen += olen;

                // q
                if(( olen = export_bn(RSA_get0_q(rsa), out, outlen) ) == 0) {
                    break;
                }
                *outlen += olen;

                // dp
                if(( olen = export_bn(RSA_get0_dmp1(rsa), out, outlen) ) == 0) {
                    break;
                }
                *outlen += olen;

                // dq
                if(( olen = export_bn(RSA_get0_dmq1(rsa), out, outlen) ) == 0) {
                    break;
                }
                *outlen += olen;

                // qinv
                if(( olen = export_bn(RSA_get0_iqmp(rsa), out, outlen) ) == 0) {
                    break;
                }
                *outlen += olen;
            }

            ret = ERR_OK;
        }while(0);

        return ret;
    }

    void rsa_dup_ctx(RSA * dist, const RSA * src) {
        const BIGNUM * t = NULL;
        BIGNUM * n = NULL;
        BIGNUM * e = NULL;
        BIGNUM * d = NULL;
        BIGNUM * p = NULL;
        BIGNUM * q = NULL;
        BIGNUM * dp = NULL;
        BIGNUM * dq = NULL;
        BIGNUM * qinv = NULL;

        // n
        if((t = RSA_get0_n(src)) != NULL) {
            n = BN_new();
            BN_copy(n, t);
        }

        // e
        if((t = RSA_get0_e(src)) != NULL) {
            e = BN_new();
            BN_copy(e, t);
        }

        // d
        if((t = RSA_get0_d(src)) != NULL) {
            d = BN_secure_new();
            BN_copy(d, t);
        }

        // p
        if((t = RSA_get0_p(src)) != NULL) {
            p = BN_secure_new();
            BN_copy(p, t);
        }

        // q
        if((t = RSA_get0_q(src)) != NULL) {
            q = BN_secure_new();
            BN_copy(q, t);
        }

        // dp
        if((t = RSA_get0_dmp1(src)) != NULL) {
            dp = BN_secure_new();
            BN_copy(dp, t);
        }

        // dq
        if((t = RSA_get0_dmq1(src)) != NULL) {
            dq = BN_secure_new();
            BN_copy(dq, t);
        }

        // qinv
        if((t = RSA_get0_iqmp(src)) != NULL) {
            qinv = BN_secure_new();
            BN_copy(qinv, t);
        }

        RSA_set0_key(dist, n, e, d);
        RSA_set0_factors(dist, p, q);
        RSA_set0_crt_params(dist, dp, dq, qinv);
    }

}