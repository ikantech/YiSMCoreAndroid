#ifndef _YISMCORE_TYPES_H
#define _YISMCORE_TYPES_H

namespace yiim {
        typedef enum {
            ERR_UNKNOWN = -1,
            ERR_OK = 0,
            ERR_NO_SUCH_ALGORITHM = 1,
            ERR_ALGORITHM_NOT_INIT = 2,
            ERR_ALGORITHM_INIT_FAILED = 3,
            ERR_ILLEGAL_INPUT = 4,
            ERR_ILLEGAL_KEY = 5,
            ERR_ILLEGAL_IV = 6,
            ERR_ILLEGAL_BUFFER = 7,
            ERR_ILLEGAL_PARAMS = 8,
            ERR_ILLEGAL_PADDING = 9,
            ERR_ILLEGAL_ALGORITHM = 10,
            ERR_GEN_KEYPAIR_FAILED = 11,
            ERR_CRYPT_FAILED = 12,
            ERR_SIGN_FAILED = 13,
            ERR_VERIFY_FAILED = 14,
            ERR_BASE64_ENCODE_FAILED = 15,
            ERR_BASE64_DECODE_FAILED = 16,
            ERR_DES_PBOC_MAC_FAILED = 17,
            ERR_ANSI_MAC_FAILED = 18,
            ERR_WBSMS4_CRYPT_FAILED = 19,
            ERR_DIGEST_UPDATE_FAILED = 20,
            ERR_DIGEST_FAILED = 21,
            ERR_HMAC_UPDATE_FAILED = 22,
            ERR_HMAC_FAILED = 23,
            ERR_DES_DIVERSIFY_FAILED = 24,
            ERR_DES_CRYPT_FAILED = 25,
            ERR_SDK_SETUP_FAILED = 26
        } YiErrorCode;
}

#endif