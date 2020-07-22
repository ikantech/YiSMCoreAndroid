package net.yiim.yismcore;

/**
 * Created by saint on 2018/7/27.
 */

public enum YiCryptoErrorCode {
    ERR_UNKNOWN(-1, "unknown error."),
    ERR_OK(0, "ok"),
    ERR_NO_SUCH_ALGORITHM(1, "no such algorithm."),
    ERR_ALGORITHM_NOT_INIT(2, "algorithm not init."),
    ERR_ALGORITHM_INIT_FAILED(3, "algorithm init failed."),
    ERR_ILLEGAL_INPUT(4, "illegal input."),
    ERR_ILLEGAL_KEY(5, "illegal key."),
    ERR_ILLEGAL_IV(6, "illegal iv."),
    ERR_ILLEGAL_BUFFER(7, "illegal buffer."),
    ERR_ILLEGAL_PARAMS(8, "illegal params."),
    ERR_ILLEGAL_PADDING(9, "illegal padding."),
    ERR_ILLEGAL_ALGORITHM(10, "illegal algorithm."),
    ERR_GEN_KEYPAIR_FAILED(11, "gen keypair failed."),
    ERR_CRYPT_FAILED(12, "crypt failed."),
    ERR_SIGN_FAILED(13, "generate signature failed."),
    ERR_VERIFY_FAILED(14, "verify signature failed."),
    ERR_BASE64_ENCODE_FAILED(15, "base64 encode failed."),
    ERR_BASE64_DECODE_FAILED(16, "base64 decode failed."),
    ERR_DES_PBOC_MAC_FAILED(17, "pboc des & 3des mac failed."),
    ERR_ANSI_MAC_FAILED(18, "ansi x9.9 & x9.19 mac failed."),
    ERR_WBSMS4_CRYPT_FAILED(19, "white box sms4 crypt failed."),
    ERR_DIGEST_UPDATE_FAILED(20, "message digest update data failed."),
    ERR_DIGEST_FAILED(21, "calculate message digest failed."),
    ERR_HMAC_UPDATE_FAILED(22, "hmac update failed."),
    ERR_HMAC_FAILED(23, "calculate hmac failed."),
    ERR_DES_DIVERSIFY_FAILED(24, "des diversify failed."),
    ERR_DES_CRYPT_FAILED(25, "des crypt failed."),
    ERR_SDK_SETUP_FAILED(26, "setup sdk failed.");

    private String msg;
    private int code;
    YiCryptoErrorCode(int code, String msg) {
        this.msg = msg;
        this.code = code;
    }

    public String getMessage() {
        return msg;
    }

    public int getCode() {
        return code;
    }

    public static YiCryptoErrorCode valuesOf(int code) {
        for(YiCryptoErrorCode c : values()) {
            if(c.code == code) {
                return c;
            }
        }
        return ERR_UNKNOWN;
    }
}
