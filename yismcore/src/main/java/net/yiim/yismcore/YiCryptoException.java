package net.yiim.yismcore;

/**
 * Created by saint on 2018/7/26.
 */

public class YiCryptoException extends Exception {
    YiCryptoErrorCode errorCode;

    public YiCryptoException(YiCryptoErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }

    public YiCryptoErrorCode getErrorCode() {
        return errorCode;
    }

    @Override
    public String toString() {
        return "net.yiim.yismcore.YiCryptoException: {" +
                "code: " + errorCode.getCode() +
                ", message: " + errorCode.getMessage() +
                '}';
    }
}
