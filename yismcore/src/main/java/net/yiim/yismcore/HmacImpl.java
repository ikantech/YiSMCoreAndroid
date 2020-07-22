package net.yiim.yismcore;

final class HmacImpl implements ICrypto {
    int mType;
    long mHmacPtr = 0;

    HmacImpl(YiSMCore.Algorithm algorithm) {
        mType = algorithm.getType();
    }

    HmacImpl(int type) {
        mType = type;
    }

    @Override
    protected void finalize() throws Throwable {
        if(mHmacPtr != 0L) {
            NativeSupport._destroyHmacCtx(mHmacPtr);
            mHmacPtr = 0L;
        }
        super.finalize();
    }

    public HmacImpl init(YiCryptoKey cryptoKey) throws YiCryptoException {
        if(cryptoKey == null || cryptoKey.getSymmetricKey() == null ||
                cryptoKey.getSymmetricKey().length < 1) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }

        mHmacPtr = NativeSupport._createHmacCtx(mType, cryptoKey.getSymmetricKey());
        if(mHmacPtr == 0L) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ALGORITHM_INIT_FAILED);
        }
        return this;
    }

    @Override
    public void update(byte[] input, int offset, int len) throws YiCryptoException {
        if(offset < 0 || len < 1 || (input != null && len > (input.length - offset))) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_PARAMS);
        }
        if(input == null || input.length < len) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_INPUT);
        }
        int retCdoe = NativeSupport._hmacUpdate(mHmacPtr, input, offset, len);
        if(retCdoe != 0) {
            throw new YiCryptoException(YiCryptoErrorCode.valuesOf(retCdoe));
        }
    }

    @Override
    public byte[] doFinal() throws YiCryptoException {
        byte[] retBytes = NativeSupport._hmacFinal(mHmacPtr);
        return YiSMCore.checkResultBytes(retBytes);
    }
}