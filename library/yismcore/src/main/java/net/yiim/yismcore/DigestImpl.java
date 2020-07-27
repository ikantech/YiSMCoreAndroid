package net.yiim.yismcore;

final class DigestImpl implements ICrypto {
    int mType;
    long digestPtr = 0;

    DigestImpl(YiSMCore.Algorithm algorithm) {
        mType = algorithm.getType();
    }

    DigestImpl(int type) {
        mType = type;
    }

    @Override
    protected void finalize() throws Throwable {
        if(digestPtr != 0L) {
            NativeSupport._destroyDigestCtx(digestPtr);
            digestPtr = 0L;
        }
        super.finalize();
    }

    public DigestImpl init() throws YiCryptoException {
        digestPtr = NativeSupport._createDigestCtx(mType);
        if(digestPtr == 0L) {
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
        int retCdoe = NativeSupport._digestUpdate(digestPtr, input, offset, len);
        if(retCdoe != 0) {
            throw new YiCryptoException(YiCryptoErrorCode.valuesOf(retCdoe));
        }
    }

    @Override
    public byte[] doFinal() throws YiCryptoException {
        byte[] retBytes = NativeSupport._digestFinal(digestPtr);
        return YiSMCore.checkResultBytes(retBytes);
    }

    static int getDigestSize(int type) throws YiCryptoException {
        if(type == YiSMCore.Algorithm.MD5.getType()) {
            return 16;
        }else if(type == YiSMCore.Algorithm.SHA1.getType()) {
            return 20;
        }else if(type == YiSMCore.Algorithm.SHA224.getType() ||
                type == YiSMCore.Algorithm.SHA3_224.getType()) {
            return 28;
        }else if(type == YiSMCore.Algorithm.SHA256.getType() ||
                type == YiSMCore.Algorithm.SHA3_256.getType() ||
                type == YiSMCore.Algorithm.SM3.getType() ||
                type == YiSMCore.Algorithm.BLAKE_2S.getType()) {
            return 32;
        }else if(type == YiSMCore.Algorithm.SHA384.getType() ||
                type == YiSMCore.Algorithm.SHA3_384.getType()) {
            return 48;
        }else if(type == YiSMCore.Algorithm.SHA512.getType() ||
                type == YiSMCore.Algorithm.SHA3_512.getType() ||
                type == YiSMCore.Algorithm.BLAKE_2B.getType()) {
            return 64;
        }
        throw new YiCryptoException(YiCryptoErrorCode.ERR_NO_SUCH_ALGORITHM);
    }
}