package net.yiim.yismcore;

// Created by saint on 2020-03-16.

import java.io.ByteArrayOutputStream;

final class GMSigner implements ISigner {
    private static final byte[] DEFAULT_USERID = new byte[]{
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
    };
    private YiSMCore.Algorithm mAlgorithm;
    private boolean mForSigning;
    private YiCryptoKey mCryptoKey = null;
    private byte[] mUserIdBytes = null;
    private ByteArrayOutputStream mByteout;

    GMSigner(YiSMCore.Algorithm algorithm) throws YiCryptoException {
        mAlgorithm = algorithm;
        mByteout = new ByteArrayOutputStream(512);
    }

    public GMSigner init(boolean forSigning, YiCryptoKey cryptoKey) throws YiCryptoException {
        if(forSigning) {
            if(cryptoKey == null || cryptoKey.checkSM2PrivateKeyFail()) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }
        }else {
            if(cryptoKey == null || cryptoKey.checkSM2PublicKeyFail()) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }
        }
        byte[] userId = cryptoKey.getSM2UserId();
        if(userId == null || userId.length < 1) {
            userId = DEFAULT_USERID;
        }
        mUserIdBytes = userId;

        mForSigning = forSigning;
        mCryptoKey = cryptoKey;
        return this;
    }

    @Override
    public byte[] generateSignature() throws YiCryptoException {
        if(mForSigning) {
            return YiSMCore.checkResultBytes(NativeSupport._sm2SignOrVerify(mCryptoKey.sm2Ptr,
                    mAlgorithm.getType(), mUserIdBytes, mByteout.toByteArray(), null));
        }
        throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_PARAMS);
    }

    @Override
    public boolean verifySignature(byte[] signature) throws YiCryptoException {
        if(!mForSigning && signature != null && signature.length > 0) {
            byte[] retBytes = NativeSupport._sm2SignOrVerify(mCryptoKey.sm2Ptr,
                    mAlgorithm.getType(), mUserIdBytes, mByteout.toByteArray(), signature);
            if(retBytes[0] != 0) {
                throw new YiCryptoException(YiCryptoErrorCode.valuesOf(retBytes[0]));
            }
            return true;
        }
        throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_PARAMS);
    }

    @Override
    public void update(byte[] input, int offset, int len) throws YiCryptoException {
        mByteout.write(input, offset, len);
    }

    @Override
    public byte[] doFinal() throws YiCryptoException {
        return generateSignature();
    }
}
