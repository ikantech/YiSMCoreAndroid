package net.yiim.yismcore;

// Created by saint on 2020-04-30.

final class RSASigner implements ISigner {
    private static final int RSA_PKCS_V15 = 0;
    private static final int RSA_PKCS_V21 = 1;

    private DigestImpl digest;
    private int paddingType;
    private boolean isPrivate = false;
    private boolean forSigning;
    private YiCryptoKey cryptoKey;

    RSASigner(YiSMCore.Algorithm algorithm) {
        digest = new DigestImpl(algorithm.getType());
        if(algorithm.getIndex() >= YiSMCore.Algorithm.MD5WITHRSA_PSS.getIndex()) {
            paddingType = RSA_PKCS_V21;
        }else {
            paddingType = RSA_PKCS_V15;
        }
    }

    public ICrypto init(boolean forWhat, YiCryptoKey cryptoKey) throws YiCryptoException {
        isPrivate = !cryptoKey.checkRSAPrivateKeyFail();
        if(!isPrivate && cryptoKey.checkRSAPublicKeyFail()) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }

        if(paddingType == RSA_PKCS_V21) {
            int emBits = cryptoKey.getRSA_NBytes().length * 8 - 1;
            int hLen = DigestImpl.getDigestSize(digest.mType);
            if (emBits < (16 * hLen + 9)) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }
        }

        digest.init();

        this.cryptoKey = cryptoKey;
        forSigning = forWhat;
        return this;
    }

    @Override
    public byte[] generateSignature() throws YiCryptoException {
        if(forSigning) {
            byte[] mdBytes = digest.doFinal();
            return YiSMCore.checkResultBytes(NativeSupport._rsaSignOrVerify(cryptoKey.rsaPtr,
                    isPrivate, paddingType,
                    digest.mType, mdBytes, null));
        }
        throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_PARAMS);
    }

    @Override
    public boolean verifySignature(byte[] signature) throws YiCryptoException {
        if(!forSigning && signature != null && signature.length > 0) {
            byte[] mdBytes = digest.doFinal();
            byte[] retBytes = NativeSupport._rsaSignOrVerify(cryptoKey.rsaPtr,
                    isPrivate, paddingType,
                    digest.mType, mdBytes, signature);
            if(retBytes[0] != 0) {
                throw new YiCryptoException(YiCryptoErrorCode.valuesOf(retBytes[0]));
            }
            return true;
        }
        throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_PARAMS);
    }

    @Override
    public void update(byte[] input, int offset, int len) throws YiCryptoException {
        digest.update(input, offset, len);
    }

    @Override
    public byte[] doFinal() throws YiCryptoException {
        return generateSignature();
    }
}
