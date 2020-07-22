package net.yiim.yismcore;

// Created by saint on 2019-10-08.

import java.io.ByteArrayOutputStream;

final class CipherImpl implements ICrypto {
    private YiSMCore.Algorithm algorithm;
    private ByteArrayOutputStream bout;
    // symmetric
    long symmetricPtr = 0;

    CipherImpl(YiSMCore.Algorithm algorithm) {
        this.algorithm = algorithm;
        bout = new ByteArrayOutputStream();
    }

    @Override
    protected void finalize() throws Throwable {
        if(symmetricPtr != 0L) {
            NativeSupport._destroyCipherCtx(symmetricPtr);
            symmetricPtr = 0L;
        }
        super.finalize();
    }

    public CipherImpl init(boolean forEncryption, YiCryptoKey cryptoKey) throws YiCryptoException {
        symmetricPtr = NativeSupport._createCipherCtx();
        if(symmetricPtr == 0L) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ALGORITHM_INIT_FAILED);
        }

        // check key parameter
        if(cryptoKey == null || cryptoKey.getSymmetricKey() == null ||
                cryptoKey.getSymmetricKey().length < 1 ||
                (cryptoKey.getSymmetricKey().length % 8) != 0) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }

        byte[] keyBytes = cryptoKey.getSymmetricKey();
        byte[] ivBytes = cryptoKey.getIV();
        int index = algorithm.getIndex();
        int retCode = 0;
        boolean noPadding = algorithm.getAlgorithm().endsWith("NoPadding");
        if (index >= YiSMCore.Algorithm.AES_ECB_NOPADDING.getIndex() &&
                index <= YiSMCore.Algorithm.AES_CBC_PKCS7PADDING.getIndex()) {
            // AES

            // check iv
            if(ivBytes != null && ivBytes.length < 16) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_IV);
            }

            int type = algorithm.getType();

            if(keyBytes.length == 16) {
                retCode = NativeSupport._cipherInit(symmetricPtr, keyBytes, ivBytes, noPadding, forEncryption, type);
            }else if(keyBytes.length == 24) {
                retCode = NativeSupport._cipherInit(symmetricPtr, keyBytes, ivBytes, noPadding, forEncryption, type + 1);
            }else if(keyBytes.length == 32) {
                retCode = NativeSupport._cipherInit(symmetricPtr, keyBytes, ivBytes, noPadding, forEncryption, type + 2);
            }else {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }
        } else if (index >= YiSMCore.Algorithm.DES_ECB_NOPADDING.getIndex() &&
                index <= YiSMCore.Algorithm.DES_CBC_PKCS7PADDING.getIndex()) {
            // DES
            if (keyBytes.length != 8) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }

            // check iv
            if(ivBytes != null && ivBytes.length < 8) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_IV);
            }

            retCode = NativeSupport._cipherInit(symmetricPtr, keyBytes, ivBytes, noPadding, forEncryption, algorithm.getType());
        } else if (index >= YiSMCore.Algorithm.DESEDE_ECB_NOPADDING.getIndex() &&
                index <= YiSMCore.Algorithm.DESEDE_CBC_PKCS7PADDING.getIndex()) {
            // 3DES

            // check iv
            if(ivBytes != null && ivBytes.length < 8) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_IV);
            }

            int type = algorithm.getType();

            if(keyBytes.length == 16) {
                retCode = NativeSupport._cipherInit(symmetricPtr, keyBytes, ivBytes, noPadding, forEncryption, type);
            }else if(keyBytes.length == 24) {
                retCode = NativeSupport._cipherInit(symmetricPtr, keyBytes, ivBytes, noPadding, forEncryption, type + 1);
            }else {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }
        }  else if (index >= YiSMCore.Algorithm.SM4_ECB_NOPADDING.getIndex() &&
                index <= YiSMCore.Algorithm.SM4_CBC_PKCS7PADDING.getIndex()) {
            // SM4
            if (keyBytes.length != 16) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }

            // check iv
            if(ivBytes != null && ivBytes.length < 16) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_IV);
            }

            retCode = NativeSupport._cipherInit(symmetricPtr, keyBytes, ivBytes, noPadding, forEncryption, algorithm.getType());
        }

        if(retCode != 0) {
            throw new YiCryptoException(YiCryptoErrorCode.valuesOf(retCode));
        }
        return this;
    }

    @Override
    public void update(byte[] input, int offset, int len) throws YiCryptoException {
        byte[] retBytes = NativeSupport._cipherUpdate(symmetricPtr, input, offset, len);
        if(retBytes[0] != 0) {
            throw new YiCryptoException(YiCryptoErrorCode.valuesOf(retBytes[0]));
        }
        if(retBytes.length > 1) {
            bout.write(retBytes, 1, retBytes.length - 1);
        }
    }

    @Override
    public byte[] doFinal() throws YiCryptoException {
        byte[] retBytes = NativeSupport._cipherFinal(symmetricPtr);
        if(retBytes[0] != 0) {
            throw new YiCryptoException(YiCryptoErrorCode.valuesOf(retBytes[0]));
        }
        if(retBytes.length > 1) {
            bout.write(retBytes, 1, retBytes.length - 1);
        }
        return bout.toByteArray();
    }
}
