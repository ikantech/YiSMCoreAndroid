package net.yiim.yismcore;

// Created by saint on 2020-03-12.

import java.io.ByteArrayOutputStream;

final class GMCipherImpl implements ICrypto {
    enum Mode
    {
        C1C2C3, C1C3C2;
    }

    private ByteArrayOutputStream bout;
    private YiSMCore.Algorithm mdAlg;
    private Mode mode;
    private YiCryptoKey cryptoKey;
    private boolean forEncryption;

    GMCipherImpl(YiSMCore.Algorithm algorithm) throws YiCryptoException {
        switch (algorithm) {
            case SM2WITHSM3_C1C2C3:
                mdAlg = YiSMCore.Algorithm.SM3;
                mode = Mode.C1C2C3;
                break;
            case SM2WITHSM3_C1C3C2:
                mdAlg = YiSMCore.Algorithm.SM3;
                mode = Mode.C1C3C2;
                break;
            case SM2WITHSHA256_C1C2C3:
                mdAlg = YiSMCore.Algorithm.SHA256;
                mode = Mode.C1C2C3;
                break;
            case SM2WITHSHA256_C1C3C2:
                mdAlg = YiSMCore.Algorithm.SHA256;
                mode = Mode.C1C3C2;
                break;
            case SM2WITHSHA3_256_C1C2C3:
                mdAlg = YiSMCore.Algorithm.SHA3_256;
                mode = Mode.C1C2C3;
                break;
            case SM2WITHSHA3_256_C1C3C2:
                mdAlg = YiSMCore.Algorithm.SHA3_256;
                mode = Mode.C1C3C2;
                break;
            case SM2WITHBLAKE_2S_C1C2C3:
                mdAlg = YiSMCore.Algorithm.BLAKE_2S;
                mode = Mode.C1C2C3;
                break;
            case SM2WITHBLAKE_2S_C1C3C2:
                mdAlg = YiSMCore.Algorithm.BLAKE_2S;
                mode = Mode.C1C3C2;
                break;
            default:
                throw new YiCryptoException(YiCryptoErrorCode.ERR_NO_SUCH_ALGORITHM);
        }
        bout = new ByteArrayOutputStream(512);
    }

    public GMCipherImpl init(boolean forEncryption, YiCryptoKey cryptoKey) throws YiCryptoException {
        if (forEncryption) {
            if(cryptoKey == null || cryptoKey.checkSM2PublicKeyFail()) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }
        }else {
            if(cryptoKey == null || cryptoKey.checkSM2PrivateKeyFail()) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }
        }
        this.cryptoKey = cryptoKey;
        this.forEncryption = forEncryption;
        return this;
    }

    @Override
    public void update(byte[] input, int offset, int len) throws YiCryptoException {
        bout.write(input, offset, len);
    }

    @Override
    public byte[] doFinal() throws YiCryptoException {
        if(bout.size() < 1) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_INPUT);
        }

        if(mode == Mode.C1C3C2 && !forEncryption) {
            byte[] plainBytes = bout.toByteArray();
            bout.reset();
            // C1C3C2 to C1C2C3
            bout.write(plainBytes, 0, 65);
            bout.write(plainBytes, 97, plainBytes.length - 97);
            bout.write(plainBytes, 65, 32);
        }
        byte[] retBytes = NativeSupport._sm2Crypt(cryptoKey.sm2Ptr, forEncryption,
                mdAlg.getType(), bout.toByteArray());
        if(retBytes[0] != 0) {
            throw new YiCryptoException(YiCryptoErrorCode.valuesOf(retBytes[0]));
        }
        ByteArrayOutputStream out  = null;
        try {
            out = new ByteArrayOutputStream(retBytes.length);
            if(mode == Mode.C1C3C2 && forEncryption) {
                // C1C2C3 to C1C3C2
                out.write(retBytes, 1, 65);
                out.write(retBytes, retBytes.length - 32, 32);
                out.write(retBytes, 66, retBytes.length - 98);
            }else {
                // C1C2C3
                out.write(retBytes, 1, retBytes.length - 1);
            }
            return out.toByteArray();
        }catch (Exception ex) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_CRYPT_FAILED);
        }finally {
            try {
                if(out != null) {
                    out.close();
                }
            }catch (Exception iex) {
                // ignore
            }
        }
    }
}
