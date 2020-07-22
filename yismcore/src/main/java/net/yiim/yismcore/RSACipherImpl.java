package net.yiim.yismcore;

// Created by saint on 2020-04-29.

import java.io.ByteArrayOutputStream;

final class RSACipherImpl implements ICrypto {
    private static final int RSA_PKCS_V15 = 1;
    private static final int RSA_PKCS_V21 = 4;
    private static final int RSA_NO_PADDING = 3;

    private YiSMCore.Algorithm algorithm;
    private ByteArrayOutputStream buf;
    private ByteArrayOutputStream bout;
    private boolean forEncryption;
    private boolean isPrivate = false;
    private int mdType;
    private int paddingType;
    private int inputBlockSize = 0;
    private YiCryptoKey cryptoKey;

    RSACipherImpl(YiSMCore.Algorithm algorithm) throws YiCryptoException {
        this.algorithm = algorithm;
        if(algorithm.equals(YiSMCore.Algorithm.RSA_NOPADDING)) {
            paddingType = RSA_NO_PADDING;
            mdType = YiSMCore.Algorithm.MD5.getType();
        }else if(algorithm.equals(YiSMCore.Algorithm.RSA_PKCS1PADDING)) {
            paddingType = RSA_PKCS_V15;
            mdType = YiSMCore.Algorithm.MD5.getType();
        }else {
            paddingType = RSA_PKCS_V21;
            mdType = algorithm.getType();
        }
        bout = new ByteArrayOutputStream(1024);
    }

    public ICrypto init(boolean forWhat, YiCryptoKey cryptoKey) throws YiCryptoException {
        isPrivate = !cryptoKey.checkRSAPrivateKeyFail();
        if(!isPrivate && cryptoKey.checkRSAPublicKeyFail()) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }

        if(forWhat) {
            inputBlockSize = cryptoKey.getRSA_NBytes().length;
            if(algorithm.equals(YiSMCore.Algorithm.RSA_PKCS1PADDING)) {
                inputBlockSize -= 11;
            }else if(algorithm.equals(YiSMCore.Algorithm.RSA_NOPADDING)) {
                inputBlockSize -= 1;
            }else {
                inputBlockSize = inputBlockSize - 2 - 2 * DigestImpl.getDigestSize(algorithm.getType());
            }
        }else {
            inputBlockSize = cryptoKey.getRSA_NBytes().length;
        }
        if(inputBlockSize < 0) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
        this.forEncryption = forWhat;
        this.cryptoKey = cryptoKey;
        buf = new ByteArrayOutputStream(cryptoKey.getRSA_NBytes().length + 8);
        return this;
    }

    byte[] processBlock(byte[] bytes) throws YiCryptoException {
        if(paddingType == RSA_NO_PADDING) {
            if(forEncryption) {
                byte[] buf = new byte[inputBlockSize + 1];
                buf[0] = 0;
                System.arraycopy(bytes, 0, buf, 1, bytes.length);
                return YiSMCore.checkResultBytes(NativeSupport._rsaCrypt(cryptoKey.rsaPtr, isPrivate, forEncryption,
                        paddingType, mdType, buf));
            }else {
                return YiSMCore.checkResultBytes(NativeSupport._rsaCrypt(cryptoKey.rsaPtr, isPrivate, forEncryption,
                        paddingType, mdType, bytes), 2);

            }
        }else {
            return YiSMCore.checkResultBytes(NativeSupport._rsaCrypt(cryptoKey.rsaPtr, isPrivate, forEncryption,
                    paddingType, mdType, bytes));
        }
    }

    @Override
    public void update(byte[] input, int offset, int len) throws YiCryptoException {
        try {
            int expLen = len + buf.size();
            while (expLen >= inputBlockSize) {
                if (buf.size() < inputBlockSize) {
                    int iLen = inputBlockSize - buf.size();
                    if (iLen > 0) {
                        int l = Math.min(iLen, len);
                        buf.write(input, offset, l);
                        offset += l;
                        len -= l;
                    }
                }
                if (buf.size() == inputBlockSize) {
                    byte[] bufBytes = buf.toByteArray();
                    bout.write(processBlock(bufBytes));
                    buf.reset();
                    expLen -= inputBlockSize;
                }
            }

            if(len > 0) {
                buf.write(input, offset, len);
            }
        }catch (Exception ex) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_CRYPT_FAILED);
        }
    }

    @Override
    public byte[] doFinal() throws YiCryptoException {
        try {
            if(forEncryption) {
                if(algorithm.equals(YiSMCore.Algorithm.RSA_NOPADDING)) {
                    // 加密，no padding情况下，长度必须等于InputBlockSize
                    if(buf.size() > 0 && buf.size() != inputBlockSize) {
                        throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_PADDING);
                    }
                }
            }else {
                // 解密，所以长度不管是不是有填充，都必须等于InputBlockSize
                if(buf.size() > 0 && buf.size() != inputBlockSize) {
                    throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_PADDING);
                }
            }
            if(buf.size() > 0) {
                byte[] bufBytes = buf.toByteArray();
                bout.write(processBlock(bufBytes));
                buf.reset();
            }
            return bout.toByteArray();
        } catch (YiCryptoException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_CRYPT_FAILED);
        }
    }
}
