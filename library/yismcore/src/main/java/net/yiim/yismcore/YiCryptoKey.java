package net.yiim.yismcore;

// Created by saint on 2019-10-14.

import android.text.TextUtils;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;

public class YiCryptoKey {
    // 对称加密算法
    private byte[] symmetricKey = null;
    private byte[] ivBytes = null;


    // sm2
    long sm2Ptr = 0L;
    private byte[] sm2PrivKBytes = null;
    private int sm2PubK_YTile = 0x02;
    private byte[] sm2PubK_XBytes = null;
    private byte[] sm2PubK_YBytes = null;
    private byte[] sm2UserId = null;

    // rsa
    long rsaPtr = 0L;
    private byte[] rsaNBytes = null;
    private byte[] rsaEBytes = null;
    private byte[] rsaDBytes = null;
    private byte[] rsaPBytes = null;
    private byte[] rsaQBytes = null;
    private byte[] rsaDPBytes = null;
    private byte[] rsaDQBytes = null;
    private byte[] rsaQInvBytes = null;

    @Override
    protected void finalize() throws Throwable {
        if(sm2Ptr != 0L) {
            NativeSupport._destroySM2Ctx(sm2Ptr);
        }
        if(rsaPtr != 0L) {
            NativeSupport._destroyRSACtx(rsaPtr);
        }
        super.finalize();
    }

    /**
     * 对称加密算法，初始化密钥
     * @param keyBytes 密钥数据
     * @param ivBytes 向量数据
     * @throws YiCryptoException 密钥非法时抛出
     */
    public void setupSymmetricKey(byte[] keyBytes, byte[] ivBytes) throws YiCryptoException {
        if(keyBytes == null || keyBytes.length < 1) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }

        this.symmetricKey = keyBytes;
        this.ivBytes = ivBytes;
    }

    /**
     * 对称加密算法，获取密钥
     * @return 对称密钥数据
     */
    public byte[] getSymmetricKey() {
        return symmetricKey;
    }

    /**
     * 对称加密算法，获取向量
     * @return 向量数据
     */
    public byte[] getIV() {
        return ivBytes;
    }

    private void setupForSM2() throws YiCryptoException {
        this.sm2Ptr = NativeSupport._createSM2Ctx();
        if(this.sm2Ptr == 0L) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_PARAMS);
        }
    }

    private void setupForRSA() throws YiCryptoException {
        this.rsaPtr = NativeSupport._createRSACtx();
        if(this.rsaPtr == 0L) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_PARAMS);
        }
    }

    private void genSM2Key() throws YiCryptoException {
        byte[] retBytes = NativeSupport._sm2GenKeypair(sm2Ptr);
        if(retBytes[0] != 0) {
            throw new YiCryptoException(YiCryptoErrorCode.valuesOf(retBytes[0]));
        }
        sm2PrivKBytes = new byte[32];
        System.arraycopy(retBytes, 1, sm2PrivKBytes, 0, 32);
        sm2PubK_YTile = retBytes[33];
        sm2PubK_XBytes = new byte[32];
        System.arraycopy(retBytes, 34, sm2PubK_XBytes, 0, 32);
        sm2PubK_YBytes = new byte[32];
        System.arraycopy(retBytes, 66, sm2PubK_YBytes, 0, 32);
    }

    /**
     * 非对称加密算法，初始化国密SM2私钥
     * @param keyBytes 32字节密钥数据
     * @throws YiCryptoException 密钥非法时抛出
     */
    public void setupSM2PrivateKey(byte[] keyBytes) throws YiCryptoException {
        if(keyBytes == null || keyBytes.length != 32) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
        this.setupForSM2();
        byte[] retBytes = NativeSupport._sm2CtxInit(sm2Ptr, true, keyBytes);
        if(retBytes[0] != 0) {
            throw new YiCryptoException(YiCryptoErrorCode.valuesOf(retBytes[0]));
        }
        sm2PubK_YTile = retBytes[1];
        sm2PubK_XBytes = new byte[32];
        System.arraycopy(retBytes, 2, sm2PubK_XBytes, 0, 32);
        sm2PubK_YBytes = new byte[32];
        System.arraycopy(retBytes, 34, sm2PubK_YBytes, 0, 32);
        this.sm2PrivKBytes = keyBytes;
    }

    /**
     * 非对称加密算法，获取国密SM2私钥分量
     * @return 32字节密钥数据
     * @throws YiCryptoException 密钥非法时抛出
     */
    public byte[] getSM2PrivateKey() throws YiCryptoException {
        if(sm2Ptr == 0L) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
        return sm2PrivKBytes;
    }

    /**
     * 非对称加密算法，初始化国密SM2公钥，支持压缩公钥及非压缩公钥
     * 非压缩公钥PC||x||y，其中PC=4
     * 压缩公钥yTilde||x
     * @param keyBytes SM2公钥
     * @throws YiCryptoException 密钥非法时抛出
     */
    public void setupSM2PublicKey(byte[] keyBytes) throws YiCryptoException {
        if(keyBytes == null || (keyBytes.length != 33 && keyBytes.length != 65)) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
        byte firstByte = keyBytes[0];
        if(firstByte != 0x04 && firstByte != 0x03 && firstByte != 0x02) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }

        this.setupForSM2();
        byte[] retBytes = NativeSupport._sm2CtxInit(sm2Ptr, false, keyBytes);
        if(retBytes[0] != 0) {
            throw new YiCryptoException(YiCryptoErrorCode.valuesOf(retBytes[0]));
        }
        sm2PubK_YTile = retBytes[1];
        sm2PubK_XBytes = new byte[32];
        System.arraycopy(retBytes, 2, sm2PubK_XBytes, 0, 32);
        sm2PubK_YBytes = new byte[32];
        System.arraycopy(retBytes, 34, sm2PubK_YBytes, 0, 32);
    }

    /**
     * 非对称加密算法，获取国密SM2公钥
     * 如果初始化过公钥，则直接从公钥中获取
     * 如果初始化过私钥，则由私钥生成公钥
     * @return 压缩公钥或非压缩公钥
     * @throws YiCryptoException 密钥非法时抛出
     */
    public byte[] getSM2PublicKey(boolean compressed) throws YiCryptoException {
        if(sm2Ptr == 0L) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }

        ByteArrayOutputStream out = null;
        try {
            out = new ByteArrayOutputStream(65);
            if(!compressed) {
                out.write(0x04);
                out.write(sm2PubK_XBytes);
                out.write(sm2PubK_YBytes);
            }else {
                out.write(sm2PubK_YTile);
                out.write(sm2PubK_XBytes);
            }
            return out.toByteArray();
        }catch (Exception ex) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }finally {
            if(out != null) {
                try {
                    out.close();
                }catch (Exception ex) {
                    // ignore
                }
            }
        }
    }

    boolean checkSM2PublicKeyFail() {
        return sm2Ptr == 0L || sm2PubK_XBytes == null || sm2PubK_YBytes == null;
    }

    boolean checkSM2PrivateKeyFail() {
        return sm2Ptr == 0L || sm2PrivKBytes == null;
    }

    public byte[] getSM2UserId() {
        return sm2UserId;
    }

    public void setSM2UserId(byte[] sm2UserId) {
        this.sm2UserId = sm2UserId;
    }

    /**
     * 非对称加密算法，国密SM2密钥对生成
     * @return 返回生成的国密SM2密钥对
     * @throws YiCryptoException 计算错误时抛出
     */
    public static YiCryptoKey genSM2KeyPair() throws YiCryptoException {
        YiCryptoKey cryptoKey = new YiCryptoKey();
        cryptoKey.setupForSM2();
        cryptoKey.genSM2Key();
        return cryptoKey;
    }

    private void dealRSAReturnBytes(byte[] retBytes, boolean isPrivate) {
        int rLen = 1;
        // N
        int iLen = ((retBytes[rLen++] & 0x0FF) << 8 ) |
                (retBytes[rLen++] & 0x0FF);
        rsaNBytes = new byte[iLen];
        System.arraycopy(retBytes, rLen, rsaNBytes, 0, iLen);
        rLen += iLen;

        // E
        iLen = ((retBytes[rLen++] & 0x0FF) << 8 ) |
                (retBytes[rLen++] & 0x0FF);
        rsaEBytes = new byte[iLen];
        System.arraycopy(retBytes, rLen, rsaEBytes, 0, iLen);
        rLen += iLen;

        if(isPrivate) {
            // D
            iLen = ((retBytes[rLen++] & 0x0FF) << 8) |
                    (retBytes[rLen++] & 0x0FF);
            rsaDBytes = new byte[iLen];
            System.arraycopy(retBytes, rLen, rsaDBytes, 0, iLen);
            rLen += iLen;

            // P
            iLen = ((retBytes[rLen++] & 0x0FF) << 8) |
                    (retBytes[rLen++] & 0x0FF);
            rsaPBytes = new byte[iLen];
            System.arraycopy(retBytes, rLen, rsaPBytes, 0, iLen);
            rLen += iLen;

            // Q
            iLen = ((retBytes[rLen++] & 0x0FF) << 8) |
                    (retBytes[rLen++] & 0x0FF);
            rsaQBytes = new byte[iLen];
            System.arraycopy(retBytes, rLen, rsaQBytes, 0, iLen);
            rLen += iLen;

            // DP
            iLen = ((retBytes[rLen++] & 0x0FF) << 8) |
                    (retBytes[rLen++] & 0x0FF);
            rsaDPBytes = new byte[iLen];
            System.arraycopy(retBytes, rLen, rsaDPBytes, 0, iLen);
            rLen += iLen;

            // DQ
            iLen = ((retBytes[rLen++] & 0x0FF) << 8) |
                    (retBytes[rLen++] & 0x0FF);
            rsaDQBytes = new byte[iLen];
            System.arraycopy(retBytes, rLen, rsaDQBytes, 0, iLen);
            rLen += iLen;

            // QInv
            iLen = ((retBytes[rLen++] & 0x0FF) << 8) |
                    (retBytes[rLen++] & 0x0FF);
            rsaQInvBytes = new byte[iLen];
            System.arraycopy(retBytes, rLen, rsaQInvBytes, 0, iLen);
        }
    }

    private void genRSAKey(int publicExponent, int strength) throws YiCryptoException {
        byte[] retBytes = NativeSupport._rsaGenKeypair(rsaPtr, publicExponent, strength);
        if(retBytes[0] != 0) {
            throw new YiCryptoException(YiCryptoErrorCode.valuesOf(retBytes[0]));
        }
        dealRSAReturnBytes(retBytes, true);
    }

    public byte[] getRSA_NBytes() {
        return rsaNBytes;
    }

    public byte[] getRSA_EBytes() {
        return rsaEBytes;
    }

    public byte[] getRSA_DBytes() {
        return rsaDBytes;
    }

    public byte[] getRSA_PBytes() {
        return rsaPBytes;
    }

    public byte[] getRSA_QBytes() {
        return rsaQBytes;
    }

    public byte[] getRSA_DPBytes() {
        return rsaDPBytes;
    }

    public byte[] getRSA_DQBytes() {
        return rsaDQBytes;
    }

    public byte[] getRSA_QInvBytes() {
        return rsaQInvBytes;
    }

    boolean checkRSAPrivateKeyFail() {
        return rsaNBytes == null || rsaEBytes == null || rsaDBytes == null ||
                rsaPBytes == null || rsaQBytes == null || rsaDPBytes == null ||
                rsaDQBytes == null || rsaQInvBytes == null;
    }

    boolean checkRSAPublicKeyFail() {
        return rsaNBytes == null || rsaEBytes == null;
    }

    public void setupRSAPublicKeyFromRaw(byte[] nBytes, byte[] eBytes) throws YiCryptoException {
        if(nBytes == null || eBytes == null) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
        try {
            this.setupForRSA();
            byte[] retBytes = NativeSupport._rsaCtxInit(rsaPtr, false, nBytes,
                    eBytes, null, null, null);
            if(retBytes[0] != 0) {
                throw new YiCryptoException(YiCryptoErrorCode.valuesOf(retBytes[0]));
            }
            dealRSAReturnBytes(retBytes, false);
        }catch (Exception ex) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
    }

    public void setupRSAPrivateKeyFromRaw(byte[] nBytes, byte[] eBytes, byte[] dBytes,
                                          byte[] pBytes, byte[] qBytes) throws YiCryptoException {
        if (nBytes == null || eBytes == null || dBytes == null ||
                pBytes == null || qBytes == null) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
        try {
            this.setupForRSA();
            byte[] retBytes = NativeSupport._rsaCtxInit(rsaPtr, true, nBytes,
                    eBytes, dBytes, pBytes, qBytes);
            if(retBytes[0] != 0) {
                throw new YiCryptoException(YiCryptoErrorCode.valuesOf(retBytes[0]));
            }
            dealRSAReturnBytes(retBytes, true);
        }catch (Exception ex) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
    }

    public void setupRSAKeyFromPEM(String pemStr) throws YiCryptoException {
        if(TextUtils.isEmpty(pemStr)) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
        try {
            this.setupForRSA();
            pemStr = pemStr.replaceAll("\r*\n*$", "");
            boolean isPrivate;
            boolean isPKCS1;

            if(pemStr.startsWith("-----BEGIN RSA PRIVATE KEY-----") &&
                    pemStr.endsWith("-----END RSA PRIVATE KEY-----")) {
                // pkcs#1 private key
                isPrivate = true;
                isPKCS1 = true;
            }else if(pemStr.startsWith("-----BEGIN PRIVATE KEY-----") &&
                    pemStr.endsWith("-----END PRIVATE KEY-----")) {
                // pkcs#8 private key
                isPrivate = true;
                isPKCS1 = false;
            }else if(pemStr.startsWith("-----BEGIN RSA PUBLIC KEY-----") &&
                    pemStr.endsWith("-----END RSA PUBLIC KEY-----")) {
                // pkcs#1 public key
                isPrivate = false;
                isPKCS1 = true;
            }else if(pemStr.startsWith("-----BEGIN PUBLIC KEY-----") &&
                    pemStr.endsWith("-----END PUBLIC KEY-----")) {
                // pkcs#8 public key
                isPrivate = false;
                isPKCS1 = false;
            }else {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }

            byte[] retBytes = NativeSupport._rsaCtxInitFromPem(rsaPtr, isPrivate, pemStr, isPKCS1);
            if(retBytes[0] != 0) {
                throw new YiCryptoException(YiCryptoErrorCode.valuesOf(retBytes[0]));
            }
            dealRSAReturnBytes(retBytes, isPrivate);
        }catch (Exception ex) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
    }

    public String getRSAPublicKeyToPem(boolean pkcs1) throws YiCryptoException {
        if(rsaPtr == 0L || checkRSAPublicKeyFail()) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
        byte[] retBytes = NativeSupport._rsaCtxToPem(rsaPtr, false, pkcs1);
        if(retBytes[0] != 0) {
            throw new YiCryptoException(YiCryptoErrorCode.valuesOf(retBytes[0]));
        }
        try {
            String retPem = new String(retBytes, 1, retBytes.length - 1, "ASCII");
            return retPem.replaceAll("\r*\n*\\s*$", "");
        } catch (UnsupportedEncodingException e) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
    }

    public String getRSAPrivateKeyToPem(boolean pkcs1) throws YiCryptoException {
        if(rsaPtr == 0L || checkRSAPrivateKeyFail()) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
        byte[] retBytes = NativeSupport._rsaCtxToPem(rsaPtr, true, pkcs1);
        if(retBytes[0] != 0) {
            throw new YiCryptoException(YiCryptoErrorCode.valuesOf(retBytes[0]));
        }
        try {
            String retPem = new String(retBytes, 1, retBytes.length - 1, "ASCII");
            return retPem.replaceAll("\r*\n*\\s*$", "");
        } catch (UnsupportedEncodingException e) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
    }

    /**
     * 非对称加密算法，国际RSA密钥对生成
     * @param strength 密钥长度
     * @return 返回生成的RSA密钥对
     * @throws YiCryptoException 计算错误时抛出
     */
    public static YiCryptoKey genRSAKeyPair(int strength) throws YiCryptoException {
        return genRSAKeyPair(0x10001, strength);
    }

    /**
     * 非对称加密算法，国际RSA密钥对生成
     * @param publicExponent 公钥指数e
     * @param strength 密钥长度
     * @return 返回生成的RSA密钥对
     * @throws YiCryptoException 计算错误时抛出
     */
    public static YiCryptoKey genRSAKeyPair(int publicExponent, int strength) throws YiCryptoException {
//        try {
//            // C++生成太慢，改用java原生生成
//            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//            RSAKeyGenParameterSpec keyGenParameterSpec = new RSAKeyGenParameterSpec(strength,
//                    BigInteger.valueOf(publicExponent));
//            keyPairGenerator.initialize(keyGenParameterSpec);
//            KeyPair keyPair = keyPairGenerator.generateKeyPair();
//            RSAPrivateCrtKey privateCrtKey = (RSAPrivateCrtKey) keyPair.getPrivate();
//            YiCryptoKey cryptoKey = new YiCryptoKey();
//            cryptoKey.setupRSAPrivateKeyFromRaw(
//                    privateCrtKey.getModulus().toByteArray(),
//                    privateCrtKey.getPublicExponent().toByteArray(),
//                    privateCrtKey.getPrivateExponent().toByteArray(),
//                    privateCrtKey.getPrimeP().toByteArray(),
//                    privateCrtKey.getPrimeQ().toByteArray());
//            return cryptoKey;
//        }catch (Exception ex) {
            YiCryptoKey cryptoKey = new YiCryptoKey();
            cryptoKey.setupForRSA();
            cryptoKey.genRSAKey(publicExponent, strength);
            return cryptoKey;
//        }
    }
}
