package net.yiim.yismcore;

// Created by saint on 2020-06-20.

class NativeSupport {

    static {
        System.loadLibrary("yismcore");
    }

    // Digest
    synchronized static native long _createDigestCtx(int algorithm);
    synchronized static native void _destroyDigestCtx(long ptr);
    synchronized static native int _digestUpdate(long ptr, byte[] input, int offset, int len);
    synchronized static native byte[] _digestFinal(long ptr);

    // Cipher
    synchronized static native long _createCipherCtx();
    synchronized static native void _destroyCipherCtx(long ptr);
    synchronized static native int _cipherInit(long ptr, byte[] keyBytes, byte[] ivBytes,
                                               boolean noPadding, boolean forEncryption, int algorithm);
    synchronized static native byte[] _cipherUpdate(long ptr, byte[] input, int offset, int len);
    synchronized static native byte[] _cipherFinal(long ptr);

    // Hmac
    synchronized static native long _createHmacCtx(int algorithm, byte[] keyBytes);
    synchronized static native void _destroyHmacCtx(long ptr);
    synchronized static native int _hmacUpdate(long ptr, byte[] input, int offset, int len);
    synchronized static native byte[] _hmacFinal(long ptr);

    // sm2
    synchronized static native long _createSM2Ctx();
    synchronized static native void _destroySM2Ctx(long ptr);
    synchronized static native byte[] _sm2CtxInit(long ptr, boolean isPrivate, byte[] keyBytes);
    synchronized static native byte[] _sm2GenKeypair(long ptr);

    synchronized static native byte[] _sm2Crypt(long ptr, boolean forEncryption,
                                                int mdtype, byte[] input);

    synchronized static native byte[] _sm2SignOrVerify(long ptr, int mdtype, byte[] userId,
                                                       byte[] bytes, byte[] signData);

    // rsa
    synchronized static native long _createRSACtx();
    synchronized static native void _destroyRSACtx(long ptr);

    synchronized static native byte[] _rsaGenKeypair(long ptr, int publicExponent, int strength);
    synchronized static native byte[] _rsaCtxInit(long ptr, boolean isPrivate,
                                                  byte[] nBytes, byte[] eBytes,
                                                  byte[] dBytes, byte[] pBytes,
                                                  byte[] qBytes);
    synchronized static native byte[] _rsaCtxInitFromPem(long ptr, boolean isPrivate, String pemKey, boolean pkcs1);
    synchronized static native byte[] _rsaCtxToPem(long ptr, boolean isPrivate, boolean pkcs1);

    synchronized static native byte[] _rsaCrypt(long ptr, boolean isPrivate, boolean forEncryption,
                                                int paddingType, int mdType, byte[] input);

    synchronized static native byte[] _rsaSignOrVerify(long ptr, boolean isPrivate,
                                                       int paddingType, int mdType,
                                                       byte[] mdBytes, byte[] signData);
}
