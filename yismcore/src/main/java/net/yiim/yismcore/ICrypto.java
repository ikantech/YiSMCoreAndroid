package net.yiim.yismcore;

interface ICrypto {
    void update(byte[] input, int offset, int len) throws YiCryptoException;
    byte[] doFinal() throws YiCryptoException;
}
