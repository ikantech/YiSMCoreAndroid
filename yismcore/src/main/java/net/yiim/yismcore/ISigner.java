package net.yiim.yismcore;

// Created by saint on 2020-03-16.

interface ISigner extends ICrypto {
    byte[] generateSignature() throws YiCryptoException;

    boolean verifySignature(byte[] signature) throws YiCryptoException;
}
