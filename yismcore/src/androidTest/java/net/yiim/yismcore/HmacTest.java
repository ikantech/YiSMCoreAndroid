package net.yiim.yismcore;

import android.util.Log;

import androidx.test.runner.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Created by ikantech on 19-9-2.
 */
@RunWith(AndroidJUnit4.class)
public class HmacTest {
    private String[] algs = new String[] {
            "HmacMD5",
            "HmacSHA1",
            "HmacSHA224",
            "HmacSHA256",
            "HmacSHA384",
            "HmacSHA512",
            "HmacSHA3-224",
            "HmacSHA3-256",
            "HmacSHA3-384",
            "HmacSHA3-512",
            "HmacSM3",
            "HmacBLAKE-2S",
            "HmacBLAKE-2B"
    };

    private String[] ciphers = new String[] {
            "30CE71A73BDD908C3955A90E8F7429EF",
            "74B55B6AB2B8E438AC810435E369E3047B3951D0",
            "0408DFCB62644A61489C371AFE2C595A56C9230B5555CB276880B671",
            "B8AD08A3A547E35829B821B75370301DD8C4B06BDD7771F9B541A75914068718",
            "B9CD582CF13F8213E8F83E384F57C9D9A7206349F81380A2C863CBF112FE16F453CB78EE18A15368A2B99320097BFEEC",
            "4899F48B7873797086FC392ED8074B34306F79145CF0F9D1757E806DA2D43F3876B3C762F38015F2D3593A595AE607A6E0AA103A2A5FE502CF95051C9CD62EE1",
            "2171F6507132F7AAA1DAFE8D586C5441795356EF4014FBB0AD511647",
            "B89979EB164DBD4EDE3B22DC6E93AD6AB55CFBABAC7AC6EA9EB26512BA9DA58E",
            "623B129FBDF6DAA8C51FB4636B3CF746E895558BF77E53462FB3EE3C1C1260B0B4F93CF431DFFDCA5755DF3C3FC31982",
            "658E647CA9E8693BFE0AAE5B2E9900E3BC9B71017549E7C434D18F02C1B22B672F4485BF6EC0B4CD1FBE039A8088DA5019DE1B9C4C6A96619FD37825536F5966",
            "A8C9EFC54C6BD610D7ABB42AE60D5D46CAE3CF9CF096E1934EDD292F55E3659F",
            "6A6720DBD6BD938D28E30C81A8541901C0FF083191FF6136E963671E0DB84A82",
            "FEFF5BC51856A83925BA5C80829275B50F944C2D6E644A47DE210D4C00C30A560701AAEEFF495EE8885F3A35206EA8C44F5381E34EF8F5507F8BDB15E13AF56A"
    };

    @Test
    public void testHmac() {
        try {
            byte[] plainBytes = new byte[]{0x31, 0x32, 0x33, 0x34, 0x35, 0x36};
            YiCryptoKey cryptoKey = new YiCryptoKey();
            cryptoKey.initSymmetricKey(plainBytes, null);

            for(int i = 0; i < algs.length; i++) {
                byte[] cipherBytes = YiSMCore.getInstance(algs[i])
                        .initForCipher(false, cryptoKey)
                        .update(plainBytes, 0, 3)
                        .doFinal(plainBytes, 3, plainBytes.length - 3);
                Log.d("YiLog", algs[i] + " : " + YiSMCore.toHexString(cipherBytes));

                Assert.assertArrayEquals(YiSMCore.fromHexString(ciphers[i]), cipherBytes);
            }
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }
}
