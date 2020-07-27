package net.yiim.yismcore;

// Created by saint on 2020-03-11.

import android.util.Log;

import androidx.test.runner.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class SM2CipherTest {
    // 004DE8D7B60E929ED1DCF8C1A94A0B06B606EC429F98205DB729119F3A5639B3
    private String sm2PrivK = "6B8B4567327B23C6643C98696633487374B0DC5119495CFF2AE8944A625558EC";
    private String sm2PubK = "040148E6AF89A0E132E4E7CDA26DF2C2AEB53B741FD00AE85C78CF6EBA13E939B12F58B1E8A661EBF3395459F28945D381259BEEDA76B4886FABF5EE0A55ADEEB2";
    private String sm2CompressedPubK = "020148E6AF89A0E132E4E7CDA26DF2C2AEB53B741FD00AE85C78CF6EBA13E939B1";

    private String[] cipherAlgs = new String[] {
            "SM2WithSM3",
            "SM2WithSHA256",
            "SM2WithSHA3-256",
            "SM2WithBLAKE-2S"
    };

    private String[][] sm2CipherBytes = new String[][] {
            {
                    "04EB04AAE0D53FBA1E3611D5B9ED6EFA3EE5BA57C41AA7A09DDC5816AF09057757CE6FA0678392F4716E45F58E7322C76D5997B1FE44C36D8A5A59B146EE162B93" +
                            "4C89B7" +
                            "7B13DD1DCB76BF6C2F4701876D6673807FACE8696A8D5FD24A473A9DAFC8A44E",
                    "04EB04AAE0D53FBA1E3611D5B9ED6EFA3EE5BA57C41AA7A09DDC5816AF09057757CE6FA0678392F4716E45F58E7322C76D5997B1FE44C36D8A5A59B146EE162B93" +
                            "7B13DD1DCB76BF6C2F4701876D6673807FACE8696A8D5FD24A473A9DAFC8A44E" +
                            "4C89B7"
            },
            {
                    "04AA307A6575D8348037CEC6F860F6312317B34C81838834EDB008F54A2E590FDC593293D89FE9C933E6CE7E91CD4ABF81EC3C26395622B65754A8C0EE8FB354E9" +
                            "CD951D" +
                            "D2C2CA92B59B388758F462337B9D52EED52AF7A9E1A57BB76E4CB082EA31AAE2",
                    "04AA307A6575D8348037CEC6F860F6312317B34C81838834EDB008F54A2E590FDC593293D89FE9C933E6CE7E91CD4ABF81EC3C26395622B65754A8C0EE8FB354E9" +
                            "D2C2CA92B59B388758F462337B9D52EED52AF7A9E1A57BB76E4CB082EA31AAE2" +
                            "CD951D"
            },
            {
                    "0493F20E43CD0EDE9D6142D276F4DF7B640F992C91DF15F871BBD09207F9BB2740670A00B80B6BBD2EF5BBC7BB82AC44C5CBA65474E5E3420D34816DC70672E2C0" +
                            "60AA3B" +
                            "05F986CB08D5461717EE46BE7E51B3A385919FE5CE101DDD4CF2F824E25EE6D3",
                    "0493F20E43CD0EDE9D6142D276F4DF7B640F992C91DF15F871BBD09207F9BB2740670A00B80B6BBD2EF5BBC7BB82AC44C5CBA65474E5E3420D34816DC70672E2C0" +
                            "05F986CB08D5461717EE46BE7E51B3A385919FE5CE101DDD4CF2F824E25EE6D3" +
                            "60AA3B"
            },
            {
                    "043FD6B6B61BD6000DD92FD72013B2F50D0C2795E93C0E12B526DD21B35A73688CC2793FC637EDBBA13A08D8ED6EB4501FEFF34924162CC2AAE7F802CEAA18F4CD" +
                            "B8E15A" +
                            "D4BF567AA5D6BA8BC570265355824BEE434EF3D7EF7A66FE8D18BEFF770E6AA6",
                    "043FD6B6B61BD6000DD92FD72013B2F50D0C2795E93C0E12B526DD21B35A73688CC2793FC637EDBBA13A08D8ED6EB4501FEFF34924162CC2AAE7F802CEAA18F4CD" +
                            "D4BF567AA5D6BA8BC570265355824BEE434EF3D7EF7A66FE8D18BEFF770E6AA6" +
                            "B8E15A"
            }

    };

    @Test
    public void testGenKey() {
        try {
            YiCryptoKey cryptoKey = YiCryptoKey.genSM2KeyPair();

            // 私钥
            byte[] privK = cryptoKey.getSM2PrivateKey();
            // 公钥
            byte[] pubK = cryptoKey.getSM2PublicKey(false);
            // 压缩公钥
            byte[] compressedPubK = cryptoKey.getSM2PublicKey(true);

            Log.d("YiLog", "private key: " + YiSMCore.toHexString(privK));
            Log.d("YiLog", "public key: " + YiSMCore.toHexString(pubK));
            Log.d("YiLog", "compressed public key: " + YiSMCore.toHexString(compressedPubK));
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    @Test
    public void testCreateKey() {
        try {
            byte[] privKBytes = YiSMCore.fromHexString(sm2PrivK);

            YiCryptoKey cryptoKey = new YiCryptoKey();
            cryptoKey.setupSM2PrivateKey(privKBytes);

            Assert.assertArrayEquals(privKBytes, cryptoKey.getSM2PrivateKey());

            // 私钥生成公钥
            Assert.assertArrayEquals(YiSMCore.fromHexString(sm2PubK), cryptoKey.getSM2PublicKey(false));
            Assert.assertArrayEquals(YiSMCore.fromHexString(sm2CompressedPubK), cryptoKey.getSM2PublicKey(true));

            // 公钥压缩
            cryptoKey = new YiCryptoKey();
            cryptoKey.setupSM2PublicKey(YiSMCore.fromHexString(sm2PubK));
            Assert.assertArrayEquals(YiSMCore.fromHexString(sm2CompressedPubK), cryptoKey.getSM2PublicKey(true));

            // 公钥解压
            cryptoKey = new YiCryptoKey();
            cryptoKey.setupSM2PublicKey(YiSMCore.fromHexString(sm2CompressedPubK));
            Assert.assertArrayEquals(YiSMCore.fromHexString(sm2PubK), cryptoKey.getSM2PublicKey(false));
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    @Test
    public void testCipher() {
        try {
            byte[] plainBytes = new byte[]{0x61, 0x62, 0x63};

            YiCryptoKey pubK = new YiCryptoKey();
            pubK.setupSM2PublicKey(YiSMCore.fromHexString(sm2CompressedPubK));

            YiCryptoKey privK = new YiCryptoKey();
            // cipher ignore this parameter
            privK.setSM2UserId(new byte[]{0x61, 0x62, 0x63});
            privK.setupSM2PrivateKey(YiSMCore.fromHexString(sm2PrivK));

            for (int i = 0; i < cipherAlgs.length; i++) {
                String alg = cipherAlgs[i];

                // C1C2C3
                byte[] cipherBytes1 = YiSMCore.getInstance(alg + "/C1C2C3")
                        .setupForCipher(true, pubK)
                        .doFinal(plainBytes);
                byte[] plainBytes1 = YiSMCore.getInstance(alg + "/C1C2C3")
                        .setupForCipher(false, privK)
                        .doFinal(cipherBytes1);

                Log.d("YiLog", YiSMCore.toHexString(cipherBytes1));
                Assert.assertArrayEquals(plainBytes, plainBytes1);

                // C1C3C2
                cipherBytes1 = YiSMCore.getInstance(alg + "/C1C3C2")
                        .setupForCipher(true, pubK)
                        .doFinal(plainBytes);
                plainBytes1 = YiSMCore.getInstance(alg + "/C1C3C2")
                        .setupForCipher(false, privK)
                        .doFinal(cipherBytes1);

                Log.d("YiLog", YiSMCore.toHexString(cipherBytes1));
                Assert.assertArrayEquals(plainBytes, plainBytes1);

                // C1C2C3 test
                byte[] cipherBytes2 = YiSMCore.fromHexString(sm2CipherBytes[i][0]);
                byte[] plainBytes2 = YiSMCore.getInstance(alg + "/C1C2C3")
                        .setupForCipher(false, privK)
                        .doFinal(cipherBytes2);
                Assert.assertArrayEquals(plainBytes, plainBytes2);

                // C1C3C2 test
                byte[] cipherBytes3 = YiSMCore.fromHexString(sm2CipherBytes[i][1]);
                byte[] plainBytes3 = YiSMCore.getInstance(alg + "/C1C3C2")
                        .setupForCipher(false, privK)
                        .doFinal(cipherBytes3);
                Assert.assertArrayEquals(plainBytes, plainBytes3);
            }
        }catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail(ex.getMessage());
        }
    }
}
