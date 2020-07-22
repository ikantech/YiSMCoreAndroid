package net.yiim.yismcore;

// Created by saint on 2020-03-16.

import android.util.Log;

import androidx.test.runner.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class SM2SignTest {
    private String sm2PrivK = "6B8B4567327B23C6643C98696633487374B0DC5119495CFF2AE8944A625558EC";

    private String[] algs = new String[] {
            "SM3WithSM2", "SHA256WithSM2", "SHA3-256WithSM2", "BLAKE-2SWithSM2"
    };
    private byte[] plainBytes = new byte[]{0x61, 0x62, 0x63};
    private byte[][] userIds = new byte[][] {
            null,
            {0x61, 0x62, 0x63},
    };

    private String[] defaultUserIDSignDatas = new String[] {
            "D81B28EA714DADBEA553A3FCB19AEF125282FB0B59DA2B6868B4846B6022157E33F61EF7FA041B04F91A28E646B656D31A092F0BCA5586A2090CB65098BBC57E",
            "88C146200F42AE6D391AE9C5F39C62867A882525C2F792E9C954DBFD30D20B8A14868742B4C84DB3004DE34A86FE3F1FB9531BA583681BD6D834F58304F42B24",
            "F181435CB61A50A56C5FA12F39A5FCDC60047A5BE497B00B4BB755FBB1EACE4399083B0EBB847560F0EAAECF52D67CC0B3C345BEA32E3BEA8524EF09C53ECD21",
            "788142E72F4DCDEB05035D0076F227F3137AA05B36DDF9FEFB90B990B851ADB2A0011242051520EA4C84EE0EF804AE7E39512A935A35E483F7DC59B4D17963FF",

            "F35CF9EDDDB46BA53A192954878B1C77197F5D9A3CB63735B190B21C58B61797AD5160AB9F63A223B1E9BB9F95D4C3961B9D7DEABC63F1314DAA21F99A249E8E",
            "2C7CE4B51BA22A240F018E8C27C8BBECE8313CC3B81A0E02F2C2B421EB7038C64B99BD94655D875044EBF35206A9F7B02F6ED3699C37F0BE4291205CDAFBCC4C",
            "A11E4E12694A0700CFF11DB7691855026B8E2D1FC0089085791E98176EBC9C39974803A6B3041B17F99EE6862F62F0BA9F3990B7EE749FEE338D37AE80605B36",
            "788142E72F4DCDEB05035D0076F227F3137AA05B36DDF9FEFB90B990B851ADB2A0011242051520EA4C84EE0EF804AE7E39512A935A35E483F7DC59B4D17963FF"
    };
    private String[] customUserIDSignDatas = new String[] {
            "678CBD694C94015CB8DB9A0CE37A40EECD318909209253D54150E5C7AE652696CF0E4A9AA638DC5ACF3A9F656C11E4E0C884ADEB5B8C0E72ED08911C1B2C6B04",
            "F1F8FB73DE53C72D467A89696BA435F4B74CF7BAA7FC0C888A6959A267C32EF9CF577493A7B4E1FDC6F0F87EB25FF5F156C61C920BFF3388DFBA339FD43CE98A",
            "0A4D3C21C6140361C8FA997EEF3C9E8C0FE2E97D02CDE2764A6B4CC323DD12928B4DC067978D035EDA034FA082A3CD19E67C18F35DA0FF6453EC32A883B1D3E3",
            "CEEE49B70739347E00E92548EC74CD61C0D612F07CFAB6E8FAA44DABAD2E065CA4F48356D1800F7056A4979C7942D7CCC89858E5A7BA636054C84BB9F6AEF682",

            "C4A04E1A90C369400D33F093FB4F52F1DDBB2984D0232C6D28E3EA6F98417881915116EC42CA093CC654677B09415E49A6637A1BD9DD32E49B40995675E3EFF7",
            "0A2A6348C871B2CBC1CF1741EF87CF4B695E55D3848D970BF4EFD08AFC50803DC0DA25AF7D4E73BE1E46B7462DCD60E4CE25D5B159974BDBFFF22E1829FB18EA",
            "7FBD051A8EF84B73881A8CC6D881595BC834FFDDA2C10F734718D33D7CFD41D4FDFA70D758E71C177B2755AA8CB544EDD7733C3A89A9656A42BC4EA56DF246D3",
            "CEEE49B70739347E00E92548EC74CD61C0D612F07CFAB6E8FAA44DABAD2E065CA4F48356D1800F7056A4979C7942D7CCC89858E5A7BA636054C84BB9F6AEF682"
    };

    @Test
    public void testSM2() {
        try {
            YiCryptoKey cryptoKey = YiCryptoKey.genSM2KeyPair();

            for (byte[] userId: userIds) {
                cryptoKey.setSM2UserId(userId);

                for (String alg: algs) {
                    byte[] signBytes = YiSMCore.getInstance(alg)
                            .initForSigner(true, cryptoKey)
                            .update(plainBytes, 0, plainBytes.length)
                            .generateSignature();

                    Log.d("YiLog", YiSMCore.toHexString(signBytes));

                    boolean verified = YiSMCore.getInstance(alg)
                            .initForSigner(false, cryptoKey)
                            .update(plainBytes, 0, plainBytes.length)
                            .verifySignature(signBytes);
                    Assert.assertTrue(verified);
                }
            }

            cryptoKey = new YiCryptoKey();
            cryptoKey.initSM2PrivateKey(YiSMCore.fromHexString(sm2PrivK));

            for (int i = 0; i < defaultUserIDSignDatas.length; i++) {
                cryptoKey.setSM2UserId(userIds[0]);
                boolean verified = YiSMCore.getInstance(algs[i % 4])
                        .initForSigner(false, cryptoKey)
                        .update(plainBytes, 0, plainBytes.length)
                        .verifySignature(YiSMCore.fromHexString(defaultUserIDSignDatas[i]));
                Assert.assertTrue(verified);
            }

            for (int i = 0; i < customUserIDSignDatas.length; i++) {
                cryptoKey.setSM2UserId(userIds[1]);
                boolean verified = YiSMCore.getInstance(algs[i % 4])
                        .initForSigner(false, cryptoKey)
                        .update(plainBytes, 0, plainBytes.length)
                        .verifySignature(YiSMCore.fromHexString(customUserIDSignDatas[i]));
                Assert.assertTrue(verified);
            }
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }
}
