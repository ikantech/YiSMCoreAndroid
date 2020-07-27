package net.yiim.yismcore;

import android.util.Log;

import androidx.test.runner.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class CipherTest {
    private byte[] bytes = new byte[]{0x61, 0x62, 0x63, 0x64, 0x65};

    private String[] pkcs7Algs = new String[] {
            // AES 128
            "AES/ECB/PKCS7Padding",
            "AES/CBC/PKCS7Padding",
            // AES 192
            "AES/ECB/PKCS7Padding",
            "AES/CBC/PKCS7Padding",
            // AES 256
            "AES/ECB/PKCS7Padding",
            "AES/CBC/PKCS7Padding",
            // DES 64
            "DES/ECB/PKCS7Padding",
            "DES/CBC/PKCS7Padding",
            // 3DES 128
            "DESede/ECB/PKCS7Padding",
            "DESede/CBC/PKCS7Padding",
            // 3DES 192
            "DESede/ECB/PKCS7Padding",
            "DESede/CBC/PKCS7Padding",
            // SM4 128
            "SM4/ECB/PKCS7Padding",
            "SM4/CBC/PKCS7Padding"
    };

    private String[] noPaddingAlgs = new String[] {
            // AES 128
            "AES/ECB/NoPadding",
            "AES/CBC/NoPadding",
            // AES 192
            "AES/ECB/NoPadding",
            "AES/CBC/NoPadding",
            // AES 256
            "AES/ECB/NoPadding",
            "AES/CBC/NoPadding",
            // DES 64
            "DES/ECB/NoPadding",
            "DES/CBC/NoPadding",
            // 3DES 128
            "DESede/ECB/NoPadding",
            "DESede/CBC/NoPadding",
            // 3DES 192
            "DESede/ECB/NoPadding",
            "DESede/CBC/NoPadding",
            // SM4 128
            "SM4/ECB/NoPadding",
            "SM4/CBC/NoPadding"
    };

    private String[] keyBytes = new String[] {
            // AES 128
            "6B8B4567327B23C6643C986966334873",
            "6B8B4567327B23C6643C986966334873",
            // AES 192
            "6B8B4567327B23C6643C986966334873674695B1B6409014",
            "6B8B4567327B23C6643C986966334873674695B1B6409014",
            // AES 256
            "6B8B4567327B23C6643C986966334873674695B1B6409014B26453AEE2006862",
            "6B8B4567327B23C6643C986966334873674695B1B6409014B26453AEE2006862",
            // DES 64
            "6B8B4567327B23C6",
            "6B8B4567327B23C6",
            // 3DES 128
            "6B8B4567327B23C6643C986966334873",
            "6B8B4567327B23C6643C986966334873",
            // 3DES 192
            "6B8B4567327B23C6643C9869663348730123456789ABCDEF",
            "6B8B4567327B23C6643C9869663348730123456789ABCDEF",
            // SM4 128
            "6B8B4567327B23C6643C986966334873",
            "6B8B4567327B23C6643C986966334873",
    };

    private String[][] pkcs7Expected = new String[][] {
            {
                // AES 128 ECB
                    "C03E1A044FE0F07BBA290A2F36FBBC48",
                    "364A1DA779C18D5F5DF0DCA7E7DDCBA3",
                    "6A8C201D8371C3D147AA24DB14C93A61",
                    "893FC5E8109BB4FE427DA3E0829B962A06365FCAA270307F7642BB1003C5F5BC",
                    "893FC5E8109BB4FE427DA3E0829B962A3EDA60372B077EECA268CD20EDB26865"
            },
            {
                // AES 128 CBC
                    "5247CA45F3AC4C15DAFF8D9A15AF97EF",
                    "B9B78AD8988AD38E8507B364A4752AEE",
                    "7AD72FE4F8E703C422E9658D91CD4B60",
                    "C70C2302D74E007B4935CCC98A1B6EA7849A12C515A2864138B79689C00086D7",
                    "C70C2302D74E007B4935CCC98A1B6EA7B39569B56C635763FD1561CA5329254E"
            },
            {
                // AES 192 ECB
                    "76AF9B69741024CD23D231F11B2664AE",
                    "53A393A5A07F29E6622B3301EF8D2BE6",
                    "5A650F2B3EFD618F323C8BEA7C1CC948",
                    "69518860A1A8742806CC172DDF52F3494CB0F13B83375742898ED5DF79B5DDC6",
                    "69518860A1A8742806CC172DDF52F34912770A2B569D742DAC7530377770F64E"
            },
            {
                // AES 192 CBC
                    "DD9F682CEFC4D968680DBA333715710D",
                    "619A25AD08244C274F397A3712AA9EDA",
                    "CE976CACAA938814E7F31505B607ECE7",
                    "E25AFCE0B714C951D79D284FC595A8BE6C25FCB7537629AE1EB2DDAF45B86280",
                    "E25AFCE0B714C951D79D284FC595A8BE86EB8F03044290555439A5DF37592F6F"
            },
            {
                // AES 256 ECB
                    "9B9F35F0E66F5D7EAF1C226B11B80308",
                    "F1655E9A7E5E0C9F7459056C52F46CDC",
                    "B5846C33165F8540865E387D2801CCB4",
                    "97148D3BA9F55692BFC7A1E4ADEE4095FE53B0C50708AF537450389A17812950",
                    "97148D3BA9F55692BFC7A1E4ADEE409587A6C4A79328EEBB7E6A41BACBD2BDC7"
            },
            {
                // AES 256 CBC
                    "C503C921E92A74293E0C9C066526B131",
                    "6D41638633D65D075A950E88F7A23AC0",
                    "0006D1177797115A7C49C1F618ED789E",
                    "A55E2225E21CB7C785A50E0199AE2DF936FC03C4851FB58B7A5EC2DDACE6D5DA",
                    "A55E2225E21CB7C785A50E0199AE2DF9C161BF812E8F0D8BDB13C83781711CC3"
            },
            {
                // DES 64 ECB
                    "2F3CA2F2A2070979",
                    "031A354FF84C0D04",
                    "677C5E0182CAEF00298E13C9A2945557",
                    "677C5E0182CAEF00677C5E0182CAEF00298E13C9A2945557",
                    "677C5E0182CAEF00677C5E0182CAEF0042C0BF9A3016DC99"
            },
            {
                // DES 64 CBC
                    "5D12C534395A8285",
                    "6ECE366E6EA6A86D",
                    "2E883FA4E1147406DC7DD95228DCC8AA",
                    "2E883FA4E11474065057E0F5B762E6E5300B755A1EFB0BB1",
                    "2E883FA4E11474065057E0F5B762E6E5F0B82D626F22E4F1"
            },
            {
                // 3DES 128 ECB
                    "498FB860C1119F46",
                    "B8C60F4ADB590B1F",
                    "F0C53CC538183FF3FFFEE6EBA848CE05",
                    "F0C53CC538183FF3F0C53CC538183FF3FFFEE6EBA848CE05",
                    "F0C53CC538183FF3F0C53CC538183FF3ED48A2F02DFF588E"
            },
            {
                // 3DES 128 CBC
                    "983DD36BD988BEF7",
                    "CD579AB4826D4BBB",
                    "C767A8A64C2ECF581412A5A30E578C77",
                    "C767A8A64C2ECF58A95CF7651A84B745EDCB9D934A7E406E",
                    "C767A8A64C2ECF58A95CF7651A84B7456CFB5627E12040DE"
            },
            {
                // 3DES 192 ECB
                    "93E5BAD390AE5B2A",
                    "62614A9486E2C061",
                    "3BB22E9E43235F876B21366E2ABAE66B",
                    "3BB22E9E43235F873BB22E9E43235F876B21366E2ABAE66B",
                    "3BB22E9E43235F873BB22E9E43235F87584FF6BEB9A2066E"
            },
            {
                // 3DES 192 CBC
                    "178F8803D58231CF",
                    "AA8F4050AB37055A",
                    "2E57C10286F9B1C725296A3D129FB559",
                    "2E57C10286F9B1C7292E86042CD360D1CA61DDFD72EE1967",
                    "2E57C10286F9B1C7292E86042CD360D10155F5C1C4C210BF"
            },
            {
                // SM4 ECB
                    "F8BDF76B3989491612D731AFCA117FBE",
                    "2F3421DE228B4431DE3A18EAB7E58823",
                    "C6E212F5AB1541B2F2611EB9156A01CB",
                    "DABD81F30819A22E3771A81A8EAD8F073395144E8B354BC4283F458288CF81FD",
                    "DABD81F30819A22E3771A81A8EAD8F07D718E453666E2C5B37D5777F10FC4818"
            },
            {
                // SM4 CBC
                    "1DAD7613654C3C566F231D082FAD34D3",
                    "C2B833BAA9672BF6A08508C2A14CACCD",
                    "EB9D840220A3B7F4841E07065100E841",
                    "7CBBDFB637BEA235B46753EE289C962F64CDDD2055A6A454F25E2762B2AB005E",
                    "7CBBDFB637BEA235B46753EE289C962F8084AB5E438D773847CD1369BD1FEABA"
            }
    };

    private String[][] noPaddingExpected = new String[][] {
            {
                // AES 128 ECB
                    "893FC5E8109BB4FE427DA3E0829B962A",
                    "893FC5E8109BB4FE427DA3E0829B962A10D3C6CFD8B6260835B4781884A4F734"
            },
            {
                // AES 128 CBC
                    "C70C2302D74E007B4935CCC98A1B6EA7",
                    "C70C2302D74E007B4935CCC98A1B6EA7FC23DE6724EC626529B919AB87C3296B"
            },
            {
                // AES 192 ECB
                    "69518860A1A8742806CC172DDF52F349",
                    "69518860A1A8742806CC172DDF52F34940216BCDA9BD1600BE5EBE495A60DB53"
            },
            {
                // AES 192 CBC
                    "E25AFCE0B714C951D79D284FC595A8BE",
                    "E25AFCE0B714C951D79D284FC595A8BED86727D747449A37511EAA6175086B82"
            },
            {
                // AES 256 ECB
                    "97148D3BA9F55692BFC7A1E4ADEE4095",
                    "97148D3BA9F55692BFC7A1E4ADEE40959B8D8B73735C8BD4142B016F7E70A643"
            },
            {
                // AES 256 CBC
                    "A55E2225E21CB7C785A50E0199AE2DF9",
                    "A55E2225E21CB7C785A50E0199AE2DF971A0B22645E93348FCCA4264356012FA"
            },
            {
                // DES 64 ECB
                    "677C5E0182CAEF00677C5E0182CAEF00",
                    "677C5E0182CAEF00677C5E0182CAEF001544ABB0008FBA99528BA27BAC13530A"
            },
            {
                // DES 64 CBC
                    "2E883FA4E11474065057E0F5B762E6E5",
                    "2E883FA4E11474065057E0F5B762E6E569C24E8946F4850B90221B44A5F56D15"
            },
            {
                // 3DES 128 ECB
                    "F0C53CC538183FF3F0C53CC538183FF3",
                    "F0C53CC538183FF3F0C53CC538183FF36085886BDD3437C442CB13C28961C2B6"
            },
            {
                // 3DES 128 CBC
                    "C767A8A64C2ECF58A95CF7651A84B745",
                    "C767A8A64C2ECF58A95CF7651A84B745C1EDAE228C485E27248BE667AFD41461"
            },
            {
                // 3DES 192 ECB
                    "3BB22E9E43235F873BB22E9E43235F87",
                    "3BB22E9E43235F873BB22E9E43235F87317B48728466BFE8FFC54C3600F076ED"
            },
            {
                // 3DES 192 CBC
                    "2E57C10286F9B1C7292E86042CD360D1",
                    "2E57C10286F9B1C7292E86042CD360D1271E069602D9089CED01FA8B213195E5"
            },
            {
                // SM4 ECB
                    "DABD81F30819A22E3771A81A8EAD8F07",
                    "DABD81F30819A22E3771A81A8EAD8F07A1AE25CAA89BAAB23539D05B12C4AC9D"
            },
            {
                // SM4 CBC
                    "7CBBDFB637BEA235B46753EE289C962F",
                    "7CBBDFB637BEA235B46753EE289C962FE3DE0BE5C2747B9D5545A99DC618F7C3"
            }
    };

    @Test
    public void testCipherPKCS7Padding() {
        try {
            byte[] iv = YiSMCore.fromHexString("56097B7E240371A01290986E00C171E2");

            for (int i = 0; i < pkcs7Algs.length; i++) {
                Log.d("YiLog", pkcs7Algs[i]);

                YiCryptoKey cryptoKey = new YiCryptoKey();
                cryptoKey.setupSymmetricKey(YiSMCore.fromHexString(keyBytes[i]), iv);

                // 616263
                byte[] cipherBytes = YiSMCore.getInstance(pkcs7Algs[i])
                        .setupForCipher(true, cryptoKey)
                        .doFinal(bytes, 0, 3);
                Log.d("YiLog", YiSMCore.toHexString(cipherBytes));
                Assert.assertArrayEquals(cipherBytes, YiSMCore.fromHexString(pkcs7Expected[i][0]));

                byte[] plainBytes = YiSMCore.getInstance(pkcs7Algs[i])
                        .setupForCipher(false, cryptoKey)
                        .doFinal(cipherBytes, 0, cipherBytes.length);
                Assert.assertArrayEquals(plainBytes, YiSMCore.fromHexString("616263"));

                // 6162636465
                cipherBytes = YiSMCore.getInstance(pkcs7Algs[i])
                        .setupForCipher(true, cryptoKey)
                        .update(bytes, 0, bytes.length)
                        .doFinal();
                Log.d("YiLog", YiSMCore.toHexString(cipherBytes));
                Assert.assertArrayEquals(cipherBytes, YiSMCore.fromHexString(pkcs7Expected[i][1]));

                plainBytes = YiSMCore.getInstance(pkcs7Algs[i])
                        .setupForCipher(false, cryptoKey)
                        .update(cipherBytes, 0, 3)
                        .update(cipherBytes, 3, 2)
                        .doFinal(cipherBytes, 5, cipherBytes.length - 5);
                Assert.assertArrayEquals(plainBytes, YiSMCore.fromHexString("6162636465"));

                // 6162636465626364
                cipherBytes = YiSMCore.getInstance(pkcs7Algs[i])
                        .setupForCipher(true, cryptoKey)
                        .update(bytes, 0, bytes.length)
                        .update(bytes, 1, 3)
                        .doFinal();
                Log.d("YiLog", YiSMCore.toHexString(cipherBytes));
                Assert.assertArrayEquals(cipherBytes, YiSMCore.fromHexString(pkcs7Expected[i][2]));

                plainBytes = YiSMCore.getInstance(pkcs7Algs[i])
                        .setupForCipher(false, cryptoKey)
                        .update(cipherBytes, 0, 3)
                        .update(cipherBytes, 3, 2)
                        .doFinal(cipherBytes, 5, cipherBytes.length - 5);
                Assert.assertArrayEquals(plainBytes, YiSMCore.fromHexString("6162636465626364"));

                // 61626364656263646162636465626364
                cipherBytes = YiSMCore.getInstance(pkcs7Algs[i])
                        .setupForCipher(true, cryptoKey)
                        .update(bytes, 0, bytes.length)
                        .update(bytes, 1, 3)
                        .update(bytes, 0, bytes.length)
                        .doFinal(bytes, 1, 3);
                Log.d("YiLog", YiSMCore.toHexString(cipherBytes));
                Assert.assertArrayEquals(cipherBytes, YiSMCore.fromHexString(pkcs7Expected[i][3]));

                plainBytes = YiSMCore.getInstance(pkcs7Algs[i])
                        .setupForCipher(false, cryptoKey)
                        .update(cipherBytes, 0, 3)
                        .update(cipherBytes, 3, 2)
                        .doFinal(cipherBytes, 5, cipherBytes.length - 5);
                Assert.assertArrayEquals(plainBytes, YiSMCore.fromHexString("61626364656263646162636465626364"));

                // 6162636465626364616263646562636465
                cipherBytes = YiSMCore.getInstance(pkcs7Algs[i])
                        .setupForCipher(true, cryptoKey)
                        .update(bytes, 0, bytes.length)
                        .update(bytes, 1, 3)
                        .update(bytes, 0, bytes.length)
                        .doFinal(bytes, 1, 4);
                Log.d("YiLog", YiSMCore.toHexString(cipherBytes));
                Assert.assertArrayEquals(cipherBytes, YiSMCore.fromHexString(pkcs7Expected[i][4]));

                plainBytes = YiSMCore.getInstance(pkcs7Algs[i])
                        .setupForCipher(false, cryptoKey)
                        .update(cipherBytes, 0, 3)
                        .update(cipherBytes, 3, 2)
                        .doFinal(cipherBytes, 5, cipherBytes.length - 5);
                Assert.assertArrayEquals(plainBytes, YiSMCore.fromHexString("6162636465626364616263646562636465"));

                cipherBytes = YiSMCore.getInstance(pkcs7Algs[i])
                        .setupForCipher(true, cryptoKey)
                        .update(plainBytes)
                        .doFinal();
                Assert.assertArrayEquals(cipherBytes, YiSMCore.fromHexString(pkcs7Expected[i][4]));

                // 不完整的密文测试
                try {
                    YiSMCore.getInstance(pkcs7Algs[i])
                            .setupForCipher(false, cryptoKey)
                            .update(cipherBytes, 0, 3)
                            .update(cipherBytes, 3, 2)
                            .doFinal(cipherBytes, 5, cipherBytes.length - 6);
                    Assert.fail("non block size cipher bytes, but success");
                }catch (Exception ex) {
                }
            }
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    @Test
    public void testCipherNoPadding() {
        try {
            byte[] iv = YiSMCore.fromHexString("56097B7E240371A01290986E00C171E2");

            for (int i = 0; i < noPaddingAlgs.length; i++) {
                Log.d("YiLog", noPaddingAlgs[i]);

                YiCryptoKey cryptoKey = new YiCryptoKey();
                cryptoKey.setupSymmetricKey(YiSMCore.fromHexString(keyBytes[i]), iv);

                // 61626364656263646162636465626364
                byte[] cipherBytes = YiSMCore.getInstance(noPaddingAlgs[i])
                        .setupForCipher(true, cryptoKey)
                        .update(bytes, 0, bytes.length)
                        .update(bytes, 1, 3)
                        .update(bytes, 0, bytes.length)
                        .doFinal(bytes, 1, 3);
                Log.d("YiLog", YiSMCore.toHexString(cipherBytes));
                Assert.assertArrayEquals(cipherBytes, YiSMCore.fromHexString(noPaddingExpected[i][0]));

                byte[] plainBytes = YiSMCore.getInstance(noPaddingAlgs[i])
                        .setupForCipher(false, cryptoKey)
                        .doFinal(cipherBytes, 0, cipherBytes.length);
                Assert.assertArrayEquals(plainBytes, YiSMCore.fromHexString("61626364656263646162636465626364"));

                // 不完整的密文测试
                try {
                    YiSMCore.getInstance(noPaddingAlgs[i])
                            .setupForCipher(false, cryptoKey)
                            .update(cipherBytes, 0, 3)
                            .update(cipherBytes, 3, 2)
                            .doFinal(cipherBytes, 5, cipherBytes.length - 6);
                    Assert.fail("non block size cipher bytes, but success");
                }catch (Exception ex) {
                }

                // 非块大小明文测试
                try {
                    // 6162636465
                    YiSMCore.getInstance(noPaddingAlgs[i])
                            .setupForCipher(true, cryptoKey)
                            .update(bytes, 0, bytes.length)
                            .doFinal();
                    Assert.fail("non block size plaintext, but success");
                }catch (Exception ex) {

                }

                // 6162636465626364616263646562636462636465626364616263646562636465
                cipherBytes = YiSMCore.getInstance(noPaddingAlgs[i])
                        .setupForCipher(true, cryptoKey)
                        .update(bytes, 0, bytes.length)
                        .update(bytes, 1, 3)
                        .update(bytes, 0, bytes.length)
                        .update(bytes, 1, 3)
                        .update(bytes, 1, 4)
                        .update(bytes, 1, 3)
                        .update(bytes, 0, bytes.length)
                        .doFinal(bytes, 1, 4);
                Log.d("YiLog", YiSMCore.toHexString(cipherBytes));
                Assert.assertArrayEquals(cipherBytes, YiSMCore.fromHexString(noPaddingExpected[i][1]));

                plainBytes = YiSMCore.getInstance(noPaddingAlgs[i])
                        .setupForCipher(false, cryptoKey)
                        .update(cipherBytes, 0, 3)
                        .update(cipherBytes, 3, 2)
                        .doFinal(cipherBytes, 5, cipherBytes.length - 5);
                Assert.assertArrayEquals(plainBytes, YiSMCore.fromHexString("6162636465626364616263646562636462636465626364616263646562636465"));

                cipherBytes = YiSMCore.getInstance(noPaddingAlgs[i])
                        .setupForCipher(true, cryptoKey)
                        .update(plainBytes, 0, 18)
                        .doFinal(plainBytes, 18, plainBytes.length - 18);
                Assert.assertArrayEquals(cipherBytes, YiSMCore.fromHexString(noPaddingExpected[i][1]));

                cipherBytes = YiSMCore.getInstance(noPaddingAlgs[i])
                        .setupForCipher(true, cryptoKey)
                        .update(plainBytes)
                        .doFinal();
                Assert.assertArrayEquals(cipherBytes, YiSMCore.fromHexString(noPaddingExpected[i][1]));
            }
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }
}
