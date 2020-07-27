package net.yiim.yismcore;

// Created by saint on 2020-03-27.

import android.util.Log;

import androidx.test.runner.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class RSACipherTest {
    private String pkcs1PrivKStr = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICXQIBAAKBgQC1d8wAeHL1FaSOi7DVCOGmvTHDcjpZHnqv8GbWB5g1S0LJnymN\n" +
            "xuLIhTWzszOxiAqGET4rw3sltai7lcAGaBB2PZpY0CU+P8ppmC+8uTlAI0TdPLhm\n" +
            "+WqGyyUu3VwwJR48/WhK/0bsUOyjwZi3CQe80TRfnG/EcgehH4GxLbqz5wIDAQAB\n" +
            "AoGBAKcf9lR0mcLXtN7HDguVC2Spl5wdplkPNgS1DbCN/AMRFihkGjwFcDUmYafn\n" +
            "IXOeC7sfRDe/57l6DTT9nIUJ8CW3iyTWaYJJel0VNO0RQikYUyIQtBhttaisiszp\n" +
            "aAQpAYZEavre570nKUCHbnnrmaC93PFbfwdKinQ5BdMmD+UZAkEA5gnNvrN2VCE7\n" +
            "uMKEuLNQ2xQT7E+cgjp3eOjuzZGD0VVXme4lnNSc1QIgOAcU9MuNzoWzXeUhDLPv\n" +
            "dZnNu/uBfQJBAMnytrkLCJgL+ggVvx/vKtV3p6AHXnEA3A3g4jgbVqimDBvdIIdS\n" +
            "u5gjByeP58YeTAyp6tD2awvGQqEn0Z0kCDMCQA+tB1pBfITLJvi2OLklbxMe0SS/\n" +
            "YBj3xwB0TyGvEt6HBEs3EVUYn/9b/7oRsXnlDSrPraNuY8wrztuiuYRf5TkCQQCd\n" +
            "oxVYyjESJr8sknUXY2TnLritJTNmOEqNls5fB5AUo1DuayTaHQ2MS0NpcV51eu7Y\n" +
            "L8a5CLE0hrU6ANARvq+bAkAYXxf1CpMKjJAoT5Sx0jvCcQKZlS2fmoMfJjv/qy0h\n" +
            "kmZro0KkK1TAB3QWUk3TPOe44YLk1/F13XWYeRIeg5g+\n" +
            "-----END RSA PRIVATE KEY-----";

    private String pkcs8PrivKStr = "-----BEGIN PRIVATE KEY-----\n" +
            "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALV3zAB4cvUVpI6L\n" +
            "sNUI4aa9McNyOlkeeq/wZtYHmDVLQsmfKY3G4siFNbOzM7GICoYRPivDeyW1qLuV\n" +
            "wAZoEHY9mljQJT4/ymmYL7y5OUAjRN08uGb5aobLJS7dXDAlHjz9aEr/RuxQ7KPB\n" +
            "mLcJB7zRNF+cb8RyB6EfgbEturPnAgMBAAECgYEApx/2VHSZwte03scOC5ULZKmX\n" +
            "nB2mWQ82BLUNsI38AxEWKGQaPAVwNSZhp+chc54Lux9EN7/nuXoNNP2chQnwJbeL\n" +
            "JNZpgkl6XRU07RFCKRhTIhC0GG21qKyKzOloBCkBhkRq+t7nvScpQIdueeuZoL3c\n" +
            "8Vt/B0qKdDkF0yYP5RkCQQDmCc2+s3ZUITu4woS4s1DbFBPsT5yCOnd46O7NkYPR\n" +
            "VVeZ7iWc1JzVAiA4BxT0y43OhbNd5SEMs+91mc27+4F9AkEAyfK2uQsImAv6CBW/\n" +
            "H+8q1XenoAdecQDcDeDiOBtWqKYMG90gh1K7mCMHJ4/nxh5MDKnq0PZrC8ZCoSfR\n" +
            "nSQIMwJAD60HWkF8hMsm+LY4uSVvEx7RJL9gGPfHAHRPIa8S3ocESzcRVRif/1v/\n" +
            "uhGxeeUNKs+to25jzCvO26K5hF/lOQJBAJ2jFVjKMRImvyySdRdjZOcuuK0lM2Y4\n" +
            "So2Wzl8HkBSjUO5rJNodDYxLQ2lxXnV67tgvxrkIsTSGtToA0BG+r5sCQBhfF/UK\n" +
            "kwqMkChPlLHSO8JxApmVLZ+agx8mO/+rLSGSZmujQqQrVMAHdBZSTdM857jhguTX\n" +
            "8XXddZh5Eh6DmD4=\n" +
            "-----END PRIVATE KEY-----";

    private String pkcs1PubKStr = "-----BEGIN RSA PUBLIC KEY-----\n" +
            "MIGJAoGBALV3zAB4cvUVpI6LsNUI4aa9McNyOlkeeq/wZtYHmDVLQsmfKY3G4siF\n" +
            "NbOzM7GICoYRPivDeyW1qLuVwAZoEHY9mljQJT4/ymmYL7y5OUAjRN08uGb5aobL\n" +
            "JS7dXDAlHjz9aEr/RuxQ7KPBmLcJB7zRNF+cb8RyB6EfgbEturPnAgMBAAE=\n" +
            "-----END RSA PUBLIC KEY-----";

    private String pkcs8PubKStr = "-----BEGIN PUBLIC KEY-----\n" +
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1d8wAeHL1FaSOi7DVCOGmvTHD\n" +
            "cjpZHnqv8GbWB5g1S0LJnymNxuLIhTWzszOxiAqGET4rw3sltai7lcAGaBB2PZpY\n" +
            "0CU+P8ppmC+8uTlAI0TdPLhm+WqGyyUu3VwwJR48/WhK/0bsUOyjwZi3CQe80TRf\n" +
            "nG/EcgehH4GxLbqz5wIDAQAB\n" +
            "-----END PUBLIC KEY-----";

    private String nStr = "B577CC007872F515A48E8BB0D508E1A6BD31C3723A591E7AAFF066D60798354B42C99F29" +
            "8DC6E2C88535B3B333B1880A86113E2BC37B25B5A8BB95C0066810763D9A58D0253E3FCA69982FBCB93940" +
            "2344DD3CB866F96A86CB252EDD5C30251E3CFD684AFF46EC50ECA3C198B70907BCD1345F9C6FC47207A11F" +
            "81B12DBAB3E7";

    private String eStr = "010001";

    private String dStr = "A71FF6547499C2D7B4DEC70E0B950B64A9979C1DA6590F3604B50DB08DFC03111628641A" +
            "3C0570352661A7E721739E0BBB1F4437BFE7B97A0D34FD9C8509F025B78B24D66982497A5D1534ED114229" +
            "18532210B4186DB5A8AC8ACCE96804290186446AFADEE7BD272940876E79EB99A0BDDCF15B7F074A8A7439" +
            "05D3260FE519";

    private String pStr = "E609CDBEB37654213BB8C284B8B350DB1413EC4F9C823A7778E8EECD9183D1555799EE25" +
            "9CD49CD50220380714F4CB8DCE85B35DE5210CB3EF7599CDBBFB817D";

    private String qStr = "C9F2B6B90B08980BFA0815BF1FEF2AD577A7A0075E7100DC0DE0E2381B56A8A60C1BDD20" +
            "8752BB982307278FE7C61E4C0CA9EAD0F66B0BC642A127D19D240833";

    private String dpStr = "0FAD075A417C84CB26F8B638B9256F131ED124BF6018F7C700744F21AF12DE87044B371" +
            "155189FFF5BFFBA11B179E50D2ACFADA36E63CC2BCEDBA2B9845FE539";

    private String dqStr = "9DA31558CA311226BF2C9275176364E72EB8AD253366384A8D96CE5F079014A350EE6B2" +
            "4DA1D0D8C4B4369715E757AEED82FC6B908B13486B53A00D011BEAF9B";

    private String qinvStr = "185F17F50A930A8C90284F94B1D23BC2710299952D9F9A831F263BFFAB2D2192666B" +
            "A342A42B54C0077416524DD33CE7B8E182E4D7F175DD759879121E83983E";

    private String[] cipherAlgs = new String[] {
            "PKCS1Padding", "OAEPWithMD5AndMGF1Padding", "OAEPWithSHA1AndMGF1Padding", "OAEPWithSHA224AndMGF1Padding",
            "OAEPWithSHA256AndMGF1Padding", "OAEPWithSHA384AndMGF1Padding", "OAEPWithSHA512AndMGF1Padding",
            "OAEPWithSHA3-224AndMGF1Padding", "OAEPWithSHA3-256AndMGF1Padding", "OAEPWithSHA3-384AndMGF1Padding",
            "OAEPWithSHA3-512AndMGF1Padding", "OAEPWithBLAKE-2SAndMGF1Padding", "OAEPWithBLAKE-2BAndMGF1Padding", "OAEPWithSM3AndMGF1Padding"
    };

    private String[] rsaNoPaddingCipherDatas = new String[] {
            "9e00104e1ef5edfd62eee6bbd765d27b08c1e8afc0a7b14b18f668cdeeb09b74e0b231046a9063c6874fa29bc46b8f240c0e395cc5eeef9c965ce10c9e5469aee94d0b2e93165d8a773a99db23ec14ad6be71a0ebaccc9a9a8a430be923fb30c82d9ebbc4f87153527b10f62bcaa3ff840188ee40f333b56f00bc0d10e2ae07d"
    };

    private String[][] rsaWithPaddingCipherDatas = new String[][] {
            {
                    "8e4d5ae64e9a01569c8610e8841a3502e9687abc1f0240fd3ca2627ea8f31253e57944e7952bda1a6ed7cc123e13166887585ec511d47e379b94332510aa8537c02b3df0437ecc031cd0797bd229e220b2471ada934f3499a5c1e1dcfc418ddf4b4fd4cd42229bd79b41f32f59529c00a455610a4aef3ef855824cff0cc93a0b1c6667842e36bd080de5f774d8cc9f84a8511ae8b400c8b4df9ab7e4de87d2059377bb946f7e4e3ad1bfd5e32d048cb756b7d9a23849bc7cd0d44c420dd272d8168d9123d85a1604c2e5bb698a64fe5f8e252f86aa98eb4840621254ff3566f01a669300be71ee1f5adb1ccde9a11ce6cee19653780f58f6c0d3302e5e2a2f70",
                    "8dc4bef51bfa536d860fed18c19dbe360ea9cf71f5f151b009434f7564132ad6b550d2405d124f966acc657b306e7c8c783f9176969f0a87c1c25d6f010f2e35ce8a5223731f153ce9eb1f2dcf9eb712980cb69d593ccdbe0c7561adced8dfe8cb95bf24ea95321698a5202c86269ccbe55bba597db372bda288f7f85bdbf2ec9393023dc0418cfa830ba6a062df843c4c22a4ba5d8347f6146cba4761ccc438bbe3164862d145bcbdf063cd4d47403a7f7fb74b8b42a968f28c8b469843b1720ad8f8ea5898d21c83bb04b115523685dd558752561409775f86a1b62580be20fe8342cc29fc37349cc8c0fb7937e335062596fa38f4d147884548eb0ccb7252"
            },
            {
                    "72b87e256672e58d3c46f36f1d8fe71b4e5401830a12e57e3d26c4fdf301eb7a1071cb63bdf7266bf655d03239c61c45b3f839297ab330df2ba6a819aee4b1e45b4d0bee8b7079f6c340e18838e8a21ebd551c0cb89b24531087443834869b49e6e42ca0fd74feadd2a1f426bc1ffecbe22db2b7f5fbb8d35b93d29abd07498806e5bdeff60e9435bac3794aca856bc795f2cc3b9924ef8a1d49ddddf32fa72700e68cbc1cc4f16f1fded31769d043c9aff21bba91c88be43b7461885cbdfa0b4cf3adb9a4c9d5a2f3cbee40a8378456f10e860a3bfd6df11c10919ed45ad1638d70f3a60447d11da2a62835d98b43f0f0402fca7f2eae30b675260fb101816f",
                    "58b16297f8202c8e886ba4ecbabda20467dfa6357b3a470ab9fe085a7f98cfc89167ef9e2c73b2e55e907d2b3db70f4c889a044314f63e2e0a5c9b9ed92c9eeed1a7f9f439d944c2a3d07e6faf804be6f83d5732400f0ff0173885c7472126af8fe63c82e23f28014a20fdab32ebfb31737bb56153e803b264d84e8f433336f76cb8fe0b8e3de55b511486c600885f6faa1a55799bfe796a8201c798a207c662494b91a1f1048e698246bd9b8cb27307334b961f14d63dcac01c3927402d82254a57ee7e335580edc86a22f3c687cf54674a875a8b16d5662e809077c30d3b587321d132a2b6a787755f2016f932d2a351098c5e48d661066286e015e2c7c8fc"
            },
            {
                    "8978e888fe5655b17223e5d84a47258fd14c4026658a5c4de39c56c5b28a698f5f70195d4ebb748407a4e17e8f37b9aa89ae11c53a467c1d451e0590f17d7526eab2292d7fb17eee25567575b0d8d1d74273843b9c47f1528b76f94a1e4307f50efe61d1766a2db9590792af5195be583484668d8081ba765aa35b8e67dac34b4a914a77ec2f436a621d56a9181c79bc8dba7abe1114549f648a4ed94160f75ec86079bbcc68f3186185d58fa03c82636cbcd19ff411baa243020d84b80a8faed3d5970eb562249485feb26072605bccad96e54fbc4281d234a81f4bce3c704a5c33001525c1e1fd4bf1f85ec7a761a5f59f2798b53f42fb859b3a79ac4085ca",
                    "89fb2cc549ccdb5f2dd08928f7eb09396e43795ccfa0dde6cc1f5d754e9b41b4de237e5791ade27aee670bd2753e4145ebee9f262e89af2b4237c960994b6e5587151a65101adc7ad524e91e91d8cf00d651f1f46b0d032bbaaf35e5b5ef437ed849cb1fd351ee2241e43f69a841bc4cc7a0af9629e04f668f1b1985bb982c14341f7a8932b57a3850a3b5f3a55da4a99c833e86bfb3de0fb06300c87da933a4ceea986d25c4acb6a3c6963bc796efb07da79d066879f91e8d7ff0164bec876d4b58964ac2d4fbd9a465606ab44c28d7d08ef3eb6bea595e46938759d600a2f41dcf6b3f114266b72c05b2500e5d71e56daa8c03f66257b5fa48814224924c54"
            },
            {
                    "939f8bbdf0f1689f5eeac41424e194f52830ec494e6032a5fe5a64f3bb77f9fe4f8f0c35f42a6d68be4e4563cd6dd4238b210ed9cb3d66b960c212c120719e59c09c0f165990e06d820ac5307e668bc4e7c35e87aadc6fbae2515dc76f73451147050310405d5a4dd1c88366405e37f262cc428b85d94a9ea97995d69e611efb55a0cd086e5d54654a74313ecbbb0bef50302a8e8b93febfd7415a52f4ef5b818ce6d95326d2082c715a413f00a6c18b4551a75de423343f75c1548e2d8a4f3d1016e8993550bb2fabb5d398eba072ba89a67821bb9b56e19aa8c525938f37912e1fba7be3ce40398e0e486f3f6aa1d4ae2079facb6571cf5999604e62646d01",
                    "403142fd4ddc0aae56cc2e6e2adfdb75fa0913abc41c7d99b3e195c5092e0dbab5fe515e5a775a7cdf9d71abd8491456f9ddc6d0551b78474d7ba68990ac0060c129ad5b2364ddb73ccaaa67a1a833a65f9de921c7b1f71506cc7dea442f76092d5527a3954f064bcdb1f61638688796bd97b74bcc8dd1991f224289a8cc8c26a4eb07e0e7e5b220fb1401146f9c1bdb635610896d33b96ad35a445019a2be13b594049bbe2ddd447d0e021f8ff0985c24532d705a6a67e0b50fff490bd32b5e077c1539094b89f5a652c5194bf89eab1436b9bd41b86a183553195345cdc0ab0871dca537dd381b0b08eec011a2e6089f0812290435b733270725bdf615e79e"
            },
            {
                    "a9b519f67ab16337b3b1471a626a53c23019d22de4ccb7d81551966c01a1ea17728fdb621862f7d798187ac51ca9f1cf1a495ae6f22a5d17a9db40def5d0295d457f361ddda8a3888f22b03b96bcc528ad59ad05b20e0823f0e85c525437ba860e74cafa9bc6367a5bb53cde3d41d207a07fab99151f2b7a6cc864e24f0bb2907df956e34a14caf5f58eabf067fdd09e40691c3e4456dcbf7020db7561a5373f28b627d37fb5036f1ad3bdcdecb663eb121c61772ea217148a11402dd834575a25c690cc9ec61029322c093a69a143d5b68f7ca2221a637c8de2ea932cadf3019ca79f4e3ff4318f1653459ac7adae688dc83f9b8744d5d113e109cb6892b8a30a8188cf9408a2953304829d2f9935a6b9b26fdff99f0d0f2edbd9d4d953c2ea8db66703a4976423b5fa47ff473dad959961e166d4062821f584f2dc2c6990e7305664e71db3ae0622929283efb0ae4d2e52d9338619db00257a4ba040a7a92160ba9a489c55f408e2930f415e7810c84c88594aa6932f9496d043bfd22c0900",
                    "548c057d2319a1bed6714254c23aca6e4e379ddc78386e9f813d5654a08cbf6c1878a331b0d70bf7a2cbc70cc4e15ddcb991951141278b73c4cefc0cd8e6dac708ca127d61ba1d9747fc60697101c9261ab86f612c8757cd392ee000502d8885f08b86082dece9b2350a9651ed98ec9ba3bc41771b0c3345655f3f477338f2a8b43a4b44d0b9f342fc70713d3dec566cf391aa79ebd597c00c0c612054701aab01d34a1b04f22f9686283d41853a2ced947c95532ca29189155a53fc72efc15264c47514947cc6be226550ecf1090dd963aa4ff16660d6ede85b987ddcb8bba3cbce6f4b46ef7e7f126fde769e9f017c0e9b8b3af9d6d63e3e7ff2a3b584451684e5cbb1d4751c9d49df31ff7b3617cea8397f66a8a91c520a9d398410b072e9326dd58a001a2488782d0102af3f6ee4380254f839c7f82266190451bec90cbea300f1ae4659ff56d67a4ec1f69616d865e1fc7cf0fde6e9d8379e60e1dbe75b641d479a36dc081fa3c9f918983841e223b1bc0a8c981eaea16e335329f07992"
            },
            {
                    "80b93a3aeb5075b4d1f72aa5376e758104b9e511e7ca56d0ba874efac59d6b82abe60a9825ce7c4c170584a033a7f6599917a9a80c1105719ebf0df803e68f95975e0e83966a81da44f129b880d934d2919e7884f4f0175e62bfdb060420c5a5af1b0964b56960572ac012a46327c3ad5602b4030acabd8729f505c662956e1c594706e7fc3aa4aae75d9f07ad37f5a0f5235466b679757c890b0fe4e3087a0cc5c5d41c026460c059fd4b16621aedcea9efdfe2715a0d3dc4155b84b30d39b7bc18b2c70658fc2b20b6f356b85cc01cfbee0753933f0c59330cfdbacf89a89d256b2670b9fae6a486a157f303b0fd259c6c0b9c46b64d5320508e3de15ea9f295d9aee2bd1778e8c46a4bffc2c4758eac0b99b6b076324a8c2ec9e87f0d4c992aaf7aa257f12c94f1d1dcae69db290bd4310feb120cb772b17a64c9c3ab998370fdbbb9e34a2cbec60ada21272144f62e4030d0f84da365a3e91a6937eef1526bc8db7587fc3764b22f57af65e8fcb535713ccc24559a25f5bc7a4072dbc3323987d29fbcbabe5d39b7a32b6196d558f01a42a8b678938cacfc022bcc3a5842b19bc40b7076cd36333097dddd3b5f151585fa76e4461ac016c73f42dffea46e1edf1c37c01ac1285d128af47f8c0d1c7e09b7335fafa14d2979fa0c2a2df924525a2c47867b24731f350eccbfee9c9e61903039b2948f915bc7c8ecb13dcfa072d846d33ebc29bf8a2946eebd0a81253586525ba4561aa8249707879946246d03c49aa3852082843ac743e66d3a1960531f815be9000ce1b94fd69c86c950af1d4077769c789edfd81eee374b3038374629066b3364d5c75e00735549ea9d7539f37d98c797118611f7611da2e531bb82afe048bd7fc72c921bf9892068da15",
                    "6ee94b1e2534723939f3ebe230bcdeced080d271910583e5b913c6b9d6c005837dd4b22b61d28b557731c5b77fb21682f2aaea95fb4520b45f2b8d07afbf1911af3e999074b0c119796949e73d610457c50a95974d3eb2ba09273bffdd56a524b58f59dab1a95916229fac72fc18d3f3cebcfec587dd75f62640b3619715e3889a5c239ea73637369decf1eda6da5955bc15ed99cf4e9a2298e2fda822a7426a25c9056853d772f412e2fe03296b9b95e33c3f7a2802cffdf6df3ce9f6281dbadf1b2feb7a36f380675e9e174db6530bdf4e32b83f8028f25fd97d9c153b79b348271922d07a284b8e3c6f5909290a45d2c0b1d8417ae61f2a9ba995d8c0a6edaf9df212406a619506807803a7b9bc71ac69b0bf51ee96961d82dab02f323bbb3ac7c8f2359d42a753893a41838c98abde85088b36134d7a8b3e96428c02cd7a6babb0044b6fd8c4ffbc00daf7109acdd816c2ddfe08f7ac76ec55159a295f401ee2af6569374ef73b989b29dffa2142506d40b75e65d920aa4e1618faf0f821b43123d8b9b082d40b4f61a6e8a57c8fe2c22929a1dba8a010eac51965a514b9dc61c89d8bba9c8959bb53f1bada61a43797a73e1ec701b2fb570d000b3c3b63ac1e3839070d0e463df9a073ba50968bbe5c12d054abd340d6262c57ed14624b676e5f2d27fab185aec446c6270109074476beaeaebbd2b70d30cd5059beaa118e054a70b62c19fa48f416f41cb3c872f60d60de76da1098567bbd93e22bae93e0d7e1a861f5dd924659ecbe4bcb130c43a9d0e5a4004d0ae2eaad572daf10f70f2a873380495a2ef3ef5af5a9de038c9375f6c095981987b5b76106e7c5c12efdd378c3e771f760f62562d61cfdb91638d5be37f254c387b206847d21d392d9"
            },
            {
                    "",
                    ""
            },
            {
                    "a687a9e5a3bacb9ca8729a85639c7df78134a2fd9b2e6a17b6ece258a7a153e58751d91e7df9999abbcc81a203c8bce18694f32b9a25689259787d697daefae1082240cc7c7fae76e67706c258ec03638f8da9a1e0bc80fa82aaea4600719bd73253b754fc9a1cdc384d59134cf9d48720446ed9024ab9330473e6a3890c1dc746bf1dbb910511c01c538ed93294fa67f0ca225ed4b06ad83d8a82f96cba308ed73d04bb780d1dd7bf191cfa8ef2ebbde42f193e2cba98e424decaf26c5c458612a95b8aac59ca4b8751e85b34d1a1059a65d176fa232582a01d8bca1d08699cb48eba933c18a85342a6af20979a4ee8b25d8d8c605bbde5a2873c4abcbd20b2",
                    "4d88d3db408042c15b9dfb0e22b531904b3f47e2a6cfaa0e540bd29f40e468f866b22982db87d51fff6c6539787c888bfc275ab548136e5ec97d58f84a3f6acb2fe8d632ed75d98444a702dadcca6cf97d4ce8bd710fc78bbeb61a50bd0562cc2dfd019de6600a9040f98e530ae3c7974eef251040e056e637dc5a0bdf49ecf883b2ccce441b9fa526501d7923dee4ca7cb279f12696211c7e9727661a6ff91b371fb6eb1d4dcf360a08b041f16cc72f3c9395fe533c6da059b3ed631a411078f80eb4cbab70ea9196ac5cb5b6c3cba59d8cd9238325dde4a8f06cac96cf033e34d1217391e74af6694e437b70bfab844043fcfcb91234ab737e7500585c8053"
            },
            {
                    "8c14bf6a0abf470a8cd7253c2ceaa553aab47625a11de4b0c64ed08c2a61a764e6ba4029d62d997ee6c3bb1d0ad0db548ef72f3d7cccbb064d609f2c68386bc61f041736787501c2953ea1c118054a69b557f62c4b0394b87823e0a77800fb13cecd018da7655eace8508117870f26f480e8076f8d726afba0b8eb8eb7fd4171613c833e54e6d5fb49b6879035e3a31dcea8145f68665a4fa6d6192c8b28885a557d344b527b8aaca8b8087b12e381f680393dc28a241d3155da5e734af3e9d900c2464d30f824ec8b29f375973af84152b64de0f48d09358d81b24dc9c97e9f02296026d24e32c4a41a0c503a7a82de7a6fc1ea8bfc61030aa098678721e1e12f64de3eaf6dc84e975b2488606817ac814393757730ec03dad07ad2d63fa91d2059651fcab19a20e718da374087d6751b45f31224057c03f1cf86025cee8917d23e002298488a6e6d44dde2a97a6277c003e07cff6ea7116986d631268348039be47b43c0c339ddc47b4649986d32baa4c400bc394e01454344d55d2d892dca",
                    "2048d3d4e1ecee224263d0714fee8841e85d2cbd8e9b77fd332d614a5398c904c5090ba13c8bef347cc75376a81234793fe5d24322728191cb88c25b0197a93ef77c614a0eb4f2506bd825d2661667393883db33e52f010a01afe0f98334276c7bb3950232106c19c0a7a39756d95c3162e8b10ab7864ec5c2e18d6230e159af5d677bc45d871982baea44f77487656075fe9da428f8511685d3685810755b7e4390f80b463efd5556d8f1a99b018d6bffd99888e86902dae4306d8f455dcd1d48cc5cc84fd172f88450faea3793cde65c5b3819852a63c1af5865b2c87e9a7f777ceb681605946f87adf1f525273bfeb89e414e1d3965e3ea405855df1956013cb33e26827bb223b3ecf492dc9e7505126a5f95543ee6838a72ccf8180e149303d77f817ce1af3a9798b74812fb3a19c265b3aa5ba335c5b4165545576515bf1377df4aa9e23d9e50c9653ce7924cd2e4bb088f2e7b3be760b912f37a054fef7ce72364585ac9148a7e6e3efb55474296ff40433da09e452d89707e3ef08ba6"
            },
            {
                    "7759b110f55b2e0bd1530687c9918a62bc65c70e67bc7e9fd60a1489b50472edddcfa6f7724538d8d57871f02a4aafef658131ac516f25520711e9c9db0d82a1d1b9ca0786fb3b57db7e1b79d207d5c26029c7f46351eb3c821a0b230a60d9179d8eb4ef043eb131c6fa4f556d7a2f0f279d55f13b8492dd5d4598ebdc15eae421720485c5e826710ba14de7bb1f23436fb66fc880452ceab20033d810ec9152e090b4c6927598d3b26183f2bccd2023da536d007c4dc9ff0c85bb59bfb01e19fee91792f8a4060f33d527f8d376fa8c3c8da2177ae5855f42e9d824fa540dfdb02040ed990db55ba2d0bcd1c00ff6b7589b8577d3b878511a93a7207af9c96d09caf51c0844f999a2a2c46a00e7362baa0558c087a69773f6a8b902af3a6cbfa939e4343bd144ceeba93f7cace8aeb4fd2fb4b7332de27c01593576d7ac7feaddfd6a4ef03c45471295ff498fdcd0a8795b250348e7e0e2028a93210755ed8b47fe26ec50010962b7e4d7fd3417aa0f7a444ebab0069942872a5b36cf556f0a70dec860c70473ae43a66807e1463585a7afec193c19b0687b284406d6aacc0e5222f728427dde45a5397ad35883a71c03abd5507d4c38f2e36125853fa792083f5da5ccaafadf25aae65b1cdbd0b1c9abea89cdc7e8efc0c63fa94f1c7cf9b4c8b0a2d9148ba1654372e7db5d6d18b91c3c2abf9c7a56f223b7b217cb2c59e935728433511e19428363b582adc16de59b353c0a1f3ad66b32384b297326864b17e797882063246b649b93c4ed4a9beff70fdb5f4569c6446f01d5b36b7a2a2c9323a344f692596eb7572e5b607bbd5621f9473c34ff3781ca303707fc66a72367fb7205214a3cd868ce4fe5a46711a76f84a67d2ca9ca72fb45e4f3ddea258b",
                    "a3474d169070e18e31a7f1dd94a1e8fc231f2b06e392dedc16ae5f836479c0fbc0e9d3f97cfd72f325c2cd29d379fdb566b0b2e838745511057cedce253eb042fd07f4c777eb9f494d7a13022a4eec9b037d3d0b7d08a0db192cc5439ddc8c58bd98d4a5605245053b869ae9f8d8cafcaa3214761eda13efbeb4c1fe61a1100c4be3e01becd6e029d18dcda9c71b0e51f59f8c5dc14ec70e5a77411a4b2de14bd010c3ef533707e5ff8b7e811147aff0cba7210d590cac33b6ec1e3aca418738d11897249b2fb6ed634d03e586ed8ea9d906941e776aaa67da624e188fd0f03d81caee576c171c06dacad08aa89360fae7dedc423d51055f8f94b05f91baf9229d72cbc3814bc7603e005eb6502b948f38ba9d2717edb04f084f736dbc1bd76f7cda99e6e9a62b6a643cd3f2d32362f98027eceeb8a7914b95462ab6e9d78f876f9fdd3850d6e541e778922a15b6aef06c19d06237b26ac7abe261a0cbbf1b60382eb73916622017a9d1a4d3b07a6d24a9be7461165876609620c098c08e57e1a300adbfd78db3ac0b296370bae4761d2bc1413980b0f2d03e1f84326b6ba3ff78e1367c219e5d09164e1526c92c5cbe6fe9f56e0c9510495b8e1324291ef53698cb31f6dbb69c88e6f78549bd88e3e4dc840fdcbc7ddf8ecae3a658b209de4653d5553e774501d96bd9095f4e1a677c2bedf0ddea9cf5869b261696eb7c924d733d4829fe9636da4c4317a1c7b6f21568e3b959e2e2212c6c73cea3858e2e463339543b8835d6f2ddf54fbce1ed32049a87df7bcb0673a87d69b5a1a9af9e579b50d5c5a7aea77b12db4fb92be778ffd9dae1da1b0a656e1adf0dfd4b6f92181cf91b4e561cef0183eb8242e50e2c178132c94b2a54817aa42f346695d3e689"
            },
            {
                    "",
                    ""
            },
            {
                    "19E8B6897EA6A4B4C2964BB619A2C1DAB5C68EA9935B3B9F8C23C81496B1C0CE2ABE150285C02C4A0EB4A9C7A292E0C3D8EFC1BD4FC87FE4E07C87C4CDD6A793E45633CF03570AE978FDEFEA09EB90DE1AFD527073AB7FE6D903814C416BB90CF7D0FBA34272F79EA99B0EFDEADD2D584E2F5A9479E032EFBE2CD2C9A5E1742FAA4BCCB5C55A8A8961350A28689E9C1F6D84CD275FF3E622D5A1E8B5269986E553B1FEEA90FA7914859BED2D967FFA534A7AB8A5F57A865803E694E2630C501F1ACAC8339484C20FC1074DF75F78F967F845052C611A57B21CF3F9F1BCF5642CD93A82375A0BC8B8912E71801AC0E0A43C21F8A41ED9879521286A0711D54F0D39868A4E6B030FB9EF2B061E9EACF626432630BB955EA158F73EF71BF5A055CF034E2B09725AC44EB0077E4E80227B58D63BE6FAC2AEF759F2D2A98BE24F84DD643DF97D450F0229C217E281F49F0F676B33EFB1A6D012014D8F51A315521E543B193BBD78B6C26DEEF5DE3140A01DE08B360873B8025961210A562C76A0025C",
                    "731659DD02407CC6FD5A8194CAA2D73C54C7F663074C882596765940762BD6D64D19B079F7E9FEB2BBAC291262D683304D0D630CABD9E47AE153640A82AE902C3C5AE6DD10D9DD782EC62B8E44586294590BB9F0058A01415C4892A4129D7EFFDCD83E5E01A6835B8722683F0E0A49189863DBE6400A37D1803D53AD786723D3475D3C542DC81F2496BAE6794863DE3ACC52D8C585E58C61C779673166E472A5C6CB475853AB0FFE147CA624DFAA973B8E9E2A39FAAABF53B4588246B08EA31F774588B0159AD945EEDE859921F4C3BE1C8F680457EABADDEAC51383669A818AD4471668AC2300F8C90C6530BDFA809B0DB8C031B449D97421A59C5D187A3420066F0A7A6D2BC0B1323ACFD4B49215A34E379A5947668D581890B8BF6BB3D18E8DB9628B2A2A2350EC0553C0EA2AA5B0D32A7A1FFC89804BA523FACD7713828F60AB441FEFBDDB5666B5F543E78F95E7479D2AFB487788183D22F19EDAE6437D443103D3FA6AD5B22E0BF02E710F31316431A7CF681B9FC037559477458877CC"
            },
            {
                    "",
                    ""
            },

            {
                    "b3d379f9bc84ea0f47ea7fb1a12874e4ec1e40e355af734711a433a23dec0f96a68856f202511d3d56ddc552dcd362f8797496f0a1660cde005c4aceaf3c20c423e7282f8bae7bc3311c91edbf6f7491df9006d04d8e65f5a443619dce98302e2da25dc395e3b2676aec783d42bc0a04f305e20b74d2c19b38070fb795a6399c342f35157440577fce4aa00426c85fbdc65b220a936fe920ac703b031d39d7ae4c85ddc7b79fe489a20a521c1d50d7c1d6136a0b5e17d1edc0fbc1fac2e232b6541bcbaff66dc6c1643f7d950991aaa0cc2091ae8e66db594dfe60ff83547fcda28bf3f8cbeaf5d1c0e3d8340de2314f36e195c300839761768b127bbe3e1b435c67481d50ede676311d97227be6849974e5524daf5a6460b96b3a78e8eb6a3fc3ff5a4e43f2e449c4f5121ee5f48eca76639da11759404458b44082d6a516bf5e56e78082a8964e4db4e853cd597122adc19ca8caaeaf2d28255de0895befe1040d65cad124cabfb2de387f17118e5f918cfe4f0ae867f62336bd16b6cb59b7",
                    "15078ea41bd0de755855010e10e28f08cfb1261c37052ae5408e9359bee8eb3ef60f2a6e741453acbb1e68f109753570fdf4ad2849f6a4491bb264a6449cc1c8c015dc442f2114a159bd6a5391c792dbf0c1fd4a54095bff2ed55473585cb6b9c76e66b15608fa6b317be175b6e721f3b7c7ee0a97dd46939ed3548b0a0fef616dcafcfb2ac11e0e9559f0fda2bf8ad7f95625d6811cd16c5f4ba9237c17891e022e05ae4797ce44fb8505fd32e95b99ce21dad1ad56bfba03b819a6ad4e4d535b71ab340dc63ea19b5ea1bcb0ca9ed31c270766bf6567fb17f8f07ca4643a1f4babe93c953e7ae4994ecd2f936da96c714b670ed533e86ac5ef7636c9fbda85253b2003982b0b954bf5fd954020dd4e907615ce703dc8c6e9712a5e2baf8de02846b2ab5ff4b4b3a39e8d54b644afdcf1bd2b6ef2bdeddf4093a55fe78ac5b568543f015a4c95e1bbd39aec0ce0c6cb16a6b51af931dd6217adbac0fcc9a05296d314ad71c33cad0f02487c235f94ec078f55b3079e995555cde5e8d53c9ddf"
            }
    };

    @Test
    public void testGenKey() {
        try {
            //生成密钥对
            YiCryptoKey cryptoKey = YiCryptoKey.genRSAKeyPair(0x03, 2048);

            String pkcs1PrivStr = cryptoKey.getRSAPrivateKeyToPem(true);
            String pkcs8PrivStr = cryptoKey.getRSAPrivateKeyToPem(false);

            String pkcs1PubStr = cryptoKey.getRSAPublicKeyToPem(true);
            String pkcs8PubStr = cryptoKey.getRSAPublicKeyToPem(false);

            //这里可以将密钥对保存到本地
            Log.d("YiLog", "PKCS#1 PrivateKey:\n" + pkcs1PrivStr);
            Log.d("YiLog", "PKCS#8 PrivateKey:\n" + pkcs8PrivStr);

            Log.d("YiLog", "\nPKCS#1 PublicKey:\n" + pkcs1PubStr);
            Log.d("YiLog", "PKCS#8 PublicKey:\n" + pkcs8PubStr);

            Log.d("YiLog", "n: " + YiSMCore.toHexString(cryptoKey.getRSA_NBytes()));
            Log.d("YiLog", "e: " + YiSMCore.toHexString(cryptoKey.getRSA_EBytes()));
            Log.d("YiLog", "d: " + YiSMCore.toHexString(cryptoKey.getRSA_DBytes()));
            Log.d("YiLog", "p: " + YiSMCore.toHexString(cryptoKey.getRSA_PBytes()));
            Log.d("YiLog", "q: " + YiSMCore.toHexString(cryptoKey.getRSA_QBytes()));
            Log.d("YiLog", "dp: " + YiSMCore.toHexString(cryptoKey.getRSA_DPBytes()));
            Log.d("YiLog", "dq: " + YiSMCore.toHexString(cryptoKey.getRSA_DQBytes()));
            Log.d("YiLog", "qinv: " + YiSMCore.toHexString(cryptoKey.getRSA_QInvBytes()));
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    private void checkPubKey(YiCryptoKey cryptoKey) throws YiCryptoException {
        String pkcs1PubStr = cryptoKey.getRSAPublicKeyToPem(true);
        String pkcs8PubStr = cryptoKey.getRSAPublicKeyToPem(false);
        String pubNStr = YiSMCore.toHexString(cryptoKey.getRSA_NBytes());
        String pubEStr = YiSMCore.toHexString(cryptoKey.getRSA_EBytes());

        Assert.assertEquals(pkcs1PubKStr, pkcs1PubStr);
        Assert.assertEquals(pkcs8PubKStr, pkcs8PubStr);
        Assert.assertEquals(pubNStr, nStr);
        Assert.assertEquals(pubEStr, eStr);
    }

    private void checkPrivKey(YiCryptoKey cryptoKey) throws YiCryptoException {
        String pkcs1PrivStr = cryptoKey.getRSAPrivateKeyToPem(true);
        String pkcs8PrivStr = cryptoKey.getRSAPrivateKeyToPem(false);
        String pubNStr = YiSMCore.toHexString(cryptoKey.getRSA_NBytes());
        String pubEStr = YiSMCore.toHexString(cryptoKey.getRSA_EBytes());
        String pubDStr = YiSMCore.toHexString(cryptoKey.getRSA_DBytes());
        String pubPStr = YiSMCore.toHexString(cryptoKey.getRSA_PBytes());
        String pubQStr = YiSMCore.toHexString(cryptoKey.getRSA_QBytes());
        String pubDPStr = YiSMCore.toHexString(cryptoKey.getRSA_DPBytes());
        String pubDQStr = YiSMCore.toHexString(cryptoKey.getRSA_DQBytes());
        String pubQInvStr = YiSMCore.toHexString(cryptoKey.getRSA_QInvBytes());

        Assert.assertEquals(pkcs1PrivKStr, pkcs1PrivStr);
        Assert.assertEquals(pkcs8PrivKStr, pkcs8PrivStr);
        Assert.assertEquals(pubNStr, nStr);
        Assert.assertEquals(pubEStr, eStr);
        Assert.assertEquals(pubDStr, dStr);
        Assert.assertEquals(pubPStr, pStr);
        Assert.assertEquals(pubQStr, qStr);
        Assert.assertEquals(pubDPStr, dpStr);
        Assert.assertEquals(pubDQStr, dqStr);
        Assert.assertEquals(pubQInvStr, qinvStr);
    }

    @Test
    public void testCreatePubKeyFromPKCS1() {
        try {
            YiCryptoKey cryptoKey = new YiCryptoKey();
            cryptoKey.setupRSAKeyFromPEM(pkcs1PubKStr);

            checkPubKey(cryptoKey);
        }catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail(ex.getMessage());
        }
    }

    @Test
    public void testCreatePubKeyFromPKCS8() {
        try {
            YiCryptoKey cryptoKey = new YiCryptoKey();
            cryptoKey.setupRSAKeyFromPEM(pkcs8PubKStr);

            checkPubKey(cryptoKey);
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    @Test
    public void testCreatePrivateKeyFromPKCS1() {
        try {
            YiCryptoKey cryptoKey = new YiCryptoKey();
            cryptoKey.setupRSAKeyFromPEM(pkcs1PrivKStr);

            checkPrivKey(cryptoKey);
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    @Test
    public void testCreatePrivateKeyFromPKCS8() {
        try {
            YiCryptoKey cryptoKey = new YiCryptoKey();
            cryptoKey.setupRSAKeyFromPEM(pkcs8PrivKStr);

            checkPrivKey(cryptoKey);
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    @Test
    public void testCreatePublicKeyFromRaw() {
        try {
            YiCryptoKey cryptoKey = new YiCryptoKey();
            cryptoKey.setupRSAPublicKeyFromRaw(YiSMCore.fromHexString(nStr),
                    YiSMCore.fromHexString(eStr));

            checkPubKey(cryptoKey);
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    @Test
    public void testCreatePrivateKeyFromRaw() {
        try {
            YiCryptoKey cryptoKey = new YiCryptoKey();
            cryptoKey.setupRSAPrivateKeyFromRaw(YiSMCore.fromHexString(nStr),
                    YiSMCore.fromHexString(eStr), YiSMCore.fromHexString(dStr),
                    YiSMCore.fromHexString(pStr), YiSMCore.fromHexString(qStr));


            checkPrivKey(cryptoKey);
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    @Test
    public void testCreateCipherNoPadding() {
        try {
            YiCryptoKey privKey = new YiCryptoKey();
            privKey.setupRSAKeyFromPEM(pkcs1PrivKStr);

            YiCryptoKey pubKey = new YiCryptoKey();
            pubKey.setupRSAKeyFromPEM(pkcs1PubKStr);

            byte[] bytes = YiSMCore.fromHexString(nStr + eStr);

            try {
                YiSMCore.getInstance("RSA/None/NoPadding")
                        .setupForCipher(true, pubKey)
                        .update(bytes, 0, 32)
                        .update(bytes, 32, 96)
                        .doFinal();
                Assert.fail("should throw illegal padding exception.");
            }catch (YiCryptoException ex) {
                Assert.assertEquals(ex.getErrorCode().getCode(),
                        YiCryptoErrorCode.ERR_ILLEGAL_PADDING.getCode());
            }

            byte[] cipherBytes = YiSMCore.getInstance("RSA/None/NoPadding")
                    .setupForCipher(true, pubKey)
                    .update(bytes, 0, 32)
                    .update(bytes, 32, 95)
                    .doFinal();
            Log.d("YiLog", "pubK cipher: " + YiSMCore.toHexString(cipherBytes));

            bytes = YiSMCore.getInstance("RSA/None/NoPadding")
                    .setupForCipher(false, privKey)
                    .update(cipherBytes, 0, 32)
                    .update(cipherBytes, 32, 96)
                    .doFinal();
            Log.d("YiLog", "privK plain: " + YiSMCore.toHexString(bytes));

            byte[] plainBytes = YiSMCore.getInstance("RSA/None/NoPadding")
                    .setupForCipher(false, privKey)
                    .doFinal(YiSMCore.fromHexString(rsaNoPaddingCipherDatas[0]));
            Assert.assertArrayEquals(plainBytes, bytes);
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    @Test
    public void testCreateCipherWithPadding() {
        try {
            YiCryptoKey privKey = new YiCryptoKey();
            privKey.setupRSAKeyFromPEM(pkcs1PrivKStr);

            YiCryptoKey pubKey = new YiCryptoKey();
            pubKey.setupRSAKeyFromPEM(pkcs1PubKStr);

            byte[] bytes = YiSMCore.fromHexString(nStr + eStr);

            for(int i = 0; i < cipherAlgs.length; i++) {
                String alg = cipherAlgs[i];

                if(alg.equals("OAEPWithSHA512AndMGF1Padding") ||
                        alg.equals("OAEPWithSHA3-512AndMGF1Padding") ||
                        alg.equals("OAEPWithBLAKE-2BAndMGF1Padding")) {
                    try {
                        YiSMCore.getInstance("RSA/None/" + alg)
                                .setupForCipher(true, pubKey);
                        Assert.fail("must throw illegal key.");
                    }catch (YiCryptoException ex) {
                        // 1024 key is too small.
                        continue;
                    }
                }

                byte[] cipherBytes = YiSMCore.getInstance("RSA/None/" + alg)
                        .setupForCipher(true, pubKey)
                        .update(bytes, 0, 32)
                        .update(bytes, 32, 95)
                        .update(bytes, 127, bytes.length - 127)
                        .doFinal();
                Log.d("YiLog", alg + " pubK cipher: " + YiSMCore.toHexString(cipherBytes));

                bytes = YiSMCore.getInstance("RSA/None/" + alg)
                        .setupForCipher(false, privKey)
                        .update(cipherBytes, 0, 32)
                        .update(cipherBytes, 32, 96)
                        .update(cipherBytes, 128, cipherBytes.length - 128)
                        .doFinal();
                Log.d("YiLog", alg + " privK plain: " + YiSMCore.toHexString(bytes));

                byte[] plainBytes = YiSMCore.getInstance("RSA/None/" + alg)
                        .setupForCipher(false, privKey)
                        .doFinal(YiSMCore.fromHexString(rsaWithPaddingCipherDatas[i][1]));
                Assert.assertArrayEquals(plainBytes, bytes);
            }
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    @Test
    public void testCreateCipher2048() {
        try {
            YiCryptoKey cryptoKey = YiCryptoKey.genRSAKeyPair(0x03, 2048);

            YiCryptoKey privKey = new YiCryptoKey();
            privKey.setupRSAKeyFromPEM(cryptoKey.getRSAPrivateKeyToPem(true));

            YiCryptoKey pubKey = new YiCryptoKey();
            pubKey.setupRSAKeyFromPEM(cryptoKey.getRSAPublicKeyToPem(true));

            byte[] bytes = YiSMCore.fromHexString(nStr + eStr);

            for(int i = 0; i < cipherAlgs.length; i++) {
                String alg = cipherAlgs[i];

                byte[] cipherBytes = YiSMCore.getInstance("RSA/None/" + alg)
                        .setupForCipher(true, pubKey)
                        .update(bytes, 0, 32)
                        .update(bytes, 32, 95)
                        .update(bytes, 127, bytes.length - 127)
                        .doFinal();
                Log.d("YiLog", alg + " pubK cipher: " + YiSMCore.toHexString(cipherBytes));

                bytes = YiSMCore.getInstance("RSA/None/" + alg)
                        .setupForCipher(false, privKey)
                        .update(cipherBytes, 0, 32)
                        .update(cipherBytes, 32, 96)
                        .update(cipherBytes, 128, cipherBytes.length - 128)
                        .doFinal();
                Log.d("YiLog", alg + " privK plain: " + YiSMCore.toHexString(bytes));
            }
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }
}
