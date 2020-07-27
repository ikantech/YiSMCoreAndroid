# YiSMCoreAndroid
yismcore for android

# How To

gradle import

```
implementation 'net.yiim.yismcore:yismcore-android:1.0.1'
```

## Digest
support digest algorithm

> MD5、SHA1、SHA224、SHA256、SHA384、SHA512、SM3、SHA3-224、SHA3-256、SHA3-384、SHA3-512、BLAKE-2S、BLAKE-2B

MD5 example
```java
byte[] retBytes = YiSMCore.getInstance("MD5")
                        .setupForDigest()
                        .doFinal(new byte[]{0x61, 0x62, 0x63});
```

## Docs

[document website](http://www.yiim.net/2020/07/14/yismcore_index/)