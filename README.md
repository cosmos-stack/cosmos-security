# COSMOSLOOPS/Encryption <a href="https://www.nuget.org/packages/Cosmos.Encryption/" rel="nofollow"><img src="https://img.shields.io/nuget/v/Cosmos.Encryption.svg?style=flat" alt="NuGet Version" data-canonical-src="https://img.shields.io/nuget/v/Cosmos.Encryption.svg?style=flat" style="max-width:100%;"></a>

[Cosmos.Encryption](https://github.com/cosmos-loops/Cosmos.Encryption) is an inline project of [Cosmosloops labs.](https://github.com/cosmos-loops).

## Install

From NuGet:

```
Install-Package Cosmos.Encryption
```

## Includes

- MD2
- MD4
- MD5
- SHA1/256/384/512
- SM3
- HMAC
- MurmurHash2
- MurmurHash3
- Time33/DBJ33A
- AES
- DES/TripleDES
- RC4
- RCX/ThreeRCX
- RCY/ThreeRCY
- SM4
- TEA/XTEA/XXTEA
- DSA
- RSA
- SM2 ***(partially implement)***
- CRC16/32

## Usage

HAMC-SHA1:

```
var signature = HMACSHA1HashingProvider.Signature("image", "alexinea");
```

DES without salt:

```
var s = DESEncryptionProvider.Encrypt("image", "alexinea", "forerunner");
Assert.Equal("fJ2yrnAPaH0=", s);

var o = DESEncryptionProvider.Decrypt(s, "alexinea", "forerunner");
Assert.Equal("image", o);
```

DES with salt:

```
var s = DESEncryptionProvider.Encrypt("image", "alexinea", "forerunner", "123412341234");
Assert.Equal("s4h5u8hA/2Y=", s);

var o = DESEncryptionProvider.Decrypt(s, "alexinea", "forerunner", "123412341234");
Assert.Equal("image", o);
```

DES with salt and autokey

```
 var key = DESEncryptionProvider.CreateKey();
var s = DESEncryptionProvider.Encrypt("image", key.Key, key.IV, "123412341234");
var o = DESEncryptionProvider.Decrypt(s, key.Key, key.IV, "123412341234");
Assert.Equal("image", o);
```

## Thanks

People or projects that have made a great contribbution to this project:

- Mr. [李志强](https://github.com/stulzq)
- [Oren Novotny](https://github.com/onovotny)
- _The next one must be you_

### Organizations and projects

- [Portable.BouncyCastle](https://github.com/onovotny/bc-csharp)
- [ToolGood.RCX](https://github.com/toolgood/RCX)
- [xxtea/xxtea-dotnet](https://github.com/xxtea/xxtea-dotnet)
- [murmurhash-net](https://github.com/darrenkopp/murmurhash-net/)
- [odinmillion/MurmurHash.Net](https://github.com/odinmillion/MurmurHash.Net)

# License

Member project of [Cosmosloops labs.](https://github.com/cosmos-loops).

[Apache License 2.0](/LICENSE)
