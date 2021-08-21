# Cosmos Security Overview <a href="https://www.nuget.org/packages/Cosmos.Security/" rel="nofollow"><img src="https://img.shields.io/nuget/v/Cosmos.Security.svg?style=flat" alt="NuGet Version" data-canonical-src="https://img.shields.io/nuget/v/Cosmos.Security.svg?style=flat" style="max-width:100%;"></a>

[Cosmos.Security](https://github.com/cosmos-loops/Cosmos.Security) is an inline project of [Cosmosloops labs.](https://github.com/cosmos-loops).

## Install

From NuGet:

```text
Install-Package Cosmos.Security.Encryption
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

## Usage

HAMC-SHA1:

```c#
var signature = HMACSHA1HashingProvider.Signature("image", "alexinea");
```

DES without salt:

```c#
var s = DESEncryptionProvider.Encrypt("image", "alexinea", "forerunner");
Assert.Equal("fJ2yrnAPaH0=", s);

var o = DESEncryptionProvider.Decrypt(s, "alexinea", "forerunner");
Assert.Equal("image", o);
```

DES with salt:

```c#
var s = DESEncryptionProvider.Encrypt("image", "alexinea", "forerunner", "123412341234");
Assert.Equal("s4h5u8hA/2Y=", s);

var o = DESEncryptionProvider.Decrypt(s, "alexinea", "forerunner", "123412341234");
Assert.Equal("image", o);
```

DES with salt and autokey

```c#
var key = DESEncryptionProvider.CreateKey();
var s = DESEncryptionProvider.Encrypt("image", key.Key, key.IV, "123412341234");
var o = DESEncryptionProvider.Decrypt(s, key.Key, key.IV, "123412341234");
Assert.Equal("image", o);
```

## Thanks

People or projects that have made a great contribbution to this project:

- [Oren Novotny](https://github.com/onovotny)
- [Stulzq](https://github.com/stulzq)
- _The next one must be you_

### Organizations and projects

- [Anarh2404/AdlerSimd](https://github.com/Anarh2404/AdlerSimd)
- [murmurhash-net](https://github.com/darrenkopp/murmurhash-net/)
- [odinmillion/MurmurHash.Net](https://github.com/odinmillion/MurmurHash.Net)
- [Portable.BouncyCastle](https://github.com/onovotny/bc-csharp)
- [Secure-Hash-Algorithms](https://github.com/TerryJackson/Secure-Hash-Algorithms) 
- [ToolGood.RCX](https://github.com/toolgood/RCX)
- [xxtea/xxtea-dotnet](https://github.com/xxtea/xxtea-dotnet)

# License

Member project of [Cosmosloops labs.](https://github.com/cosmos-loops).

[Apache License 2.0](/LICENSE)
