using System;
using Cosmos.Conversions;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

// ReSharper disable CheckNamespace

namespace Cosmos.Security.Cryptography
{
    public static class Sm2KeyGenerator
    {
        public static Sm2Key Generate(AsymmetricKeyMode mode)
        {
            return mode switch
            {
                AsymmetricKeyMode.PublicKey => GeneratePublicKey(),
                AsymmetricKeyMode.PrivateKey => GeneratePrivateKey(),
                _ => GenerateKeyInternal()
            };
        }

        public static Sm2Key Generate(AsymmetricKeyMode mode, ECPoint publicPem, BigInteger privatePem)
        {
            return mode switch
            {
                AsymmetricKeyMode.PublicKey => GeneratePublicKey(publicPem),
                AsymmetricKeyMode.PrivateKey => GeneratePrivateKey(privatePem),
                _ => GenerateKeyInternal(publicPem, privatePem)
            };
        }

        public static Sm2Key Generate(AsymmetricKeyMode mode, string publicKey, string privateKey)
        {
            return mode switch
            {
                AsymmetricKeyMode.PublicKey => GeneratePublicKey(publicKey),
                AsymmetricKeyMode.PrivateKey => GeneratePrivateKey(privateKey),
                _ => GenerateKeyInternal(publicKey, privateKey)
            };
        }

        public static Sm2Key GeneratePublicKey()
        {
            var sm2 = GenerateKeyPair();
            return new Sm2Key
            {
                PublicKey = sm2.publicPem,
                PrivateKey = null,
                Mode = AsymmetricKeyMode.PublicKey
            };
        }

        public static Sm2Key GeneratePublicKey(ECPoint publicPem)
        {
            return new()
            {
                PublicKey = BaseConv.ToBase64(publicPem.GetEncoded()), // Hex.Encode(publicPem.GetEncoded()).GetString(encoding.SafeEncodingValue()).ToUpper(),
                PrivateKey = null,
                Mode = AsymmetricKeyMode.PublicKey
            };
        }

        public static Sm2Key GeneratePublicKey(string publicKey)
        {
            return new Sm2Key
            {
                PublicKey = publicKey,
                PrivateKey = null,
                Mode = AsymmetricKeyMode.PublicKey
            };
        }

        public static Sm2Key GeneratePrivateKey()
        {
            var sm2 = GenerateKeyPair();
            return new Sm2Key
            {
                PublicKey = null,
                PrivateKey = sm2.privatePem,
                Mode = AsymmetricKeyMode.PrivateKey
            };
        }

        public static Sm2Key GeneratePrivateKey(BigInteger privatePem)
        {
            return new()
            {
                PublicKey = null,
                PrivateKey = BaseConv.ToBase64(privatePem.ToByteArray()), // Hex.Encode(privatePem.ToByteArray()).GetString(encoding.SafeEncodingValue()).ToUpper(),
                Mode = AsymmetricKeyMode.PrivateKey
            };
        }

        public static Sm2Key GeneratePrivateKey(string privateKey)
        {
            return new()
            {
                PublicKey = null,
                PrivateKey = privateKey,
                Mode = AsymmetricKeyMode.PrivateKey
            };
        }

        private static Sm2Key GenerateKeyInternal()
        {
            var sm2 = GenerateKeyPair();
            return new Sm2Key
            {
                PublicKey = sm2.publicPem,
                PrivateKey = sm2.privatePem,
                Mode = AsymmetricKeyMode.Both
            };
        }

        private static Sm2Key GenerateKeyInternal(ECPoint publicPem, BigInteger privatePem)
        {
            return new Sm2Key(publicPem, privatePem);
        }

        private static Sm2Key GenerateKeyInternal(string publicKey, string privateKey)
        {
            return new Sm2Key
            {
                PublicKey = publicKey,
                PrivateKey = privateKey,
                Mode = AsymmetricKeyMode.Both
            };
        }

        private static (string privatePem, string publicPem) GenerateKeyPair()
        {
            var SM2_ECC_P = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);
            var SM2_ECC_A = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16);
            var SM2_ECC_B = new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16);
            var SM2_ECC_N = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
            var SM2_ECC_H = BigInteger.One;
            var SM2_ECC_GX = new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
            var SM2_ECC_GY = new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);
            var SM2_ECC_Random = new SecureRandom();

            ECCurve curve = new FpCurve(SM2_ECC_P, SM2_ECC_A, SM2_ECC_B, SM2_ECC_N, SM2_ECC_H);

            var g = curve.CreatePoint(SM2_ECC_GX, SM2_ECC_GY);
            var domainParams = new ECDomainParameters(curve, g, SM2_ECC_N);

            var keyPairGenerator = new ECKeyPairGenerator();

            var aKeyGenParams = new ECKeyGenerationParameters(domainParams, SM2_ECC_Random);

            keyPairGenerator.Init(aKeyGenParams);

            var asymmetricCipherKeyPair = keyPairGenerator.GenerateKeyPair();

            var asymmetricPublicKey = (ECPublicKeyParameters) asymmetricCipherKeyPair.Public;
            var asymmetricPrivateKey = (ECPrivateKeyParameters) asymmetricCipherKeyPair.Private;

            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(asymmetricPrivateKey);
            var priPem = Convert.ToBase64String(privateKeyInfo.GetDerEncoded());

            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(asymmetricPublicKey);
            var pubPem = Convert.ToBase64String(publicKeyInfo.GetDerEncoded());

            return (priPem, pubPem);
        }
    }
}