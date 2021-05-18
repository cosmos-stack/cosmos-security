using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Cosmos.Security.Cryptography.Core.Internals;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

// ReSharper disable InconsistentNaming
// ReSharper disable CheckNamespace

namespace Cosmos.Security.Cryptography
{
    public static class RsaKeyGenerator
    {
        /// <summary>
        /// Generate RSA key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize"></param>
        /// <param name="keyFormat"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey Generate(AsymmetricKeyMode mode, int keySize, RsaKeyFormat keyFormat = RsaKeyFormat.XML, bool keepingFormat = false)
        {
            return keyFormat switch
            {
                RsaKeyFormat.XML => GenerateInXml(mode, keySize),
                RsaKeyFormat.JSON => GenerateInJson(mode, keySize),
                RsaKeyFormat.Pkcs1 => GenerateInPkcs1(mode, keySize, keepingFormat),
                RsaKeyFormat.Pkcs8 => GenerateInPkcs8(mode, keySize, keepingFormat),
                _ => GenerateInXml(mode, keySize)
            };
        }

        /// <summary>
        /// Generate RSA key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize"></param>
        /// <param name="keyFormat"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey Generate(AsymmetricKeyMode mode, RsaKeySize keySize, RsaKeyFormat keyFormat = RsaKeyFormat.XML, bool keepingFormat = false)
        {
            return keyFormat switch
            {
                RsaKeyFormat.XML => GenerateInXml(mode, keySize),
                RsaKeyFormat.JSON => GenerateInJson(mode, keySize),
                RsaKeyFormat.Pkcs1 => GenerateInPkcs1(mode, keySize, keepingFormat),
                RsaKeyFormat.Pkcs8 => GenerateInPkcs8(mode, keySize, keepingFormat),
                _ => GenerateInXml(mode, keySize)
            };
        }

        /// <summary>
        /// Generate RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keyFormat"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKey(int keySize, RsaKeyFormat keyFormat = RsaKeyFormat.XML, bool keepingFormat = false)
        {
            return keyFormat switch
            {
                RsaKeyFormat.XML => GeneratePublicKeyInXml(keySize),
                RsaKeyFormat.JSON => GeneratePublicKeyInJson(keySize),
                RsaKeyFormat.Pkcs1 => GeneratePublicKeyInPkcs1(keySize, keepingFormat),
                RsaKeyFormat.Pkcs8 => GeneratePublicKeyInPkcs8(keySize, keepingFormat),
                _ => GeneratePublicKeyInXml(keySize)
            };
        }

        /// <summary>
        /// Generate RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keyFormat"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKey(RsaKeySize keySize, RsaKeyFormat keyFormat = RsaKeyFormat.XML, bool keepingFormat = false)
        {
            return keyFormat switch
            {
                RsaKeyFormat.XML => GeneratePublicKeyInXml(keySize),
                RsaKeyFormat.JSON => GeneratePublicKeyInJson(keySize),
                RsaKeyFormat.Pkcs1 => GeneratePublicKeyInPkcs1(keySize, keepingFormat),
                RsaKeyFormat.Pkcs8 => GeneratePublicKeyInPkcs8(keySize, keepingFormat),
                _ => GeneratePublicKeyInXml(keySize)
            };
        }

        /// <summary>
        /// Generate RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keyFormat"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKey(int keySize, RsaKeyFormat keyFormat = RsaKeyFormat.XML, bool keepingFormat = false)
        {
            return keyFormat switch
            {
                RsaKeyFormat.XML => GeneratePrivateKeyInXml(keySize),
                RsaKeyFormat.JSON => GeneratePrivateKeyInJson(keySize),
                RsaKeyFormat.Pkcs1 => GeneratePrivateKeyInPkcs1(keySize, keepingFormat),
                RsaKeyFormat.Pkcs8 => GeneratePrivateKeyInPkcs8(keySize, keepingFormat),
                _ => GeneratePrivateKeyInXml(keySize)
            };
        }

        /// <summary>
        /// Generate RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keyFormat"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKey(RsaKeySize keySize, RsaKeyFormat keyFormat = RsaKeyFormat.XML, bool keepingFormat = false)
        {
            return keyFormat switch
            {
                RsaKeyFormat.XML => GeneratePrivateKeyInXml(keySize),
                RsaKeyFormat.JSON => GeneratePrivateKeyInJson(keySize),
                RsaKeyFormat.Pkcs1 => GeneratePrivateKeyInPkcs1(keySize, keepingFormat),
                RsaKeyFormat.Pkcs8 => GeneratePrivateKeyInPkcs8(keySize, keepingFormat),
                _ => GeneratePrivateKeyInXml(keySize)
            };
        }

        /// <summary>
        /// Generate RSA private key.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="keyFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKey(string key, RsaKeyFormat keyFormat = RsaKeyFormat.XML)
        {
            return keyFormat switch
            {
                RsaKeyFormat.XML => GeneratePrivateKeyInXml(key),
                RsaKeyFormat.JSON => GeneratePrivateKeyInJson(key),
                RsaKeyFormat.Pkcs1 => GeneratePrivateKeyInPkcs1(key),
                RsaKeyFormat.Pkcs8 => GeneratePrivateKeyInPkcs8(key),
                _ => GeneratePrivateKeyInXml(key)
            };
        }

        /// <summary>
        /// Generate RSA private key.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="keyFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKey(string key, RsaKeyFormat keyFormat = RsaKeyFormat.XML)
        {
            return keyFormat switch
            {
                RsaKeyFormat.XML => GeneratePrivateKeyInXml(key),
                RsaKeyFormat.JSON => GeneratePrivateKeyInJson(key),
                RsaKeyFormat.Pkcs1 => GeneratePrivateKeyInPkcs1(key),
                RsaKeyFormat.Pkcs8 => GeneratePrivateKeyInPkcs8(key),
                _ => GeneratePrivateKeyInXml(key)
            };
        }

        #region Generate in XML

        /// <summary>
        /// Generate XML Format RSA Key.
        /// </summary>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static RsaKey GenerateInXml(AsymmetricKeyMode mode)
        {
            return GenerateInXml(mode, 1024);
        }

        /// <summary>
        /// Generate XML Format RSA Key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <returns></returns>
        public static RsaKey GenerateInXml(AsymmetricKeyMode mode, int keySize)
        {
            return mode switch
            {
                AsymmetricKeyMode.PublicKey => GeneratePublicKeyInXml(keySize),
                AsymmetricKeyMode.PrivateKey => GeneratePrivateKeyInXml(keySize),
                _ => GenerateInXmlInternal(keySize)
            };
        }

        /// <summary>
        /// Generate XML Format RSA Key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GenerateInXml(AsymmetricKeyMode mode, RsaKeySize keySize)
        {
            return GenerateInXml(mode, (int) keySize);
        }

        /// <summary>
        /// Generate XML Format RSA Key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public static RsaKey GenerateInXml(string key)
        {
            using var rsa = RsaInstanceAccessor.NewAndInitWithKeyInXml(key);
            var publicKey = rsa.ExportKeyInLvccXml(false);
            var privateKey = rsa.ExportKeyInLvccXml(true);

            AsymmetricKeyMode mode;

            if (!string.IsNullOrWhiteSpace(publicKey) && !string.IsNullOrWhiteSpace(privateKey))
                mode = AsymmetricKeyMode.Both;
            else if (!string.IsNullOrWhiteSpace(publicKey))
                mode = AsymmetricKeyMode.PublicKey;
            else if (!string.IsNullOrWhiteSpace(privateKey))
                mode = AsymmetricKeyMode.PrivateKey;
            else
                throw new ArgumentOutOfRangeException(nameof(key), "Invalid XML format Key.");

            return new RsaKey
            {
                PublicKey = publicKey,
                PrivateKey = privateKey,
                Exponent = rsa.ExportParameters(false).Exponent.ToHexString(),
                Modulus = rsa.ExportParameters(false).Modulus.ToHexString(),
                Mode = mode,
                Format = RsaKeyFormat.XML,
                Size = rsa.KeySize
            };
        }

        /// <summary>
        /// Generate XML Format RSA public key.
        /// </summary>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInXml()
        {
            return GeneratePublicKeyInXml(1024);
        }

        /// <summary>
        /// Generate XML Format RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInXml(int keySize)
        {
            using var rsa = new RSACryptoServiceProvider(keySize);
            return new RsaKey
            {
                PublicKey = rsa.ExportKeyInLvccXml(false),
                PrivateKey = null,
                Exponent = rsa.ExportParameters(false).Exponent.ToHexString(),
                Modulus = rsa.ExportParameters(false).Modulus.ToHexString(),
                Mode = AsymmetricKeyMode.PublicKey,
                Format = RsaKeyFormat.XML,
                Size = rsa.KeySize
            };
        }

        /// <summary>
        /// Generate XML Format RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInXml(RsaKeySize keySize)
        {
            return GeneratePublicKeyInXml((int) keySize);
        }

        /// <summary>
        /// Generate XML Format RSA public Key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public static RsaKey GeneratePublicKeyInXml(string key)
        {
            using var rsa = RsaInstanceAccessor.NewAndInitWithKeyInXml(key);
            return new RsaKey
            {
                PublicKey = rsa.ExportKeyInLvccXml(false),
                PrivateKey = null,
                Exponent = rsa.ExportParameters(false).Exponent.ToHexString(),
                Modulus = rsa.ExportParameters(false).Modulus.ToHexString(),
                Mode = AsymmetricKeyMode.PublicKey,
                Format = RsaKeyFormat.XML,
                Size = rsa.KeySize
            };
        }

        /// <summary>
        /// Generate XML Format RSA private key.
        /// </summary>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInXml()
        {
            return GeneratePrivateKeyInXml(1024);
        }

        /// <summary>
        /// Generate XML Format RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInXml(int keySize)
        {
            using var rsa = new RSACryptoServiceProvider(keySize);
            return new RsaKey
            {
                PublicKey = null,
                PrivateKey = rsa.ExportKeyInLvccXml(true),
                Exponent = null,
                Modulus = null,
                Mode = AsymmetricKeyMode.PrivateKey,
                Format = RsaKeyFormat.XML,
                Size = rsa.KeySize
            };
        }

        /// <summary>
        /// Generate XML Format RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInXml(RsaKeySize keySize)
        {
            return GeneratePrivateKeyInXml((int) keySize);
        }

        /// <summary>
        /// Generate XML Format RSA private Key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public static RsaKey GeneratePrivateKeyInXml(string key)
        {
            using var rsa = RsaInstanceAccessor.NewAndInitWithKeyInXml(key);
            return new RsaKey
            {
                PublicKey = null,
                PrivateKey = rsa.ExportKeyInLvccXml(true),
                Exponent = null,
                Modulus = null,
                Mode = AsymmetricKeyMode.PrivateKey,
                Format = RsaKeyFormat.XML,
                Size = rsa.KeySize
            };
        }

        private static RsaKey GenerateInXmlInternal(int keySize)
        {
            using var rsa = new RSACryptoServiceProvider(keySize);
            return new RsaKey
            {
                PublicKey = rsa.ExportKeyInLvccXml(false),
                PrivateKey = rsa.ExportKeyInLvccXml(true),
                Exponent = rsa.ExportParameters(false).Exponent.ToHexString(),
                Modulus = rsa.ExportParameters(false).Modulus.ToHexString(),
                Mode = AsymmetricKeyMode.Both,
                Format = RsaKeyFormat.XML,
                Size = rsa.KeySize
            };
        }

        #endregion

        #region Generate in JSON

        /// <summary>
        /// Generate JSON Format RSA Key.
        /// </summary>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static RsaKey GenerateInJson(AsymmetricKeyMode mode)
        {
            return GenerateInJson(mode, 1024);
        }

        /// <summary>
        /// Generate JSON Format RSA Key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GenerateInJson(AsymmetricKeyMode mode, int keySize)
        {
            return mode switch
            {
                AsymmetricKeyMode.PublicKey => GeneratePublicKeyInJson(keySize),
                AsymmetricKeyMode.PrivateKey => GeneratePrivateKeyInJson(keySize),
                _ => GenerateInJsonInternal(keySize)
            };
        }

        /// <summary>
        /// Generate JSON Format RSA Key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <returns></returns>
        public static RsaKey GenerateInJson(AsymmetricKeyMode mode, RsaKeySize keySize)
        {
            return GenerateInJson(mode, (int) keySize);
        }

        /// <summary>
        /// Generate JSON Format RSA Key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GenerateInJson(string key)
        {
            using var rsa = RsaInstanceAccessor.NewAndInitWithKeyInXml(key);
            var publicKey = rsa.ExportKeyInJson(false);
            var privateKey = rsa.ExportKeyInJson(true);

            AsymmetricKeyMode mode;

            if (!string.IsNullOrWhiteSpace(publicKey) && !string.IsNullOrWhiteSpace(privateKey))
                mode = AsymmetricKeyMode.Both;
            else if (!string.IsNullOrWhiteSpace(publicKey))
                mode = AsymmetricKeyMode.PublicKey;
            else if (!string.IsNullOrWhiteSpace(privateKey))
                mode = AsymmetricKeyMode.PrivateKey;
            else
                throw new ArgumentOutOfRangeException(nameof(key), "Invalid JSON format Key.");

            return new RsaKey
            {
                PublicKey = publicKey,
                PrivateKey = privateKey,
                Exponent = rsa.ExportParameters(false).Exponent.ToHexString(),
                Modulus = rsa.ExportParameters(false).Modulus.ToHexString(),
                Mode = mode,
                Format = RsaKeyFormat.JSON,
                Size = rsa.KeySize
            };
        }

        /// <summary>
        /// Generate JSON Format RSA public key.
        /// </summary>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInJson()
        {
            return GeneratePublicKeyInJson(1024);
        }

        /// <summary>
        /// Generate JSON Format RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInJson(int keySize)
        {
            using var rsa = new RSACryptoServiceProvider(keySize);
            return new RsaKey
            {
                PublicKey = rsa.ExportKeyInJson(false),
                PrivateKey = null,
                Exponent = rsa.ExportParameters(false).Exponent.ToHexString(),
                Modulus = rsa.ExportParameters(false).Modulus.ToHexString(),
                Mode = AsymmetricKeyMode.PublicKey,
                Format = RsaKeyFormat.JSON,
                Size = rsa.KeySize
            };
        }

        /// <summary>
        /// Generate JSON Format RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInJson(RsaKeySize keySize)
        {
            return GeneratePublicKeyInJson((int) keySize);
        }

        /// <summary>
        /// Generate JSON Format RSA Public Key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInJson(string key)
        {
            using var rsa = RsaInstanceAccessor.NewAndInitWithKeyInXml(key);
            return new RsaKey
            {
                PublicKey = rsa.ExportKeyInJson(false),
                PrivateKey = null,
                Exponent = rsa.ExportParameters(false).Exponent.ToHexString(),
                Modulus = rsa.ExportParameters(false).Modulus.ToHexString(),
                Mode = AsymmetricKeyMode.PublicKey,
                Format = RsaKeyFormat.JSON,
                Size = rsa.KeySize
            };
        }

        /// <summary>
        /// Generate JSON Format RSA private key.
        /// </summary>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInJson()
        {
            return GeneratePrivateKeyInJson(1024);
        }

        /// <summary>
        /// Generate JSON Format RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInJson(int keySize)
        {
            using var rsa = new RSACryptoServiceProvider(keySize);
            return new RsaKey
            {
                PublicKey = null,
                PrivateKey = rsa.ExportKeyInJson(true),
                Exponent = null,
                Modulus = null,
                Mode = AsymmetricKeyMode.PrivateKey,
                Format = RsaKeyFormat.JSON,
                Size = rsa.KeySize
            };
        }

        /// <summary>
        /// Generate JSON Format RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInJson(RsaKeySize keySize)
        {
            return GeneratePrivateKeyInJson((int) keySize);
        }

        /// <summary>
        /// Generate JSON Format RSA private Key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInJson(string key)
        {
            using var rsa = RsaInstanceAccessor.NewAndInitWithKeyInXml(key);
            return new RsaKey
            {
                PublicKey = null,
                PrivateKey = rsa.ExportKeyInJson(true),
                Exponent = null,
                Modulus = null,
                Mode = AsymmetricKeyMode.PrivateKey,
                Format = RsaKeyFormat.JSON,
                Size = rsa.KeySize
            };
        }

        private static RsaKey GenerateInJsonInternal(int keySize)
        {
            using var rsa = new RSACryptoServiceProvider(keySize);
            return new RsaKey
            {
                PublicKey = rsa.ExportKeyInJson(false),
                PrivateKey = rsa.ExportKeyInJson(true),
                Exponent = rsa.ExportParameters(false).Exponent.ToHexString(),
                Modulus = rsa.ExportParameters(false).Modulus.ToHexString(),
                Mode = AsymmetricKeyMode.Both,
                Format = RsaKeyFormat.JSON,
                Size = rsa.KeySize
            };
        }

        #endregion

        #region Generate in Pkcs1

        /// <summary>
        /// Generate RSA key in Pkcs1 format.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GenerateInPkcs1(AsymmetricKeyMode mode, bool keepingFormat)
        {
            return GenerateInPkcs1(mode, 1024, keepingFormat);
        }

        /// <summary>
        /// Generate RSA key in Pkcs1 format.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GenerateInPkcs1(AsymmetricKeyMode mode, int keySize, bool keepingFormat)
        {
            return mode switch
            {
                AsymmetricKeyMode.PublicKey => GeneratePublicKeyInPkcs1(keySize, keepingFormat),
                AsymmetricKeyMode.PrivateKey => GeneratePrivateKeyInPkcs1(keySize, keepingFormat),
                _ => GenerateInPkcs1Internal(keySize, keepingFormat)
            };
        }

        /// <summary>
        /// Generate RSA key in Pkcs1 format.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GenerateInPkcs1(AsymmetricKeyMode mode, RsaKeySize keySize, bool keepingFormat)
        {
            return GenerateInPkcs1(mode, (int) keySize, keepingFormat);
        }

        /// <summary>
        /// Generate Pkcs1 format RSA public key.
        /// </summary>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs1(bool keepingFormat)
        {
            return GeneratePublicKeyInPkcs1(1024, keepingFormat);
        }

        /// <summary>
        /// Generate Pkcs1 format RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs1(int keySize, bool keepingFormat)
        {
            var kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");

            //init
            kpGen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));

            //get key pair
            var keyPair = kpGen.GenerateKeyPair();

            //generate public key
            using var publicWriter = new StringWriter();
            var publicPemWriter = new PemWriter(publicWriter);
            publicPemWriter.WriteObject(keyPair.Public);
            publicPemWriter.Writer.Close();

            return new RsaKey
            {
                PublicKey = publicWriter.RemovePkcs1PublicKeyFormatIfNeed(keepingFormat),
                PrivateKey = null,
                Mode = AsymmetricKeyMode.PublicKey,
                Format = RsaKeyFormat.Pkcs1,
                Size = keySize
            };
        }

        /// <summary>
        /// Generate Pkcs1 format RSA public key.
        /// </summary>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs1(RsaKeySize keySize, bool keepingFormat)
        {
            return GeneratePublicKeyInPkcs1((int) keySize, keepingFormat);
        }

        /// <summary>
        /// Generate Pkcs1 format RSA public key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs1(string key)
        {
            using var rsa = RsaInstanceAccessor.NewAndInitWithPublicKeyInPkcs1(key);
            return new RsaKey
            {
                PublicKey = rsa.ExportKeyInJson(false),
                PrivateKey = null,
                Exponent = rsa.ExportParameters(false).Exponent.ToHexString(),
                Modulus = rsa.ExportParameters(false).Modulus.ToHexString(),
                Mode = AsymmetricKeyMode.PublicKey,
                Format = RsaKeyFormat.Pkcs1,
                Size = rsa.KeySize
            };
        }

        /// <summary>
        /// Generate Pkcs1 format RSA private key.
        /// </summary>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs1(bool keepingFormat)
        {
            return GeneratePrivateKeyInPkcs1(1024, keepingFormat);
        }

        /// <summary>
        /// Generate Pkcs1 format RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs1(int keySize, bool keepingFormat)
        {
            var kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");

            //init
            kpGen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));

            //get key pair
            var keyPair = kpGen.GenerateKeyPair();

            //generate private key
            using var privateWriter = new StringWriter();
            var privatePemWriter = new PemWriter(privateWriter);
            privatePemWriter.WriteObject(keyPair.Private);
            privatePemWriter.Writer.Close();

            //result
            return new RsaKey
            {
                PublicKey = null,
                PrivateKey = privateWriter.RemovePkcs1PrivateKeyFormatIfNeed(keepingFormat),
                Mode = AsymmetricKeyMode.PrivateKey,
                Format = RsaKeyFormat.Pkcs1,
                Size = keySize
            };
        }

        /// <summary>
        /// Generate Pkcs1 format RSA private key.
        /// </summary>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs1(RsaKeySize keySize, bool keepingFormat)
        {
            return GeneratePrivateKeyInPkcs1((int) keySize, keepingFormat);
        }

        /// <summary>
        /// Generate Pkcs1 format RSA private key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs1(string key)
        {
            using var rsa = RsaInstanceAccessor.NewAndInitWithPrivateKeyInPkcs1(key);
            return new RsaKey
            {
                PublicKey = null,
                PrivateKey = rsa.ExportKeyInJson(true),
                Exponent = null,
                Modulus = null,
                Mode = AsymmetricKeyMode.PrivateKey,
                Format = RsaKeyFormat.Pkcs1,
                Size = rsa.KeySize
            };
        }

        private static RsaKey GenerateInPkcs1Internal(int keySize, bool keepingFormat)
        {
            var kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");

            //init
            kpGen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));

            //get key pair
            var keyPair = kpGen.GenerateKeyPair();

            //generate private key
            using var privateWriter = new StringWriter();
            var privatePemWriter = new PemWriter(privateWriter);
            privatePemWriter.WriteObject(keyPair.Private);
            privatePemWriter.Writer.Close();

            //generate public key
            using var publicWriter = new StringWriter();
            var publicPemWriter = new PemWriter(publicWriter);
            publicPemWriter.WriteObject(keyPair.Public);
            publicPemWriter.Writer.Close();

            //result
            return new RsaKey
            {
                PublicKey = publicWriter.RemovePkcs1PublicKeyFormatIfNeed(keepingFormat),
                PrivateKey = privateWriter.RemovePkcs1PrivateKeyFormatIfNeed(keepingFormat),
                Mode = AsymmetricKeyMode.Both,
                Format = RsaKeyFormat.Pkcs1,
                Size = keySize
            };
        }

        #endregion

        #region Generate in Pkcs8

        /// <summary>
        /// Generate Pkcs8 format RSA key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GenerateInPkcs8(AsymmetricKeyMode mode, bool keepingFormat)
        {
            return GenerateInPkcs8(mode, 1024, keepingFormat);
        }

        /// <summary>
        /// Generate Pkcs8 format RSA key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GenerateInPkcs8(AsymmetricKeyMode mode, int keySize, bool keepingFormat)
        {
            return mode switch
            {
                AsymmetricKeyMode.PublicKey => GeneratePublicKeyInPkcs8(keySize, keepingFormat),
                AsymmetricKeyMode.PrivateKey => GeneratePrivateKeyInPkcs8(keySize, keepingFormat),
                _ => GenerateInPkcs8Internal(keySize, keepingFormat)
            };
        }

        /// <summary>
        /// Generate Pkcs8 format RSA key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GenerateInPkcs8(AsymmetricKeyMode mode, RsaKeySize keySize, bool keepingFormat)
        {
            return GenerateInPkcs8(mode, (int) keySize, keepingFormat);
        }

        /// <summary>
        /// Generate Pkcs8 format RSA public key.
        /// </summary>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs8(bool keepingFormat)
        {
            return GeneratePublicKeyInPkcs8(1024, keepingFormat);
        }

        /// <summary>
        /// Generate Pkcs8 format RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs8(int keySize, bool keepingFormat)
        {
            var kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");

            //init
            kpGen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));

            //get key pair
            var keyPair = kpGen.GenerateKeyPair();

            //generate public key
            using var publicWriter = new StringWriter();
            var publicPemWriter = new PemWriter(publicWriter);
            var pkcs8 = new Pkcs8Generator(keyPair.Public);
            publicPemWriter.WriteObject(pkcs8);
            publicPemWriter.Writer.Close();

            return new RsaKey
            {
                PublicKey = publicWriter.RemovePkcs8PublicKeyFormatIfNeed(keepingFormat),
                PrivateKey = null,
                Mode = AsymmetricKeyMode.PublicKey,
                Format = RsaKeyFormat.Pkcs8,
                Size = keySize
            };
        }

        /// <summary>
        /// Generate Pkcs8 format RSA public key.
        /// </summary>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs8(RsaKeySize keySize, bool keepingFormat)
        {
            return GeneratePublicKeyInPkcs8((int) keySize, keepingFormat);
        }

        /// <summary>
        /// Generate Pkcs8 format RSA public key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs8(string key)
        {
            using var rsa = RsaInstanceAccessor.NewAndInitWithPublicKeyInPkcs8(key);
            return new RsaKey
            {
                PublicKey = rsa.ExportKeyInJson(false),
                PrivateKey = null,
                Exponent = rsa.ExportParameters(false).Exponent.ToHexString(),
                Modulus = rsa.ExportParameters(false).Modulus.ToHexString(),
                Mode = AsymmetricKeyMode.PublicKey,
                Format = RsaKeyFormat.Pkcs8,
                Size = rsa.KeySize
            };
        }

        /// <summary>
        /// Generate Pkcs8 format RSA private key.
        /// </summary>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs8(bool keepingFormat)
        {
            return GeneratePrivateKeyInPkcs8(1024, keepingFormat);
        }

        /// <summary>
        /// Generate Pkcs8 format RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs8(int keySize, bool keepingFormat)
        {
            var kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");

            //init
            kpGen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));

            //get key pair
            var keyPair = kpGen.GenerateKeyPair();

            //generate private key
            using var privateWriter = new StringWriter();
            var privatePemWriter = new PemWriter(privateWriter);
            var pkcs8 = new Pkcs8Generator(keyPair.Private);
            privatePemWriter.WriteObject(pkcs8);
            privatePemWriter.Writer.Close();

            //result
            return new RsaKey
            {
                PublicKey = null,
                PrivateKey = privateWriter.RemovePkcs8PrivateKeyFormatIfNeed(keepingFormat),
                Mode = AsymmetricKeyMode.PrivateKey,
                Format = RsaKeyFormat.Pkcs8,
                Size = keySize
            };
        }

        /// <summary>
        /// Generate Pkcs8 format RSA private key.
        /// </summary>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs8(RsaKeySize keySize, bool keepingFormat)
        {
            return GeneratePrivateKeyInPkcs8((int) keySize, keepingFormat);
        }

        /// <summary>
        /// Generate Pkcs8 format RSA private key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs8(string key)
        {
            using var rsa = RsaInstanceAccessor.NewAndInitWithPrivateKeyInPkcs8(key);
            return new RsaKey
            {
                PublicKey = null,
                PrivateKey = rsa.ExportKeyInJson(true),
                Exponent = null,
                Modulus = null,
                Mode = AsymmetricKeyMode.PrivateKey,
                Format = RsaKeyFormat.Pkcs8,
                Size = rsa.KeySize
            };
        }

        private static RsaKey GenerateInPkcs8Internal(int keySize, bool keepingFormat)
        {
            var kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");

            //init
            kpGen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));

            //get key pair
            var keyPair = kpGen.GenerateKeyPair();

            //generate private key
            using var privateWriter = new StringWriter();
            var privatePemWriter = new PemWriter(privateWriter);
            privatePemWriter.WriteObject(new Pkcs8Generator(keyPair.Private));
            privatePemWriter.Writer.Close();

            //generate public key
            using var publicWriter = new StringWriter();
            var publicPemWriter = new PemWriter(publicWriter);
            publicPemWriter.WriteObject(new Pkcs8Generator(keyPair.Public));
            publicPemWriter.Writer.Close();

            //result
            return new RsaKey
            {
                PublicKey = publicWriter.RemovePkcs8PublicKeyFormatIfNeed(keepingFormat),
                PrivateKey = privateWriter.RemovePkcs8PrivateKeyFormatIfNeed(keepingFormat),
                Mode = AsymmetricKeyMode.Both,
                Format = RsaKeyFormat.Pkcs8,
                Size = keySize
            };
        }

        #endregion

        #region Generate from file

        /// <summary>
        /// Get private key of xml format from certificate file.
        /// </summary>
        /// <param name="certFile">The string path of certificate file.</param>
        /// <param name="password">The string password of certificate file.</param>
        /// <returns>String private key of xml format.</returns>
        public static RsaKey GeneratePrivateKeyFromFile(string certFile, string password)
        {
            CheckFilePath(certFile, nameof(certFile));
            var cert = new X509Certificate2(certFile, password, X509KeyStorageFlags.Exportable);

            if (!cert.HasPrivateKey)
                throw new InvalidOperationException("Cannot generate the PrivateKey.");

            var privateKey = cert.PrivateKey!;

            return new RsaKey
            {
                PrivateKey = cert.PrivateKey!.ToXmlString(true),
                Mode = AsymmetricKeyMode.PrivateKey,
                Format = RsaKeyFormat.XML,
                Size = privateKey!.KeySize
            };
        }

        /// <summary>
        /// Get public key of xml format from certificate file.
        /// </summary>
        /// <param name="certFile">The string path of certificate file.</param>
        /// <returns>String public key of xml format.</returns>
        public static RsaKey GeneratePublicKeyFromFile(string certFile)
        {
            CheckFilePath(certFile, nameof(certFile));
            var cert = new X509Certificate2(certFile);

            var publicKey = cert.PublicKey.Key;

            return new RsaKey
            {
                PublicKey = publicKey.ToXmlString(false),
                Mode = AsymmetricKeyMode.PublicKey,
                Format = RsaKeyFormat.XML,
                Size = publicKey.KeySize
            };
        }

        private static void CheckFilePath(string filePath, string nameOfFilePath = null)
        {
            nameOfFilePath = string.IsNullOrEmpty(nameOfFilePath) ? nameof(filePath) : nameOfFilePath;
            if (!File.Exists(filePath))
                throw new FileNotFoundException(nameOfFilePath);
        }

        #endregion
    }
}