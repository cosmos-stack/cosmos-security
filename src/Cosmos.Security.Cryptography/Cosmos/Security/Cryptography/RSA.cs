#if NET451 || NET452
using System.Security.Cryptography;
using System.Text;
using MsRSA = System.Security.Cryptography.RSACryptoServiceProvider;
#else
using System.Security.Cryptography;
using System.Text;
using MsRSA = System.Security.Cryptography.RSA;
#endif
using Factory = Cosmos.Security.Cryptography.RsaFactory;

// ReSharper disable InconsistentNaming

namespace Cosmos.Security.Cryptography
{
    public static class RSA
    {
        public static MsRSA CreateProvider()
        {
#if NET451 || NET452
            return new MsRSA();
#else
            return MsRSA.Create();
#endif
        }

        #region Generate Key

        /// <summary>
        /// Generate RSA key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize"></param>
        /// <param name="keyFormat"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GenerateKey(AsymmetricKeyMode mode, int keySize, RsaKeyFormat keyFormat = RsaKeyFormat.XML, bool keepingFormat = false) => Factory.GenerateKey(mode, keySize, keyFormat, keepingFormat);

        /// <summary>
        /// Generate RSA key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize"></param>
        /// <param name="keyFormat"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GenerateKey(AsymmetricKeyMode mode, RsaKeySize keySize, RsaKeyFormat keyFormat = RsaKeyFormat.XML, bool keepingFormat = false) => Factory.GenerateKey(mode, keySize, keyFormat, keepingFormat);

        /// <summary>
        /// Generate RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keyFormat"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKey(int keySize, RsaKeyFormat keyFormat = RsaKeyFormat.XML, bool keepingFormat = false) => Factory.GeneratePublicKey(keySize, keyFormat, keepingFormat);

        /// <summary>
        /// Generate RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keyFormat"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKey(RsaKeySize keySize, RsaKeyFormat keyFormat = RsaKeyFormat.XML, bool keepingFormat = false) => Factory.GeneratePrivateKey(keySize, keyFormat, keepingFormat);

        /// <summary>
        /// Generate RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keyFormat"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKey(int keySize, RsaKeyFormat keyFormat = RsaKeyFormat.XML, bool keepingFormat = false) => Factory.GeneratePrivateKey(keySize, keyFormat, keepingFormat);

        /// <summary>
        /// Generate RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keyFormat"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKey(RsaKeySize keySize, RsaKeyFormat keyFormat = RsaKeyFormat.XML, bool keepingFormat = false) => Factory.GeneratePublicKey(keySize, keyFormat, keepingFormat);

        /// <summary>
        /// Generate RSA private key.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="keyFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKey(string key, RsaKeyFormat keyFormat = RsaKeyFormat.XML) => Factory.GeneratePrivateKey(key, keyFormat);

        /// <summary>
        /// Generate RSA private key.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="keyFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKey(string key, RsaKeyFormat keyFormat = RsaKeyFormat.XML) => Factory.GeneratePublicKey(key, keyFormat);

        /// <summary>
        /// Generate XML Format RSA Key.
        /// </summary>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInXml(AsymmetricKeyMode mode) => Factory.GenerateKeyInXml(mode);

        /// <summary>
        /// Generate XML Format RSA Key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInXml(AsymmetricKeyMode mode, int keySize) => Factory.GenerateKeyInXml(mode, keySize);

        /// <summary>
        /// Generate XML Format RSA Key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInXml(AsymmetricKeyMode mode, RsaKeySize keySize) => Factory.GenerateKeyInXml(mode, keySize);

        /// <summary>
        /// Generate XML Format RSA public key.
        /// </summary>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInXml() => Factory.GeneratePublicKeyInXml();

        /// <summary>
        /// Generate XML Format RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInXml(int keySize) => Factory.GeneratePublicKeyInXml(keySize);

        /// <summary>
        /// Generate XML Format RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInXml(RsaKeySize keySize) => Factory.GeneratePublicKeyInXml(keySize);

        /// <summary>
        /// Generate XML Format RSA public key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInXml(string key) => Factory.GeneratePublicKeyInXml(key);

        /// <summary>
        /// Generate XML Format RSA private key.
        /// </summary>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInXml() => Factory.GeneratePrivateKeyInXml();

        /// <summary>
        /// Generate XML Format RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInXml(int keySize) => Factory.GeneratePrivateKeyInXml(keySize);

        /// <summary>
        /// Generate XML Format RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInXml(RsaKeySize keySize) => Factory.GeneratePrivateKeyInXml(keySize);

        /// <summary>
        /// Generate XML Format RSA private key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInXml(string key) => Factory.GeneratePrivateKeyInXml(key);

        /// <summary>
        /// Generate JSON Format RSA Key.
        /// </summary>
        /// <param name="mode"></param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInJson(AsymmetricKeyMode mode) => Factory.GenerateKeyInJson(mode);

        /// <summary>
        /// Generate JSON Format RSA Key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInJson(AsymmetricKeyMode mode, int keySize) => Factory.GenerateKeyInJson(mode, keySize);

        /// <summary>
        /// Generate JSON Format RSA Key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInJson(AsymmetricKeyMode mode, RsaKeySize keySize) => Factory.GenerateKeyInJson(mode, keySize);

        /// <summary>
        /// Generate JSON Format RSA public key.
        /// </summary>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInJson() => Factory.GeneratePublicKeyInJson();

        /// <summary>
        /// Generate JSON Format RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInJson(int keySize) => Factory.GeneratePublicKeyInJson(keySize);

        /// <summary>
        /// Generate JSON Format RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInJson(RsaKeySize keySize) => Factory.GeneratePublicKeyInJson(keySize);

        /// <summary>
        /// Generate JSON Format RSA public key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInJson(string key) => Factory.GeneratePublicKeyInJson(key);

        /// <summary>
        /// Generate JSON Format RSA private key.
        /// </summary>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInJson() => Factory.GeneratePrivateKeyInJson();

        /// <summary>
        /// Generate JSON Format RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInJson(int keySize) => Factory.GeneratePrivateKeyInJson(keySize);

        /// <summary>
        /// Generate JSON Format RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInJson(RsaKeySize keySize) => Factory.GeneratePrivateKeyInJson(keySize);

        /// <summary>
        /// Generate JSON Format RSA private key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInJson(string key) => Factory.GeneratePrivateKeyInJson(key);

        /// <summary>
        /// Generate RSA key in Pkcs1 format.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInPkcs1(AsymmetricKeyMode mode, bool keepingFormat) => Factory.GenerateKeyInPkcs1(mode, keepingFormat);

        /// <summary>
        /// Generate RSA key in Pkcs1 format.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInPkcs1(AsymmetricKeyMode mode, int keySize, bool keepingFormat) => Factory.GenerateKeyInPkcs1(mode, keySize, keepingFormat);

        /// <summary>
        /// Generate RSA key in Pkcs1 format.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInPkcs1(AsymmetricKeyMode mode, RsaKeySize keySize, bool keepingFormat) => Factory.GenerateKeyInPkcs1(mode, keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs1 format RSA public key.
        /// </summary>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs1(bool keepingFormat) => Factory.GeneratePublicKeyInPkcs1(keepingFormat);

        /// <summary>
        /// Generate Pkcs1 format RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs1(int keySize, bool keepingFormat) => Factory.GeneratePublicKeyInPkcs1(keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs1 format RSA public key.
        /// </summary>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs1(RsaKeySize keySize, bool keepingFormat) => Factory.GeneratePublicKeyInPkcs1(keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs1 format RSA public key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs1(string key) => Factory.GeneratePublicKeyInPkcs1(key);

        /// <summary>
        /// Generate Pkcs1 format RSA private key.
        /// </summary>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs1(bool keepingFormat) => Factory.GeneratePrivateKeyInPkcs1(keepingFormat);

        /// <summary>
        /// Generate Pkcs1 format RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs1(int keySize, bool keepingFormat) => Factory.GeneratePrivateKeyInPkcs1(keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs1 format RSA private key.
        /// </summary>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs1(RsaKeySize keySize, bool keepingFormat) => Factory.GeneratePrivateKeyInPkcs1(keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs1 format RSA private key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs1(string key) => Factory.GeneratePrivateKeyInPkcs1(key);

        /// <summary>
        /// Generate Pkcs8 format RSA key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInPkcs8(AsymmetricKeyMode mode, bool keepingFormat) => Factory.GenerateKeyInPkcs8(mode, keepingFormat);

        /// <summary>
        /// Generate Pkcs8 format RSA key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInPkcs8(AsymmetricKeyMode mode, int keySize, bool keepingFormat) => Factory.GenerateKeyInPkcs8(mode, keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs8 format RSA key.
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GenerateKeyInPkcs8(AsymmetricKeyMode mode, RsaKeySize keySize, bool keepingFormat) => Factory.GenerateKeyInPkcs8(mode, keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs8 format RSA public key.
        /// </summary>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs8(bool keepingFormat) => Factory.GeneratePublicKeyInPkcs8(keepingFormat);

        /// <summary>
        /// Generate Pkcs8 format RSA public key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs8(int keySize, bool keepingFormat) => Factory.GeneratePublicKeyInPkcs8(keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs8 format RSA public key.
        /// </summary>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs8(RsaKeySize keySize, bool keepingFormat) => Factory.GeneratePublicKeyInPkcs8(keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs8 format RSA public key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePublicKeyInPkcs8(string key) => Factory.GeneratePublicKeyInPkcs8(key);

        /// <summary>
        /// Generate Pkcs8 format RSA private key.
        /// </summary>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs8(bool keepingFormat) => Factory.GeneratePrivateKeyInPkcs8(keepingFormat);

        /// <summary>
        /// Generate Pkcs8 format RSA private key.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="keepingFormat"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs8(int keySize, bool keepingFormat) => Factory.GeneratePrivateKeyInPkcs8(keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs8 format RSA private key.
        /// </summary>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="keepingFormat">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs8(RsaKeySize keySize, bool keepingFormat) => Factory.GeneratePrivateKeyInPkcs8(keySize, keepingFormat);

        /// <summary>
        /// Generate Pkcs8 format RSA private key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RsaKey GeneratePrivateKeyInPkcs8(string key) => Factory.GeneratePrivateKeyInPkcs8(key);

        /// <summary>
        /// Get private key of xml format from certificate file.
        /// </summary>
        /// <param name="certFile">The string path of certificate file.</param>
        /// <param name="password">The string password of certificate file.</param>
        /// <returns>String private key of xml format.</returns>
        public static RsaKey GeneratePrivateKeyFromFile(string certFile, string password) => Factory.GeneratePrivateKeyFromFile(certFile, password);

        /// <summary>
        /// Get public key of xml format from certificate file.
        /// </summary>
        /// <param name="certFile">The string path of certificate file.</param>
        /// <returns>String public key of xml format.</returns>
        public static RsaKey GeneratePublicKeyFromFile(string certFile) => Factory.GeneratePublicKeyFromFile(certFile);

        #endregion

        #region Create

        public static IRSA Create(RsaKey key) => new RsaFunction(key);

        public static IRSA CreateWithPublicKey(string key, RsaKeyFormat keyFormat) => new RsaFunction(RsaKeyGenerator.GeneratePublicKey(key, keyFormat));

        public static IRSA CreateWithPrivateKey(string key, RsaKeyFormat keyFormat) => new RsaFunction(RsaKeyGenerator.GeneratePrivateKey(key, keyFormat));

        public static IRSA CreateWithKeyInXml(string key) => new RsaFunction(RsaKeyGenerator.GenerateInXml(key));

        public static IRSA CreateWithPublicKeyInXml(string key) => new RsaFunction(RsaKeyGenerator.GeneratePublicKeyInXml(key));

        public static IRSA CreateWithPrivateKeyInXml(string key) => new RsaFunction(RsaKeyGenerator.GeneratePrivateKeyInXml(key));

        public static IRSA CreateWithKeyInJson(string key) => new RsaFunction(RsaKeyGenerator.GenerateInJson(key));

        public static IRSA CreateWithPublicKeyInJson(string key) => new RsaFunction(RsaKeyGenerator.GeneratePublicKeyInJson(key));

        public static IRSA CreateWithPrivateKeyInJson(string key) => new RsaFunction(RsaKeyGenerator.GeneratePrivateKeyInJson(key));

        public static IRSA CreateWithPublicKeyInPkcs1(string key) => new RsaFunction(RsaKeyGenerator.GeneratePublicKeyInPkcs1(key));

        public static IRSA CreateWithPrivateKeyInPkcs1(string key) => new RsaFunction(RsaKeyGenerator.GeneratePrivateKeyInPkcs1(key));

        public static IRSA CreateWithPublicKeyInPkcs8(string key) => new RsaFunction(RsaKeyGenerator.GeneratePublicKeyInPkcs8(key));

        public static IRSA CreateWithPrivateKeyInPkcs8(string key) => new RsaFunction(RsaKeyGenerator.GeneratePrivateKeyInPkcs8(key));

        public static IRSA CreateWithPublicKeyFromFile(string certFile) => new RsaFunction(RsaKeyGenerator.GeneratePublicKeyFromFile(certFile));

        public static IRSA CreateWithPrivateKeyFromFile(string certFile, string password) => new RsaFunction(RsaKeyGenerator.GeneratePrivateKeyFromFile(certFile, password));

        #endregion

        #region Encrypt

#if NET451 || NET452
        public static ICryptoValue EncryptByPublicKey(byte[] originalData, string publicKey, RsaKeyFormat format, bool fOEAP)
        {
            var key = RsaKeyGenerator.GeneratePublicKey(publicKey, format);
            var function = Factory.Create(key);
            return function.EncryptByPublicKey(originalData, fOEAP);
        }

        public static ICryptoValue EncryptByPrivateKey(byte[] originalData, string privateKey, RsaKeyFormat format)
        {
            var key = RsaKeyGenerator.GeneratePrivateKey(privateKey, format);
            var function = Factory.Create(key);
            return function.EncryptByPrivateKey(originalData);
        }

        public static ICryptoValue EncryptByPublicKey(string originalText, string publicKey, RsaKeyFormat format, bool fOEAP, Encoding encoding = null)
        {
            var key = RsaKeyGenerator.GeneratePublicKey(publicKey, format);
            var function = Factory.Create(key);
            return function.EncryptByPublicKey(originalText, fOEAP, encoding);
        }

        public static ICryptoValue EncryptByPrivateKey(string originalText, string privateKey, RsaKeyFormat format, Encoding encoding = null)
        {
            var key = RsaKeyGenerator.GeneratePrivateKey(privateKey, format);
            var function = Factory.Create(key);
            return function.EncryptByPrivateKey(originalText, encoding);
        }
#else
        public static ICryptoValue EncryptByPublicKey(byte[] originalData, string publicKey, RsaKeyFormat format, RSAEncryptionPadding padding)
        {
            var key = RsaKeyGenerator.GeneratePublicKey(publicKey, format);
            var function = Factory.Create(key);
            return function.EncryptByPublicKey(originalData, padding);
        }

        public static ICryptoValue EncryptByPrivateKey(byte[] originalData, string privateKey, RsaKeyFormat format, RSAEncryptionPadding padding)
        {
            var key = RsaKeyGenerator.GeneratePrivateKey(privateKey, format);
            var function = Factory.Create(key);
            return function.EncryptByPrivateKey(originalData, padding);
        }

        public static ICryptoValue EncryptByPublicKey(string originalText, string publicKey, RsaKeyFormat format, RSAEncryptionPadding padding, Encoding encoding = null)
        {
            var key = RsaKeyGenerator.GeneratePublicKey(publicKey, format);
            var function = Factory.Create(key);
            return function.EncryptByPublicKey(originalText, padding, encoding);
        }

        public static ICryptoValue EncryptByPrivateKey(string originalText, string privateKey, RsaKeyFormat format, RSAEncryptionPadding padding, Encoding encoding = null)
        {
            var key = RsaKeyGenerator.GeneratePrivateKey(privateKey, format);
            var function = Factory.Create(key);
            return function.EncryptByPrivateKey(originalText, padding, encoding);
        }
#endif

        #endregion

        #region Decrypt

#if NET451 || NET452
        public static ICryptoValue DecryptByPublicKey(byte[] cipherData, string publicKey, RsaKeyFormat format, bool fOEAP)
        {
            var key = RsaKeyGenerator.GeneratePublicKey(publicKey, format);
            var function = Factory.Create(key);
            return function.DecryptByPublicKey(cipherData);
        }

        public static ICryptoValue DecryptByPrivateKey(byte[] cipherData, string privateKey, RsaKeyFormat format, bool fOEAP)
        {
            var key = RsaKeyGenerator.GeneratePrivateKey(privateKey, format);
            var function = Factory.Create(key);
            return function.DecryptByPrivateKey(cipherData, fOEAP);
        }

        public static ICryptoValue DecryptByPublicKey(string cipherText, string publicKey, RsaKeyFormat format, bool fOEAP, Encoding encoding = null)
        {
            var key = RsaKeyGenerator.GeneratePublicKey(publicKey, format);
            var function = Factory.Create(key);
            return function.DecryptByPublicKey(cipherText, encoding);
        }

        public static ICryptoValue DecryptByPrivateKey(string cipherText, string privateKey, RsaKeyFormat format, bool fOEAP, Encoding encoding = null)
        {
            var key = RsaKeyGenerator.GeneratePrivateKey(privateKey, format);
            var function = Factory.Create(key);
            return function.DecryptByPrivateKey(cipherText, fOEAP, encoding);
        }
#else
        public static ICryptoValue DecryptByPublicKey(byte[] cipherData, string publicKey, RsaKeyFormat format, RSAEncryptionPadding padding)
        {
            var key = RsaKeyGenerator.GeneratePublicKey(publicKey, format);
            var function = Factory.Create(key);
            return function.DecryptByPublicKey(cipherData, padding);
        }

        public static ICryptoValue DecryptByPrivateKey(byte[] cipherData, string privateKey, RsaKeyFormat format, RSAEncryptionPadding padding)
        {
            var key = RsaKeyGenerator.GeneratePrivateKey(privateKey, format);
            var function = Factory.Create(key);
            return function.DecryptByPrivateKey(cipherData, padding);
        }

        public static ICryptoValue DecryptByPublicKey(string cipherText, string publicKey, RsaKeyFormat format, RSAEncryptionPadding padding, Encoding encoding = null)
        {
            var key = RsaKeyGenerator.GeneratePublicKey(publicKey, format);
            var function = Factory.Create(key);
            return function.DecryptByPublicKey(cipherText, padding, encoding);
        }

        public static ICryptoValue DecryptByPrivateKey(string cipherText, string privateKey, RsaKeyFormat format, RSAEncryptionPadding padding, Encoding encoding = null)
        {
            var key = RsaKeyGenerator.GeneratePrivateKey(privateKey, format);
            var function = Factory.Create(key);
            return function.DecryptByPrivateKey(cipherText, padding, encoding);
        }
#endif

        #endregion

        #region Sign

#if NET451 || NET452
        public static ISignValue SignByPublicKey(byte[] originalData, string publicKey, RsaKeyFormat format, HashAlgorithmName hashAlgorithmName)
        {
            var key = RsaKeyGenerator.GeneratePublicKey(publicKey, format);
            var function = Factory.Create(key);
            return function.SignByPublicKey(originalData, hashAlgorithmName);
        }

        public static ISignValue SignByPrivateKey(byte[] originalData, string privateKey, RsaKeyFormat format, HashAlgorithmName hashAlgorithmName)
        {
            var key = RsaKeyGenerator.GeneratePrivateKey(privateKey, format);
            var function = Factory.Create(key);
            return function.SignByPrivateKey(originalData, hashAlgorithmName);
        }

        public static ISignValue SignByPublicKey(string originalText, string publicKey, RsaKeyFormat format, HashAlgorithmName hashAlgorithmName, Encoding encoding = null)
        {
            var key = RsaKeyGenerator.GeneratePublicKey(publicKey, format);
            var function = Factory.Create(key);
            return function.SignByPublicKey(originalText, hashAlgorithmName, encoding);
        }

        public static ISignValue SignByPrivateKey(string originalText, string privateKey, RsaKeyFormat format, HashAlgorithmName hashAlgorithmName, Encoding encoding = null)
        {
            var key = RsaKeyGenerator.GeneratePrivateKey(privateKey, format);
            var function = Factory.Create(key);
            return function.SignByPrivateKey(originalText, hashAlgorithmName, encoding);
        }
#else
        public static ISignValue SignByPublicKey(byte[] originalData, string publicKey, RsaKeyFormat format, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            var key = RsaKeyGenerator.GeneratePublicKey(publicKey, format);
            var function = Factory.Create(key);
            return function.SignByPublicKey(originalData, hashAlgorithmName, padding);
        }

        public static ISignValue SignByPrivateKey(byte[] originalData, string privateKey, RsaKeyFormat format, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            var key = RsaKeyGenerator.GeneratePrivateKey(privateKey, format);
            var function = Factory.Create(key);
            return function.SignByPrivateKey(originalData, hashAlgorithmName, padding);
        }

        public static ISignValue SignByPublicKey(string originalText, string publicKey, RsaKeyFormat format, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding = null)
        {
            var key = RsaKeyGenerator.GeneratePublicKey(publicKey, format);
            var function = Factory.Create(key);
            return function.SignByPublicKey(originalText, hashAlgorithmName, padding, encoding);
        }

        public static ISignValue SignByPrivateKey(string originalText, string privateKey, RsaKeyFormat format, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding = null)
        {
            var key = RsaKeyGenerator.GeneratePrivateKey(privateKey, format);
            var function = Factory.Create(key);
            return function.SignByPrivateKey(originalText, hashAlgorithmName, padding, encoding);
        }
#endif

        #endregion

        #region Verify

#if NET451 || NET452
        public static bool VerifyByPublicKey(byte[] originalData, byte[] signature, string publicKey, RsaKeyFormat format, HashAlgorithmName hashAlgorithmName)
        {
            var key = RsaKeyGenerator.GeneratePublicKey(publicKey, format);
            var function = Factory.Create(key);
            return function.VerifyByPublicKey(originalData, signature, hashAlgorithmName);
        }

        public static bool VerifyByPrivateKey(byte[] originalData, byte[] signature, string privateKey, RsaKeyFormat format, HashAlgorithmName hashAlgorithmName)
        {
            var key = RsaKeyGenerator.GeneratePrivateKey(privateKey, format);
            var function = Factory.Create(key);
            return function.VerifyByPrivateKey(originalData, signature, hashAlgorithmName);
        }

        public static bool VerifyByPublicKey(string originalText, string signature, string publicKey, RsaKeyFormat format, HashAlgorithmName hashAlgorithmName, Encoding encoding = null)
        {
            var key = RsaKeyGenerator.GeneratePublicKey(publicKey, format);
            var function = Factory.Create(key);
            return function.VerifyByPublicKey(originalText, signature, hashAlgorithmName, encoding);
        }

        public static bool VerifyByPrivateKey(string originalText, string signature, string privateKey, RsaKeyFormat format, HashAlgorithmName hashAlgorithmName, Encoding encoding = null)
        {
            var key = RsaKeyGenerator.GeneratePrivateKey(privateKey, format);
            var function = Factory.Create(key);
            return function.VerifyByPrivateKey(originalText, signature, hashAlgorithmName, encoding);
        }
#else
        public static bool VerifyByPublicKey(byte[] originalData, byte[] signature, string publicKey, RsaKeyFormat format, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            var key = RsaKeyGenerator.GeneratePublicKey(publicKey, format);
            var function = Factory.Create(key);
            return function.VerifyByPublicKey(originalData, signature, hashAlgorithmName, padding);
        }

        public static bool VerifyByPrivateKey(byte[] originalData, byte[] signature, string privateKey, RsaKeyFormat format, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            var key = RsaKeyGenerator.GeneratePrivateKey(privateKey, format);
            var function = Factory.Create(key);
            return function.VerifyByPrivateKey(originalData, signature, hashAlgorithmName, padding);
        }

        public static bool VerifyByPublicKey(string originalText, string signature, string publicKey, RsaKeyFormat format, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding = null)
        {
            var key = RsaKeyGenerator.GeneratePublicKey(publicKey, format);
            var function = Factory.Create(key);
            return function.VerifyByPublicKey(originalText, signature, hashAlgorithmName, padding, encoding);
        }

        public static bool VerifyByPrivateKey(string originalText, string signature, string privateKey, RsaKeyFormat format, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Encoding encoding = null)
        {
            var key = RsaKeyGenerator.GeneratePrivateKey(privateKey, format);
            var function = Factory.Create(key);
            return function.VerifyByPrivateKey(originalText, signature, hashAlgorithmName, padding, encoding);
        }
#endif

        #endregion
    }
}