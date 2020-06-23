#if !NET451

using System.Security.Cryptography;
using System.Text;

// ReSharper disable once CheckNamespace
namespace Cosmos.Encryption
{
    /// <summary>
    /// Asymmetric/RSA encryption.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static partial class RSAEncryptionProvider
    {
        /// <summary>
        /// Encrypt string data with xml/json format.
        /// </summary>
        /// <param name="data">The data to be encrypted.</param>
        /// <param name="publicKey">The public key of xml format.</param>
        /// <param name="padding"></param>
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <param name="sizeType"></param>
        /// <param name="keyType"></param>
        /// <returns>The encrypted data.</returns>
        public static string EncryptByPublicKey(
            string data,
            string publicKey,
            RSAEncryptionPadding padding,
            Encoding encoding = null,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML)
        {
            var rsa = TouchRsaUtilFromPublicKey(keyType, encoding, publicKey, sizeType);
            return rsa.EncryptByPublicKey(data, padding);
        }

        /// <summary>
        /// Encrypt byte[] data with xml/json format.
        /// </summary>
        /// <param name="dataBytes">The data to be encrypted.</param>
        /// <param name="publicKey">The public key of xml format.</param>
        /// <param name="sizeType"></param>
        /// <param name="keyType"></param>
        /// <param name="padding"></param>
        /// <returns>The encrypted data.</returns>
        public static string EncryptByPublicKey(
            byte[] dataBytes,
            string publicKey,
            RSAEncryptionPadding padding,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML)
        {
            var rsa = TouchRsaUtilFromPublicKey(keyType, Encoding.UTF8, publicKey, sizeType);
            return rsa.EncryptByPublicKey(dataBytes, padding);
        }

        /// <summary>
        /// Encrypt string data with xml/json format.
        /// </summary>
        /// <param name="data">The data to be encrypted.</param>
        /// <param name="privateKey">The public key of xml format.</param>
        /// <param name="padding"></param>
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <param name="sizeType"></param>
        /// <param name="keyType"></param>
        /// <returns>The encrypted data.</returns>
        public static string EncryptByPrivateKey(
            string data,
            string privateKey,
            RSAEncryptionPadding padding,
            Encoding encoding = null,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML)
        {
            var rsa = TouchRsaUtilFromPrivateKey(keyType, encoding, privateKey, sizeType);
            return rsa.EncryptByPrivateKey(data, padding);
        }

        /// <summary>
        /// Encrypt byte[] data with xml/json format.
        /// </summary>
        /// <param name="dataBytes">The data to be encrypted.</param>
        /// <param name="privateKey">The public key of xml format.</param>
        /// <param name="sizeType"></param>
        /// <param name="keyType"></param>
        /// <param name="padding"></param>
        /// <returns>The encrypted data.</returns>
        public static string EncryptByPrivateKey(
            byte[] dataBytes,
            string privateKey,
            RSAEncryptionPadding padding,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML)
        {
            var rsa = TouchRsaUtilFromPrivateKey(keyType, Encoding.UTF8, privateKey, sizeType);
            return rsa.EncryptByPrivateKey(dataBytes, padding);
        }

        /// <summary>
        /// Decrypt string data with xml/json format.
        /// </summary>
        /// <param name="data">The data to be encrypted.</param>
        /// <param name="privateKey">The private key of xml format.</param>
        /// <param name="padding"></param>
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <param name="sizeType"></param>
        /// <param name="keyType"></param>
        /// <returns>The decrypted data.</returns>
        public static string DecryptByPrivateKey(
            string data,
            string privateKey,
            RSAEncryptionPadding padding,
            Encoding encoding = null,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML)
        {
            var rsa = TouchRsaUtilFromPrivateKey(keyType, encoding, privateKey, sizeType);
            return rsa.DecryptByPrivateKey(data, padding);
        }

        /// <summary>
        /// Decrypt byte[] data with xml/json format.
        /// </summary>
        /// <param name="dataBytes">The data to be encrypted.</param>
        /// <param name="privateKey">The private key of xml format.</param>
        /// <param name="padding"></param>
        /// <param name="sizeType"></param>
        /// <param name="keyType"></param>
        /// <returns>The decrypted data.</returns>
        public static string DecryptByPrivateKey(
            byte[] dataBytes,
            string privateKey,
            RSAEncryptionPadding padding,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML)
        {
            var rsa = TouchRsaUtilFromPrivateKey(keyType, Encoding.UTF8, privateKey, sizeType);
            return rsa.DecryptByPrivateKey(dataBytes, padding);
        }

        /// <summary>
        /// Signature as string
        /// </summary>
        /// <param name="data"></param>
        /// <param name="publicKey"></param>
        /// <param name="hashAlgorithmName"></param>
        /// <param name="padding"></param>
        /// <param name="encoding"></param>
        /// <param name="sizeType"></param>
        /// <param name="keyType"></param>
        /// <returns></returns>
        public static string SignatureByPublicKeyAsString(
            string data,
            string publicKey,
            HashAlgorithmName hashAlgorithmName,
            RSASignaturePadding padding,
            Encoding encoding = null,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML)
        {
            var rsa = TouchRsaUtilFromPublicKey(keyType, encoding, publicKey, sizeType);
            return rsa.SignDataByPublicKey(data, hashAlgorithmName, padding);
        }

        /// <summary>
        /// Signature as byte[]
        /// </summary>
        /// <param name="data"></param>
        /// <param name="publicKey"></param>
        /// <param name="hashAlgorithmName"></param>
        /// <param name="padding"></param>
        /// <param name="encoding"></param>
        /// <param name="sizeType"></param>
        /// <param name="keyType"></param>
        /// <returns></returns>
        public static byte[] SignatureByPublicKeyAsBytes(
            string data,
            string publicKey,
            HashAlgorithmName hashAlgorithmName,
            RSASignaturePadding padding,
            Encoding encoding = null,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML)
        {
            var rsa = TouchRsaUtilFromPublicKey(keyType, encoding, publicKey, sizeType);
            return rsa.SignDataByPublicKeyToBytes(data, hashAlgorithmName, padding);
        }

        /// <summary>
        /// Signature as string
        /// </summary>
        /// <param name="data"></param>
        /// <param name="privateKey"></param>
        /// <param name="hashAlgorithmName"></param>
        /// <param name="padding"></param>
        /// <param name="encoding"></param>
        /// <param name="sizeType"></param>
        /// <param name="keyType"></param>
        /// <returns></returns>
        public static string SignatureByPrivateKeyAsString(
            string data,
            string privateKey,
            HashAlgorithmName hashAlgorithmName,
            RSASignaturePadding padding,
            Encoding encoding = null,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML)
        {
            var rsa = TouchRsaUtilFromPrivateKey(keyType, encoding, privateKey, sizeType);
            return rsa.SignDataByPrivateKey(data, hashAlgorithmName, padding);
        }

        /// <summary>
        /// Signature as byte[]
        /// </summary>
        /// <param name="data"></param>
        /// <param name="privateKey"></param>
        /// <param name="hashAlgorithmName"></param>
        /// <param name="padding"></param>
        /// <param name="encoding"></param>
        /// <param name="sizeType"></param>
        /// <param name="keyType"></param>
        /// <returns></returns>
        public static byte[] SignatureByPrivateAsBytes(
            string data,
            string privateKey,
            HashAlgorithmName hashAlgorithmName,
            RSASignaturePadding padding,
            Encoding encoding = null,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML)
        {
            var rsa = TouchRsaUtilFromPrivateKey(keyType, encoding, privateKey, sizeType);
            return rsa.SignDataByPrivateKeyToBytes(data, hashAlgorithmName, padding);
        }

        /// <summary>
        /// Verify
        /// </summary>
        /// <param name="data"></param>
        /// <param name="publicKey"></param>
        /// <param name="signature"></param>
        /// <param name="hashAlgorithmName"></param>
        /// <param name="padding"></param>
        /// <param name="encoding"></param>
        /// <param name="sizeType"></param>
        /// <param name="keyType"></param>
        /// <returns></returns>
        public static bool VerifyByPublicKey(
            string data,
            string publicKey,
            string signature,
            HashAlgorithmName hashAlgorithmName,
            RSASignaturePadding padding,
            Encoding encoding = null,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML)
        {
            var rsa = TouchRsaUtilFromPublicKey(keyType, encoding, publicKey, sizeType);
            return rsa.VerifyDataByPublicKey(data, signature, hashAlgorithmName, padding);
        }

        /// <summary>
        /// Verify
        /// </summary>
        /// <param name="data"></param>
        /// <param name="privateKey"></param>
        /// <param name="signature"></param>
        /// <param name="hashAlgorithmName"></param>
        /// <param name="padding"></param>
        /// <param name="encoding"></param>
        /// <param name="sizeType"></param>
        /// <param name="keyType"></param>
        /// <returns></returns>
        public static bool VerifyByPrivateKey(
            string data,
            string privateKey,
            string signature,
            HashAlgorithmName hashAlgorithmName,
            RSASignaturePadding padding,
            Encoding encoding = null,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML)
        {
            var rsa = TouchRsaUtilFromPrivateKey(keyType, encoding, privateKey, sizeType);
            return rsa.VerifyDataByPrivateKey(data, signature, hashAlgorithmName, padding);
        }
    }
}

#endif