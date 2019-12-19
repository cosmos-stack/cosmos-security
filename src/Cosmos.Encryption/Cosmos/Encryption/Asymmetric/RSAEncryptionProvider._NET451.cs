#if NET451

using System.Text;

// ReSharper disable once CheckNamespace
namespace Cosmos.Encryption {
    /// <summary>
    /// Asymmetric/RSA encryption.
    /// Reference: Seay Xu
    ///     https://github.com/godsharp/GodSharp.Encryption/blob/master/src/GodSharp.Shared/Encryption/Asymmetric/RSA.cs
    /// Reference: myloveCc
    ///     https://github.com/myloveCc/NETCore.Encrypt/blob/master/src/NETCore.Encrypt/EncryptProvider.cs
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static partial class RSAEncryptionProvider {
        /// <summary>
        /// Encrypt string data with xml/json format.
        /// </summary>
        /// <param name="data">The data to be encrypted.</param>
        /// <param name="publicKey">The public key of xml format.</param>
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <param name="sizeType"></param>
        /// <param name="keyType"></param>
        /// <returns>The encrypted data.</returns>
        public static string EncryptByPublicKey(
            string data,
            string publicKey,
            Encoding encoding = null,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML) {
            var rsa = TouchRsaUtilFromPublicKey(keyType, encoding, publicKey, sizeType);
            return rsa.EncryptByPublicKey(data);
        }

        /// <summary>
        /// Encrypt byte[] data with xml/json format.
        /// </summary>
        /// <param name="dataBytes">The data to be encrypted.</param>
        /// <param name="publicKey">The public key of xml format.</param>
        /// <param name="sizeType"></param>
        /// <param name="keyType"></param>
        /// <returns>The encrypted data.</returns>
        public static string EncryptByPublicKey(
            byte[] dataBytes,
            string publicKey,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML) {
            var rsa = TouchRsaUtilFromPublicKey(keyType, Encoding.UTF8, publicKey, sizeType);
            return rsa.EncryptByPublicKey(dataBytes);
        }


        /// <summary>
        /// Decrypt string data with xml/json format.
        /// </summary>
        /// <param name="data">The data to be encrypted.</param>
        /// <param name="privateKey">The private key of xml format.</param>
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <param name="sizeType"></param>
        /// <param name="keyType"></param>
        /// <returns>The decrypted data.</returns>
        public static string DecryptByPrivateKey(
            string data,
            string privateKey,
            Encoding encoding = null,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML) {
            var rsa = TouchRsaUtilFromPrivateKey(keyType, encoding, privateKey, sizeType);
            return rsa.DecryptByPrivateKey(data);
        }

        /// <summary>
        /// Decrypt byte[] data with xml/json format.
        /// </summary>
        /// <param name="dataBytes">The data to be encrypted.</param>
        /// <param name="privateKey">The private key of xml format.</param>
        /// <param name="sizeType"></param>
        /// <param name="keyType"></param>
        /// <returns>The decrypted data.</returns>
        public static string DecryptByPrivateKey(
            byte[] dataBytes,
            string privateKey,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML) {
            var rsa = TouchRsaUtilFromPrivateKey(keyType, Encoding.UTF8, privateKey, sizeType);
            return rsa.DecryptByPrivateKey(dataBytes);
        }
    }
}

#endif