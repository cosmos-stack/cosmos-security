#if !NET451
using System;
using System.Security.Cryptography;
using System.Text;

/*
 * Reference to:
 *     https://github.com/stulzq/RSAUtil/blob/master/XC.RSAUtil/RSABase.cs
 *     Author:Zhiqiang Li
 */

namespace Cosmos.Encryption.Core {
    /// <summary>
    /// RSABase
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public abstract class RSABase {
        /// <summary>
        /// Private rsa
        /// </summary>
        public RSA PrivateRsa;

        /// <summary>
        /// Public rsa
        /// </summary>
        public RSA PublicRsa;

        /// <summary>
        /// Data encoding
        /// </summary>
        public Encoding DataEncoding;

        #region Encrypt - Public key

        /// <summary>
        /// RSA public key encryption
        /// </summary>
        /// <param name="data">Need to encrypt data</param>
        /// <param name="padding">Padding algorithm</param>
        /// <returns></returns>
        public string EncryptByPublicKey(string data, RSAEncryptionPadding padding) {
            if (PublicRsa == null) {
                throw new ArgumentException("public key can not null");
            }

            var dataBytes = DataEncoding.GetBytes(data);
            return EncryptByPublicKey(dataBytes, padding);
        }

        /// <summary>
        /// RSA public key encryption
        /// </summary>
        /// <param name="dataBytes">Need to encrypt data</param>
        /// <param name="padding">Padding algorithm</param>
        /// <returns></returns>
        public string EncryptByPublicKey(byte[] dataBytes, RSAEncryptionPadding padding) {
            if (PublicRsa == null) {
                throw new ArgumentException("public key can not null");
            }

            var resBytes = PublicRsa.Encrypt(dataBytes, padding);
            return Convert.ToBase64String(resBytes);
        }

        #endregion

        #region Encrypt - Private key

        /// <summary>
        /// RSA public key encryption
        /// </summary>
        /// <param name="data">Need to encrypt data</param>
        /// <param name="padding">Padding algorithm</param>
        /// <returns></returns>
        public string EncryptByPrivateKey(string data, RSAEncryptionPadding padding) {
            if (PrivateRsa == null) {
                throw new ArgumentException("private key can not null");
            }

            var dataBytes = DataEncoding.GetBytes(data);
            return EncryptByPrivateKey(dataBytes, padding);
        }

        /// <summary>
        /// RSA private key encryption
        /// </summary>
        /// <param name="dataBytes">Need to encrypt data</param>
        /// <param name="padding">Padding algorithm</param>
        /// <returns></returns>
        public string EncryptByPrivateKey(byte[] dataBytes, RSAEncryptionPadding padding) {
            if (PrivateRsa == null) {
                throw new ArgumentException("private key can not null");
            }

            var resBytes = PrivateRsa.Encrypt(dataBytes, padding);
            return Convert.ToBase64String(resBytes);
        }

        #endregion

        #region Decrypt - Public key

        /// <summary>
        /// RSA public key is decrypted
        /// </summary>
        /// <param name="data">Need to decrypt the data</param>
        /// <param name="padding">Padding algorithm</param>
        /// <returns></returns>
        public string DecryptByPublicKey(string data, RSAEncryptionPadding padding) {
            if (PublicRsa == null) {
                throw new ArgumentException("public key can not null");
            }

            byte[] dataBytes = Convert.FromBase64String(data);
            return DecryptByPublicKey(dataBytes, padding);
        }

        /// <summary>
        /// RSA public key is decrypted
        /// </summary>
        /// <param name="dataBytes">Need to decrypt the data</param>
        /// <param name="padding">Padding algorithm</param>
        /// <returns></returns>
        public string DecryptByPublicKey(byte[] dataBytes, RSAEncryptionPadding padding) {
            if (PublicRsa == null) {
                throw new ArgumentException("public key can not null");
            }

            var resBytes = PublicRsa.Decrypt(dataBytes, padding);
            return DataEncoding.GetString(resBytes);
        }

        #endregion

        #region Decrypt - Private key

        /// <summary>
        /// RSA private key is decrypted
        /// </summary>
        /// <param name="data">Need to decrypt the data</param>
        /// <param name="padding">Padding algorithm</param>
        /// <returns></returns>
        public string DecryptByPrivateKey(string data, RSAEncryptionPadding padding) {
            if (PrivateRsa == null) {
                throw new ArgumentException("private key can not null");
            }

            byte[] dataBytes = Convert.FromBase64String(data);
            return DecryptByPrivateKey(dataBytes, padding);
        }

        /// <summary>
        /// RSA private key is decrypted
        /// </summary>
        /// <param name="dataBytes">Need to decrypt the data</param>
        /// <param name="padding">Padding algorithm</param>
        /// <returns></returns>
        public string DecryptByPrivateKey(byte[] dataBytes, RSAEncryptionPadding padding) {
            if (PrivateRsa == null) {
                throw new ArgumentException("private key can not null");
            }

            var resBytes = PrivateRsa.Decrypt(dataBytes, padding);
            return DataEncoding.GetString(resBytes);
        }

        #endregion

        #region Sign - Private key

        /// <summary>
        /// Use private key for data signing
        /// </summary>
        /// <param name="data">Need to sign data</param>
        /// <param name="hashAlgorithmName">Signed hash algorithm name</param>
        /// <param name="padding">Signature padding algorithm</param>
        /// <returns></returns>
        public string SignData(string data, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding) {
            var res = SignDataGetBytes(data, hashAlgorithmName, padding);
            return Convert.ToBase64String(res);
        }

        /// <summary>
        /// Use private key for data signing
        /// </summary>
        /// <param name="data">Need to sign data</param>
        /// <param name="hashAlgorithmName">Signed hash algorithm name</param>
        /// <param name="padding">Signature padding algorithm</param>
        /// <returns>Sign bytes</returns>
        public byte[] SignDataGetBytes(string data, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding) {
            if (PrivateRsa == null) {
                throw new ArgumentException("private key can not null");
            }

            var dataBytes = DataEncoding.GetBytes(data);
            return PrivateRsa.SignData(dataBytes, hashAlgorithmName, padding);
        }

        #endregion

        #region Verify - Public key

        /// <summary>
        /// Use public key to verify data signature
        /// </summary>
        /// <param name="data">Need to verify the signature data</param>
        /// <param name="sign">sign</param>
        /// <param name="hashAlgorithmName">Signed hash algorithm name</param>
        /// <param name="padding">Signature padding algorithm</param>
        /// <returns></returns>
        public bool VerifyData(string data, string sign, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding) {
            if (PublicRsa == null) {
                throw new ArgumentException("public key can not null");
            }

            var dataBytes = DataEncoding.GetBytes(data);
            var signBytes = Convert.FromBase64String(sign);
            var res = PublicRsa.VerifyData(dataBytes, signBytes, hashAlgorithmName, padding);
            return res;
        }

        #endregion

    }
}
#endif