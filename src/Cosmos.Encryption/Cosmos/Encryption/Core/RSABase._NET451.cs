#if NET451
using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

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
        /// Private rsa key parameter
        /// </summary>
        protected AsymmetricKeyParameter PrivateRsaKeyParameter;

        /// <summary>
        /// Public rsa
        /// </summary>
        public RSA PublicRsa;

        /// <summary>
        /// Public rsa key parameter
        /// </summary>
        protected AsymmetricKeyParameter PublicRsaKeyParameter;

        /// <summary>
        /// Data encoding
        /// </summary>
        public Encoding DataEncoding;

        #region Encrypt - Public key

        /// <summary>
        /// RSA public key encryption
        /// </summary>
        /// <param name="data">Need to encrypt data</param>
        /// <returns></returns>
        public string EncryptByPublicKey(string data) {
            if (PublicRsa == null) {
                throw new ArgumentException("public key can not null");
            }

            var dataBytes = DataEncoding.GetBytes(data);
            return EncryptByPublicKey(dataBytes);
        }

        /// <summary>
        /// RSA public key encryption
        /// </summary>
        /// <param name="dataBytes">Need to encrypt data</param>
        /// <returns></returns>
        public string EncryptByPublicKey(byte[] dataBytes) {
            if (PublicRsa == null) {
                throw new ArgumentException("public key can not null");
            }

            var resBytes = PublicRsa.EncryptValue(dataBytes);
            return Convert.ToBase64String(resBytes);
        }

        #endregion

        #region Encrypt - Private key

        /// <summary>
        /// RSA public key encryption
        /// </summary>
        /// <param name="data">Need to encrypt data</param>
        /// <returns></returns>
        public string EncryptByPrivateKey(string data) {
            if (PrivateRsa == null) {
                throw new ArgumentException("private key can not null");
            }

            var dataBytes = DataEncoding.GetBytes(data);
            return EncryptByPrivateKey(dataBytes);
        }

        /// <summary>
        /// RSA private key encryption
        /// </summary>
        /// <param name="dataBytes">Need to encrypt data</param>
        /// <returns></returns>
        public string EncryptByPrivateKey(byte[] dataBytes) {
            if (PrivateRsa == null) {
                throw new ArgumentException("private key can not null");
            }

            var resBytes = PrivateRsa.EncryptValue(dataBytes);
            return Convert.ToBase64String(resBytes);
        }

        #endregion

        #region Decrypt - Public key

        /// <summary>
        /// RSA public key is decrypted
        /// </summary>
        /// <param name="data">Need to decrypt the data</param>
        /// <returns></returns>
        public string DecryptByPublicKey(string data) {
            if (PublicRsa == null) {
                throw new ArgumentException("public key can not null");
            }

            byte[] dataBytes = Convert.FromBase64String(data);
            return DecryptByPublicKey(dataBytes);
        }

        /// <summary>
        /// RSA public key is decrypted
        /// </summary>
        /// <param name="dataBytes">Need to decrypt the data</param>
        /// <returns></returns>
        public string DecryptByPublicKey(byte[] dataBytes) {
            if (PublicRsa == null) {
                throw new ArgumentException("public key can not null");
            }

            var resBytes = PublicRsa.DecryptValue(dataBytes);
            return DataEncoding.GetString(resBytes);
        }

        #endregion

        #region Decrypt - Private key

        /// <summary>
        /// RSA private key is decrypted
        /// </summary>
        /// <param name="data">Need to decrypt the data</param>
        /// <returns></returns>
        public string DecryptByPrivateKey(string data) {
            if (PrivateRsa == null) {
                throw new ArgumentException("private key can not null");
            }

            byte[] dataBytes = Convert.FromBase64String(data);
            return DecryptByPrivateKey(dataBytes);
        }

        /// <summary>
        /// RSA private key is decrypted
        /// </summary>
        /// <param name="dataBytes">Need to decrypt the data</param>
        /// <returns></returns>
        public string DecryptByPrivateKey(byte[] dataBytes) {
            if (PrivateRsa == null) {
                throw new ArgumentException("private key can not null");
            }

            var resBytes = PrivateRsa.DecryptValue(dataBytes);
            return DataEncoding.GetString(resBytes);
        }

        #endregion

        /*

        #region Sign - Private key

        /// <summary>
        /// Use private key for data signing
        /// </summary>
        /// <param name="data">Need to sign data</param>
        /// <param name="hashAlgorithmName">Signed hash algorithm name</param>
        /// <param name="padding">Signature padding algorithm</param>
        /// <returns></returns>
        public string SignData(string data, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
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
        public byte[] SignDataGetBytes(string data, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            if (PrivateRsa == null)
            {
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
        public bool VerifyData(string data, string sign, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
        {
            if (PublicRsa == null)
            {
                throw new ArgumentException("public key can not null");
            }

            var dataBytes = DataEncoding.GetBytes(data);
            var signBytes = Convert.FromBase64String(sign);
            var res = PublicRsa.VerifyData(dataBytes, signBytes, hashAlgorithmName, padding);
            return res;
        }

        #endregion
        
        */

        #region Misc

        /// <summary>
        /// Get public key parameter
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        protected AsymmetricKeyParameter GetPublicKeyParameter(string s) {
            s = s.Replace("\r", "").Replace("\n", "").Replace(" ", "");
            byte[] publicInfoByte = Convert.FromBase64String(s);
            //Asn1Object pubKeyObj = Asn1Object.FromByteArray(publicInfoByte); //这里也可以从流中读取，从本地导入   
            AsymmetricKeyParameter pubKey = PublicKeyFactory.CreateKey(publicInfoByte);
            return pubKey;
        }

        /// <summary>
        /// Get private key parameter
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        protected AsymmetricKeyParameter GetPrivateKeyParameter(string s) {
            s = s.Replace("\r", "").Replace("\n", "").Replace(" ", "");
            byte[] privateInfoByte = Convert.FromBase64String(s);
            // Asn1Object priKeyObj = Asn1Object.FromByteArray(privateInfoByte);//这里也可以从流中读取，从本地导入   
            // PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            AsymmetricKeyParameter priKey = PrivateKeyFactory.CreateKey(privateInfoByte);
            return priKey;
        }

        #endregion

    }
}
#endif