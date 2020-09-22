#if NET451 || NET452
using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Cosmos.Encryption.Core {
    /// <summary>
    /// RSABase
    /// </summary>
    // ReSharper disable once InconsistentNaming
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    public abstract class RSABase {
        /// <summary>
        /// Private rsa
        /// </summary>
        public RSACryptoServiceProvider PrivateRsa;

        /// <summary>
        /// Private rsa key parameter
        /// </summary>
        protected AsymmetricKeyParameter PrivateRsaKeyParameter;

        /// <summary>
        /// Public rsa
        /// </summary>
        public RSACryptoServiceProvider PublicRsa;

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
        /// <param name="fOEAP"></param>
        /// <returns></returns>
        public string EncryptByPublicKey(string data, bool fOEAP) {
            return EncryptByPublicKey(DataEncoding.GetBytes(data), fOEAP);
        }

        /// <summary>
        /// RSA public key encryption
        /// </summary>
        /// <param name="dataBytes">Need to encrypt data</param>
        /// <param name="fOEAP"></param>
        /// <returns></returns>
        public string EncryptByPublicKey(byte[] dataBytes, bool fOEAP) {
            if (PublicRsa is null) {
                throw new ArgumentException("public key can not null");
            }


            var resBytes = PublicRsa.Encrypt(dataBytes, fOEAP);
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
            return EncryptByPrivateKey(DataEncoding.GetBytes(data));
        }

        /// <summary>
        /// RSA private key encryption
        /// </summary>
        /// <param name="dataBytes">Need to encrypt data</param>
        /// <returns></returns>
        public string EncryptByPrivateKey(byte[] dataBytes) {
            if (PrivateRsa is null) {
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
            return DecryptByPublicKey(Convert.FromBase64String(data));
        }

        /// <summary>
        /// RSA public key is decrypted
        /// </summary>
        /// <param name="dataBytes">Need to decrypt the data</param>
        /// <returns></returns>
        public string DecryptByPublicKey(byte[] dataBytes) {
            if (PublicRsa is null) {
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
        /// <param name="fOEAP"></param>
        /// <returns></returns>
        public string DecryptByPrivateKey(string data, bool fOEAP) {
            return DecryptByPrivateKey(Convert.FromBase64String(data), fOEAP);
        }

        /// <summary>
        /// RSA private key is decrypted
        /// </summary>
        /// <param name="dataBytes">Need to decrypt the data</param>
        /// <param name="fOEAP"></param>
        /// <returns></returns>
        public string DecryptByPrivateKey(byte[] dataBytes, bool fOEAP) {
            if (PrivateRsa is null) {
                throw new ArgumentException("private key can not null");
            }

            var resBytes = PrivateRsa.Decrypt(dataBytes, fOEAP);
            return DataEncoding.GetString(resBytes);
        }

        #endregion

        #region Sign - Public key

        /// <summary>
        /// Use public key for data signing
        /// </summary>
        /// <param name="data">Need to sign data</param>
        /// <param name="hashAlgorithmName">Signed hash algorithm name</param>
        /// <returns></returns>
        public string SignDataByPublicKey(string data, HashAlgorithmName hashAlgorithmName) {
            var res = SignDataByPublicKeyToBytes(data, hashAlgorithmName);
            return Convert.ToBase64String(res);
        }

        /// <summary>
        /// Use private key for data signing
        /// </summary>
        /// <param name="data">Need to sign data</param>
        /// <param name="hashAlgorithmName">Signed hash algorithm name</param>
        /// <returns>Sign bytes</returns>
        public byte[] SignDataByPublicKeyToBytes(string data, HashAlgorithmName hashAlgorithmName) {
            if (PublicRsa is null) {
                throw new ArgumentException("public key can not null");
            }

            var dataBytes = DataEncoding.GetBytes(data);
            return PublicRsa.SignData(dataBytes, hashAlgorithmName.Name);
        }

        #endregion

        #region Sign - Private key

        /// <summary>
        /// Use private key for data signing
        /// </summary>
        /// <param name="data">Need to sign data</param>
        /// <param name="hashAlgorithmName">Signed hash algorithm name</param>
        /// <returns></returns>
        public string SignDataByPrivateKey(string data, HashAlgorithmName hashAlgorithmName) {
            var res = SignDataByPrivateKeyToBytes(data, hashAlgorithmName);
            return Convert.ToBase64String(res);
        }

        /// <summary>
        /// Use private key for data signing
        /// </summary>
        /// <param name="data">Need to sign data</param>
        /// <param name="hashAlgorithmName">Signed hash algorithm name</param>
        /// <returns>Sign bytes</returns>
        public byte[] SignDataByPrivateKeyToBytes(string data, HashAlgorithmName hashAlgorithmName) {
            if (PrivateRsa is null) {
                throw new ArgumentException("private key can not null");
            }

            var dataBytes = DataEncoding.GetBytes(data);
            return PrivateRsa.SignData(dataBytes, hashAlgorithmName.Name);
        }

        #endregion

        #region Verify - Public key

        /// <summary>
        /// Use public key to verify data signature
        /// </summary>
        /// <param name="data">Need to verify the signature data</param>
        /// <param name="sign">sign</param>
        /// <param name="hashAlgorithmName">Signed hash algorithm name</param>
        /// <returns></returns>
        public bool VerifyDataByPublicKey(string data, string sign, HashAlgorithmName hashAlgorithmName) {
            if (PublicRsa is null) {
                throw new ArgumentException("public key can not null");
            }

            var dataBytes = DataEncoding.GetBytes(data);
            var signBytes = Convert.FromBase64String(sign);
            var res = PublicRsa.VerifyData(dataBytes, hashAlgorithmName.Name, signBytes);
            return res;
        }

        #endregion

        #region Verify - Private key

        /// <summary>
        /// Use private key to verify data signature
        /// </summary>
        /// <param name="data">Need to verify the signature data</param>
        /// <param name="sign">sign</param>
        /// <param name="hashAlgorithmName">Signed hash algorithm name</param>
        /// <returns></returns>
        public bool VerifyDataByPrivateKey(string data, string sign, HashAlgorithmName hashAlgorithmName) {
            if (PrivateRsa is null) {
                throw new ArgumentException("private key can not null");
            }

            var dataBytes = DataEncoding.GetBytes(data);
            var signBytes = Convert.FromBase64String(sign);
            var res = PrivateRsa.VerifyData(dataBytes, hashAlgorithmName.Name, signBytes);
            return res;
        }

        #endregion

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