#if !NET451

using System.Security.Cryptography;
using System.Text;
using Cosmos.Encryption.Core;
using Cosmos.Encryption.Core.Internals;

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
        /// <param name="padding"></param>
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <param name="sizeType"></param>
        /// <param name="keyType"></param>
        /// <returns>The encrypted data.</returns>
        public static string Encrypt(
            string data,
            string publicKey,
            RSAEncryptionPadding padding,
            Encoding encoding = null,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML) {
            encoding = EncodingHelper.Fixed(encoding);

            switch (keyType) {
                case RSAKeyTypes.XML: {
                    var util = new RSAXmlUtil(encoding, publicKey, keySize: (int) sizeType);
                    return util.EncryptByPublicKey(data, padding);
                }

                case RSAKeyTypes.JSON: {
                    var util = new RSAJsonUtil(encoding, publicKey, keySize: (int) sizeType);
                    return util.EncryptByPublicKey(data, padding);
                }

                case RSAKeyTypes.Pkcs1: {
                    var util = new RSAPkcs1Util(encoding, publicKey, keySize: (int) sizeType);
                    return util.EncryptByPublicKey(data, padding);
                }

                case RSAKeyTypes.Pkcs8: {
                    var util = new RSAPkcs8Util(encoding, publicKey, keySize: (int) sizeType);
                    return util.EncryptByPublicKey(data, padding);
                }

                default: {
                    var util = new RSAXmlUtil(encoding, publicKey, keySize: (int) sizeType);
                    return util.EncryptByPublicKey(data, padding);
                }
            }
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
        public static string Encrypt(
            byte[] dataBytes,
            string publicKey,
            RSAEncryptionPadding padding,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML) {
            switch (keyType) {
                case RSAKeyTypes.XML: {
                    var util = new RSAXmlUtil(Encoding.UTF8, publicKey, keySize: (int) sizeType);
                    return util.EncryptByPublicKey(dataBytes, padding);
                }

                case RSAKeyTypes.JSON: {
                    var util = new RSAJsonUtil(Encoding.UTF8, publicKey, keySize: (int) sizeType);
                    return util.EncryptByPublicKey(dataBytes, padding);
                }

                case RSAKeyTypes.Pkcs1: {
                    var util = new RSAPkcs1Util(Encoding.UTF8, publicKey, keySize: (int) sizeType);
                    return util.EncryptByPublicKey(dataBytes, padding);
                }

                case RSAKeyTypes.Pkcs8: {
                    var util = new RSAPkcs8Util(Encoding.UTF8, publicKey, keySize: (int) sizeType);
                    return util.EncryptByPublicKey(dataBytes, padding);
                }

                default: {
                    var util = new RSAXmlUtil(Encoding.UTF8, publicKey, keySize: (int) sizeType);
                    return util.EncryptByPublicKey(dataBytes, padding);
                }
            }
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
        public static string Decrypt(
            string data,
            string privateKey,
            RSAEncryptionPadding padding,
            Encoding encoding = null,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML) {
            switch (keyType) {
                case RSAKeyTypes.XML: {
                    var util = new RSAXmlUtil(encoding, null, privateKey, (int) sizeType);
                    return util.DecryptByPrivateKey(data, padding);
                }

                case RSAKeyTypes.JSON: {
                    var util = new RSAJsonUtil(encoding, null, privateKey, (int) sizeType);
                    return util.DecryptByPrivateKey(data, padding);
                }

                case RSAKeyTypes.Pkcs1: {
                    var util = new RSAPkcs1Util(encoding, null, privateKey, (int) sizeType);
                    return util.DecryptByPrivateKey(data, padding);
                }

                case RSAKeyTypes.Pkcs8: {
                    var util = new RSAPkcs8Util(encoding, null, privateKey, (int) sizeType);
                    return util.DecryptByPrivateKey(data, padding);
                }

                default: {
                    var util = new RSAXmlUtil(encoding, null, privateKey, (int) sizeType);
                    return util.DecryptByPrivateKey(data, padding);
                }
            }
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
        public static string Decrypt(
            byte[] dataBytes,
            string privateKey,
            RSAEncryptionPadding padding,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML) {
            switch (keyType) {
                case RSAKeyTypes.XML: {
                    var util = new RSAXmlUtil(Encoding.UTF8, null, privateKey, (int) sizeType);
                    return util.DecryptByPrivateKey(dataBytes, padding);
                }

                case RSAKeyTypes.JSON: {
                    var util = new RSAJsonUtil(Encoding.UTF8, null, privateKey, (int) sizeType);
                    return util.DecryptByPrivateKey(dataBytes, padding);
                }

                case RSAKeyTypes.Pkcs1: {
                    var util = new RSAPkcs1Util(Encoding.UTF8, null, privateKey, (int) sizeType);
                    return util.DecryptByPrivateKey(dataBytes, padding);
                }

                case RSAKeyTypes.Pkcs8: {
                    var util = new RSAPkcs8Util(Encoding.UTF8, null, privateKey, (int) sizeType);
                    return util.DecryptByPrivateKey(dataBytes, padding);
                }

                default: {
                    var util = new RSAXmlUtil(Encoding.UTF8, null, privateKey, (int) sizeType);
                    return util.DecryptByPrivateKey(dataBytes, padding);
                }
            }
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
        public static string SignatureAsString(
            string data,
            string publicKey,
            HashAlgorithmName hashAlgorithmName,
            RSASignaturePadding padding,
            Encoding encoding = null,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML) {
            switch (keyType) {
                case RSAKeyTypes.XML: {
                    var util = new RSAXmlUtil(encoding, publicKey, keySize: (int) sizeType);
                    return util.SignData(data, hashAlgorithmName, padding);
                }

                case RSAKeyTypes.JSON: {
                    var util = new RSAJsonUtil(encoding, publicKey, keySize: (int) sizeType);
                    return util.SignData(data, hashAlgorithmName, padding);
                }

                case RSAKeyTypes.Pkcs1: {
                    var util = new RSAPkcs1Util(encoding, publicKey, keySize: (int) sizeType);
                    return util.SignData(data, hashAlgorithmName, padding);
                }

                case RSAKeyTypes.Pkcs8: {
                    var util = new RSAPkcs8Util(encoding, publicKey, keySize: (int) sizeType);
                    return util.SignData(data, hashAlgorithmName, padding);
                }

                default: {
                    var util = new RSAXmlUtil(encoding, publicKey, keySize: (int) sizeType);
                    return util.SignData(data, hashAlgorithmName, padding);
                }
            }
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
        public static byte[] Signature(
            string data,
            string publicKey,
            HashAlgorithmName hashAlgorithmName,
            RSASignaturePadding padding,
            Encoding encoding = null,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML) {
            switch (keyType) {
                case RSAKeyTypes.XML: {
                    var util = new RSAXmlUtil(encoding, publicKey, keySize: (int) sizeType);
                    return util.SignDataGetBytes(data, hashAlgorithmName, padding);
                }

                case RSAKeyTypes.JSON: {
                    var util = new RSAJsonUtil(encoding, publicKey, keySize: (int) sizeType);
                    return util.SignDataGetBytes(data, hashAlgorithmName, padding);
                }

                case RSAKeyTypes.Pkcs1: {
                    var util = new RSAPkcs1Util(encoding, publicKey, keySize: (int) sizeType);
                    return util.SignDataGetBytes(data, hashAlgorithmName, padding);
                }

                case RSAKeyTypes.Pkcs8: {
                    var util = new RSAPkcs8Util(encoding, publicKey, keySize: (int) sizeType);
                    return util.SignDataGetBytes(data, hashAlgorithmName, padding);
                }

                default: {
                    var util = new RSAXmlUtil(encoding, publicKey, keySize: (int) sizeType);
                    return util.SignDataGetBytes(data, hashAlgorithmName, padding);
                }
            }
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
        public static bool Verify(
            string data,
            string publicKey,
            string signature,
            HashAlgorithmName hashAlgorithmName,
            RSASignaturePadding padding,
            Encoding encoding = null,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML) {
            switch (keyType) {
                case RSAKeyTypes.XML: {
                    var util = new RSAXmlUtil(encoding, publicKey, keySize: (int) sizeType);
                    return util.VerifyData(data, signature, hashAlgorithmName, padding);
                }

                case RSAKeyTypes.JSON: {
                    var util = new RSAJsonUtil(encoding, publicKey, keySize: (int) sizeType);
                    return util.VerifyData(data, signature, hashAlgorithmName, padding);
                }

                case RSAKeyTypes.Pkcs1: {
                    var util = new RSAPkcs1Util(encoding, publicKey, keySize: (int) sizeType);
                    return util.VerifyData(data, signature, hashAlgorithmName, padding);
                }

                case RSAKeyTypes.Pkcs8: {
                    var util = new RSAPkcs8Util(encoding, publicKey, keySize: (int) sizeType);
                    return util.VerifyData(data, signature, hashAlgorithmName, padding);
                }

                default: {
                    var util = new RSAXmlUtil(encoding, publicKey, keySize: (int) sizeType);
                    return util.VerifyData(data, signature, hashAlgorithmName, padding);
                }
            }
        }
    }
}

#endif