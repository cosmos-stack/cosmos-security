#if NET451

using System;
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
        /// <param name="encoding">The <see cref="T:System.Text.Encoding"/>,default is Encoding.UTF8.</param>
        /// <param name="sizeType"></param>
        /// <param name="keyType"></param>
        /// <returns>The encrypted data.</returns>
        public static string Encrypt(
            string data,
            string publicKey,
            Encoding encoding = null,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML) {
            encoding = EncodingHelper.Fixed(encoding);

            switch (keyType) {
                case RSAKeyTypes.XML: {
                    var util = new RSAXmlUtil(encoding, publicKey, keySize: (int) sizeType);
                    return util.EncryptByPublicKey(data);
                }

                case RSAKeyTypes.JSON: {
                    var util = new RSAJsonUtil(encoding, publicKey, keySize: (int) sizeType);
                    return util.EncryptByPublicKey(data);
                }

                case RSAKeyTypes.Pkcs1: {
                    var util = new RSAPkcs1Util(encoding, publicKey, keySize: (int) sizeType);
                    return util.EncryptByPublicKey(data);
                }

                case RSAKeyTypes.Pkcs8: {
                    var util = new RSAPkcs8Util(encoding, publicKey, keySize: (int) sizeType);
                    return util.EncryptByPublicKey(data);
                }

                default: {
                    var util = new RSAXmlUtil(encoding, publicKey, keySize: (int) sizeType);
                    return util.EncryptByPublicKey(data);
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
        /// <returns>The encrypted data.</returns>
        public static string Encrypt(
            byte[] dataBytes,
            string publicKey,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML) {
            switch (keyType) {
                case RSAKeyTypes.XML: {
                    var util = new RSAXmlUtil(Encoding.UTF8, publicKey, keySize: (int) sizeType);
                    return util.EncryptByPublicKey(dataBytes);
                }

                case RSAKeyTypes.JSON: {
                    var util = new RSAJsonUtil(Encoding.UTF8, publicKey, keySize: (int) sizeType);
                    return util.EncryptByPublicKey(dataBytes);
                }

                case RSAKeyTypes.Pkcs1: {
                    var util = new RSAPkcs1Util(Encoding.UTF8, publicKey, keySize: (int) sizeType);
                    return util.EncryptByPublicKey(dataBytes);
                }

                case RSAKeyTypes.Pkcs8: {
                    var util = new RSAPkcs8Util(Encoding.UTF8, publicKey, keySize: (int) sizeType);
                    return util.EncryptByPublicKey(dataBytes);
                }

                default: {
                    var util = new RSAXmlUtil(Encoding.UTF8, publicKey, keySize: (int) sizeType);
                    return util.EncryptByPublicKey(dataBytes);
                }
            }
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
        public static string Decrypt(
            string data,
            string privateKey,
            Encoding encoding = null,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML) {
            RSABase rsa = keyType switch {
                RSAKeyTypes.XML   => new RSAXmlUtil(encoding, null, privateKey, (int) sizeType),
                RSAKeyTypes.JSON  => new RSAXmlUtil(encoding, null, privateKey, (int) sizeType),
                RSAKeyTypes.Pkcs1 => new RSAPkcs1Util(encoding, null, privateKey, (int) sizeType),
                RSAKeyTypes.Pkcs8 => new RSAPkcs8Util(encoding, null, privateKey, (int) sizeType),
                _                 => throw new NotSupportedException("Unknown RSA key type."),
            };

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
        public static string Decrypt(
            byte[] dataBytes,
            string privateKey,
            RSAKeySizeTypes sizeType = RSAKeySizeTypes.R2048,
            RSAKeyTypes keyType = RSAKeyTypes.XML) {
            switch (keyType) {
                case RSAKeyTypes.XML: {
                    var util = new RSAXmlUtil(Encoding.UTF8, null, privateKey, (int) sizeType);
                    return util.DecryptByPrivateKey(dataBytes);
                }

                case RSAKeyTypes.JSON: {
                    var util = new RSAJsonUtil(Encoding.UTF8, null, privateKey, (int) sizeType);
                    return util.DecryptByPrivateKey(dataBytes);
                }

                case RSAKeyTypes.Pkcs1: {
                    var util = new RSAPkcs1Util(Encoding.UTF8, null, privateKey, (int) sizeType);
                    return util.DecryptByPrivateKey(dataBytes);
                }

                case RSAKeyTypes.Pkcs8: {
                    var util = new RSAPkcs8Util(Encoding.UTF8, null, privateKey, (int) sizeType);
                    return util.DecryptByPrivateKey(dataBytes);
                }

                default: {
                    var util = new RSAXmlUtil(Encoding.UTF8, null, privateKey, (int) sizeType);
                    return util.DecryptByPrivateKey(dataBytes);
                }
            }
        }
    }
}

#endif