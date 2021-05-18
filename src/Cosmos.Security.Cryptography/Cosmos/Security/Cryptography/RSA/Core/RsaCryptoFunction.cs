#if NET451 || NET452
using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using MsRSA = System.Security.Cryptography.RSACryptoServiceProvider;
#else
using System;
using System.Security.Cryptography;
using System.Text;
using MsRSA = System.Security.Cryptography.RSA;
#endif
using Cosmos.Optionals;
using Cosmos.Security.Cryptography.Core.AsymmetricAlgorithmImpls;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Cryptography
{
    internal abstract partial class RsaCryptoFunction : AsymmetricCryptoFunction<RsaKey>, IRSA
    {
        protected RsaCryptoFunction(RsaKey key)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }

        public override RsaKey Key { get; }

        public override int KeySize => Key.Size;

#if NET451 || NET452
        /// <summary>
        /// RsaUtilBase
        /// </summary>
        internal abstract class RsaUtilBase
        {
            /// <summary>
            /// Private rsa
            /// </summary>
            public MsRSA PrivateRsa;

            /// <summary>
            /// Private rsa key parameter
            /// </summary>
            protected AsymmetricKeyParameter PrivateRsaKeyParameter;

            /// <summary>
            /// Public rsa
            /// </summary>
            public MsRSA PublicRsa;

            /// <summary>
            /// Public rsa key parameter
            /// </summary>
            protected AsymmetricKeyParameter PublicRsaKeyParameter;

            /// <summary>
            /// Data encoding
            /// </summary>
            public Encoding DataEncoding;

            #region Encrypt/Decrypt

            /// <summary>
            /// Encrypt data by public key.
            /// </summary>
            /// <param name="dataBytes">Need to encrypt data</param>
            /// <param name="fOEAP"></param>
            /// <returns></returns>
            public byte[] EncryptByPublicKey(byte[] dataBytes, bool fOEAP)
            {
                if (PublicRsa is null)
                    throw new ArgumentException("public key can not null");
                return PublicRsa.Encrypt(dataBytes, fOEAP);
            }

            /// <summary>
            /// Encrypt data by private key.
            /// </summary>
            /// <param name="dataBytes">Need to encrypt data</param>
            /// <returns></returns>
            public byte[] EncryptByPrivateKey(byte[] dataBytes)
            {
                if (PrivateRsa is null)
                    throw new ArgumentException("private key can not null");
                return PrivateRsa.EncryptValue(dataBytes);
            }

            /// <summary>
            /// Decrypt cipher by public key
            /// </summary>
            /// <param name="dataBytes">Need to decrypt the data</param>
            /// <returns></returns>
            public byte[] DecryptByPublicKey(byte[] dataBytes)
            {
                if (PublicRsa is null)
                    throw new ArgumentException("public key can not null");
                return PublicRsa.DecryptValue(dataBytes);
            }

            /// <summary>
            /// Decrypt cipher by private key.
            /// </summary>
            /// <param name="dataBytes">Need to decrypt the data</param>
            /// <param name="fOEAP"></param>
            /// <returns></returns>
            public byte[] DecryptByPrivateKey(byte[] dataBytes, bool fOEAP)
            {
                if (PrivateRsa is null)
                    throw new ArgumentException("private key can not null");
                return PrivateRsa.Decrypt(dataBytes, fOEAP);
            }

            #endregion

            #region Sign

            /// <summary>
            /// Sign data by PublicKey
            /// </summary>
            /// <param name="dataBytes">Need to sign data</param>
            /// <param name="hashAlgorithmName">Signed hash algorithm name</param>
            /// <returns></returns>
            public byte[] SignByPublicKey(byte[] dataBytes, HashAlgorithmName hashAlgorithmName)
            {
                if (PublicRsa is null)
                    throw new ArgumentException("public key can not null");
                return PublicRsa.SignData(dataBytes, hashAlgorithmName.Name);
            }

            /// <summary>
            /// Sign data by PrivateKey
            /// </summary>
            /// <param name="dataBytes">Need to sign data</param>
            /// <param name="hashAlgorithmName">Signed hash algorithm name</param>
            /// <returns></returns>
            public byte[] SignByPrivateKey(byte[] dataBytes, HashAlgorithmName hashAlgorithmName)
            {
                if (PrivateRsa is null)
                    throw new ArgumentException("private key can not null");
                return PrivateRsa.SignData(dataBytes, hashAlgorithmName.Name);
            }

            #endregion

            #region Verify

            /// <summary>
            /// Verify data by PublicKey
            /// </summary>
            /// <param name="dataBytes">Need to verify the signature data</param>
            /// <param name="signBytes">sign</param>
            /// <param name="hashAlgorithmName">Signed hash algorithm name</param>
            /// <returns></returns>
            public bool VerifyByPublicKey(byte[] dataBytes, byte[] signBytes, HashAlgorithmName hashAlgorithmName)
            {
                if (PublicRsa is null)
                    throw new ArgumentException("public key can not null");
                return PublicRsa.VerifyData(dataBytes, hashAlgorithmName.Name, signBytes);
            }

            /// <summary>
            /// Verify data by PrivateKey
            /// </summary>
            /// <param name="dataBytes">Need to verify the signature data</param>
            /// <param name="signBytes">sign</param>
            /// <param name="hashAlgorithmName">Signed hash algorithm name</param>
            /// <returns></returns>
            public bool VerifyByPrivateKey(byte[] dataBytes, byte[] signBytes, HashAlgorithmName hashAlgorithmName)
            {
                if (PrivateRsa is null)
                    throw new ArgumentException("private key can not null");
                return PrivateRsa.VerifyData(dataBytes, hashAlgorithmName.Name, signBytes);
            }

            #endregion

            #region Misc

            /// <summary>
            /// Get public key parameter
            /// </summary>
            /// <param name="s"></param>
            /// <returns></returns>
            protected AsymmetricKeyParameter GetPublicKeyParameter(string s)
            {
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
            protected AsymmetricKeyParameter GetPrivateKeyParameter(string s)
            {
                s = s.Replace("\r", "").Replace("\n", "").Replace(" ", "");
                byte[] privateInfoByte = Convert.FromBase64String(s);
                // Asn1Object priKeyObj = Asn1Object.FromByteArray(privateInfoByte);//这里也可以从流中读取，从本地导入   
                // PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
                AsymmetricKeyParameter priKey = PrivateKeyFactory.CreateKey(privateInfoByte);
                return priKey;
            }

            #endregion
        }

#else

        /// <summary>
        /// RsaUtilBase
        /// </summary>
        internal abstract class RsaUtilBase
        {
            /// <summary>
            /// Private rsa
            /// </summary>
            public MsRSA PrivateRsa;

            /// <summary>
            /// Public rsa
            /// </summary>
            public MsRSA PublicRsa;

            /// <summary>
            /// Data encoding
            /// </summary>
            public Encoding DataEncoding;

            #region Encrypt

            /// <summary>
            /// Encrypt data by public key
            /// </summary>
            /// <param name="dataBytes">Need to encrypt data</param>
            /// <param name="padding">Padding algorithm</param>
            /// <returns></returns>
            public byte[] EncryptByPublicKey(byte[] dataBytes, RSAEncryptionPadding padding)
            {
                if (PublicRsa is null)
                    throw new ArgumentException("public key can not null");
                return PublicRsa.Encrypt(dataBytes, padding);
            }

            /// <summary>
            /// Encrypt data by private key
            /// </summary>
            /// <param name="dataBytes">Need to encrypt data</param>
            /// <param name="padding">Padding algorithm</param>
            /// <returns></returns>
            public byte[] EncryptByPrivateKey(byte[] dataBytes, RSAEncryptionPadding padding)
            {
                if (PrivateRsa is null)
                    throw new ArgumentException("private key can not null");
                return PrivateRsa.Encrypt(dataBytes, padding);
            }

            #endregion

            #region Decrypt

            /// <summary>
            /// Decrypt cipher by public key
            /// </summary>
            /// <param name="dataBytes">Need to decrypt the data</param>
            /// <param name="padding">Padding algorithm</param>
            /// <returns></returns>
            public byte[] DecryptByPublicKey(byte[] dataBytes, RSAEncryptionPadding padding)
            {
                if (PublicRsa is null)
                    throw new ArgumentException("public key can not null");
                return PublicRsa.Decrypt(dataBytes, padding);
            }

            /// <summary>
            /// Decrypt cipher by private key
            /// </summary>
            /// <param name="dataBytes">Need to decrypt the data</param>
            /// <param name="padding">Padding algorithm</param>
            /// <returns></returns>
            /// <exception cref="ArgumentException"></exception>
            public byte[] DecryptByPrivateKey(byte[] dataBytes, RSAEncryptionPadding padding)
            {
                if (PrivateRsa is null)
                    throw new ArgumentException("private key can not null");
                return PrivateRsa.Decrypt(dataBytes, padding);
            }

            #endregion

            #region Sign

            /// <summary>
            /// Sign data by PublicKey
            /// </summary>
            /// <param name="dataBytes">Need to sign data</param>
            /// <param name="hashAlgorithmName">Signed hash algorithm name</param>
            /// <param name="padding">Signature padding algorithm</param>
            /// <returns></returns>
            public byte[] SignByPublicKey(byte[] dataBytes, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
            {
                if (PublicRsa is null)
                    throw new ArgumentException("public key can not null");
                return PublicRsa.SignData(dataBytes, hashAlgorithmName, padding);
            }

            /// <summary>
            /// Sign data by PrivateKey
            /// </summary>
            /// <param name="dataBytes">Need to sign data</param>
            /// <param name="hashAlgorithmName">Signed hash algorithm name</param>
            /// <param name="padding">Signature padding algorithm</param>
            /// <returns></returns>
            public byte[] SignByPrivateKey(byte[] dataBytes, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
            {
                if (PrivateRsa is null)
                    throw new ArgumentException("private key can not null");
                return PrivateRsa.SignData(dataBytes, hashAlgorithmName, padding);
            }

            #endregion

            #region Verify

            /// <summary>
            /// Verify data by PublicKey
            /// </summary>
            /// <param name="dataBytes">Need to verify the signature data</param>
            /// <param name="signBytes">sign</param>
            /// <param name="hashAlgorithmName">Signed hash algorithm name</param>
            /// <param name="padding">Signature padding algorithm</param>
            /// <returns></returns>
            public bool VerifyByPublicKey(byte[] dataBytes, byte[] signBytes, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
            {
                if (PublicRsa is null)
                    throw new ArgumentException("public key can not null");
                return PublicRsa.VerifyData(dataBytes, signBytes, hashAlgorithmName, padding);
            }

            /// <summary>
            /// Verify data by PrivateKey
            /// </summary>
            /// <param name="dataBytes">Need to verify the signature data</param>
            /// <param name="signBytes">sign</param>
            /// <param name="hashAlgorithmName">Signed hash algorithm name</param>
            /// <param name="padding">Signature padding algorithm</param>
            /// <returns></returns>
            public bool VerifyByPrivateKey(byte[] dataBytes, byte[] signBytes, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
            {
                if (PrivateRsa is null)
                    throw new ArgumentException("private key can not null");
                return PrivateRsa.VerifyData(dataBytes, signBytes, hashAlgorithmName, padding);
            }

            #endregion
        }

#endif

        /// <summary>
        /// RSA Xml util
        /// </summary>
        internal class RsaXmlUtil : RsaUtilBase
        {
            /// <summary>
            /// RSA encryption
            /// SHA256 hash algorithm to use the key length of at least 2048
            /// </summary>
            /// <param name="keySize">Key length in bits:</param>
            /// <param name="privateKey">private Key</param>
            /// <param name="publicKey">public Key</param>
            public RsaXmlUtil(string publicKey, string privateKey = null, int keySize = 2048)
                : this(Encoding.UTF8, publicKey, privateKey, keySize) { }

            /// <summary>
            /// RSA encryption
            /// SHA256 hash algorithm to use the key length of at least 2048
            /// </summary>
            /// <param name="encoding">Data coding</param>
            /// <param name="keySize">Key length in bits:</param>
            /// <param name="privateKey">private Key</param>
            /// <param name="publicKey">public Key</param>
            public RsaXmlUtil(Encoding encoding, string publicKey, string privateKey = null, int keySize = 2048)
            {
                if (string.IsNullOrEmpty(privateKey) && string.IsNullOrEmpty(publicKey))
                {
                    throw new ArgumentException("Public and private keys must not be empty at the same time");
                }

                if (!string.IsNullOrEmpty(privateKey))
                {
#if NET451 || NET452
                    PrivateRsa = new MsRSA {KeySize = keySize};
#else
                    PrivateRsa = MsRSA.Create();
                    PrivateRsa.KeySize = keySize;
#endif
                    PrivateRsa.ImportKeyInLvccXml(privateKey);
                }

                if (!string.IsNullOrEmpty(publicKey))
                {
#if NET451 || NET452
                    PublicRsa = new MsRSA {KeySize = keySize};
#else
                    PublicRsa = MsRSA.Create();
                    PublicRsa.KeySize = keySize;
#endif
                    PublicRsa.ImportKeyInLvccXml(publicKey);
                }

                DataEncoding = encoding.SafeEncodingValue();
            }
        }

        /// <summary>
        /// RSAJsonUtil
        /// </summary>
        internal class RsaJsonUtil : RsaUtilBase
        {
            /// <summary>
            /// RSA encryption
            /// SHA256 hash algorithm to use the key length of at least 2048
            /// </summary>
            /// <param name="keySize">Key length in bits:</param>
            /// <param name="privateKey">private Key</param>
            /// <param name="publicKey">public Key</param>
            public RsaJsonUtil(string publicKey, string privateKey = null, int keySize = 2048)
                : this(Encoding.UTF8, publicKey, privateKey, keySize) { }

            /// <summary>
            /// RSA encryption
            /// SHA256 hash algorithm to use the key length of at least 2048
            /// </summary>
            /// <param name="dataEncoding">Data coding</param>
            /// <param name="keySize">Key length in bits:</param>
            /// <param name="privateKey">private Key</param>
            /// <param name="publicKey">public Key</param>
            public RsaJsonUtil(Encoding dataEncoding, string publicKey, string privateKey = null, int keySize = 2048)
            {
                if (string.IsNullOrEmpty(privateKey) && string.IsNullOrEmpty(publicKey))
                {
                    throw new ArgumentException("Public and private keys must not be empty at the same time");
                }

                if (!string.IsNullOrEmpty(privateKey))
                {
#if NET451 || NET452
                    PrivateRsa = new RSACryptoServiceProvider {KeySize = keySize};
#else
                    PrivateRsa = System.Security.Cryptography.RSA.Create();
                    PrivateRsa.KeySize = keySize;
#endif
                    PrivateRsa.ImportKeyInJson(privateKey);
                }

                if (!string.IsNullOrEmpty(publicKey))
                {
#if NET451 || NET452
                    PublicRsa = new RSACryptoServiceProvider {KeySize = keySize};
#else
                    PublicRsa = System.Security.Cryptography.RSA.Create();
                    PublicRsa.KeySize = keySize;
#endif
                    PublicRsa.ImportKeyInJson(publicKey);
                }

                DataEncoding = dataEncoding ?? Encoding.UTF8;
            }
        }

        /// <summary>
        /// RSAPkcs1Util
        /// </summary>
        internal class RsaPkcs1Util : RsaUtilBase
        {
            /// <summary>
            /// RSAPkcs1Util
            /// </summary>
            /// <param name="publicKey"></param>
            /// <param name="privateKey"></param>
            /// <param name="keySize"></param>
            public RsaPkcs1Util(string publicKey, string privateKey = null, int keySize = 2048)
                : this(Encoding.UTF8, publicKey, privateKey, keySize) { }

            /// <summary>
            /// RSAPkcs1Util
            /// </summary>
            /// <param name="encoding"></param>
            /// <param name="publicKey"></param>
            /// <param name="privateKey"></param>
            /// <param name="keySize"></param>
            public RsaPkcs1Util(Encoding encoding, string publicKey, string privateKey = null, int keySize = 2048)
            {
                if (string.IsNullOrEmpty(privateKey) && string.IsNullOrEmpty(publicKey))
                {
                    throw new Exception("Public and private keys must not be empty at the same time");
                }

                if (!string.IsNullOrEmpty(privateKey))
                {
#if NET451 || NET452
                    PrivateRsa = new MsRSA {KeySize = keySize};
#else
                    PrivateRsa = MsRSA.Create();
                    PrivateRsa.KeySize = keySize;
#endif
                    PrivateRsa.TouchFromPrivateKeyInPkcs1(privateKey, out var priRsap);

#if NET451 || NET452
                    PrivateRsaKeyParameter = GetPrivateKeyParameter(privateKey);
#endif

                    if (string.IsNullOrEmpty(publicKey))
                    {
#if NET451 || NET452
                        PublicRsa = new MsRSA {KeySize = keySize};
#else
                        PublicRsa = MsRSA.Create();
                        PublicRsa.KeySize = keySize;
#endif
                        var pubRasp = new RSAParameters
                        {
                            Modulus = priRsap.Modulus,
                            Exponent = priRsap.Exponent
                        };
                        PublicRsa.ImportParameters(pubRasp);

#if NET451 || NET452
                        PublicRsaKeyParameter = GetPublicKeyParameter(publicKey);
#endif
                    }
                }

                if (!string.IsNullOrEmpty(publicKey))
                {
#if NET451 || NET452
                    PublicRsa = new MsRSA {KeySize = keySize};
#else
                    PublicRsa = MsRSA.Create();
                    PublicRsa.KeySize = keySize;
#endif
                    PublicRsa.TouchFromPublicKeyInPkcs1(publicKey, out _);

#if NET451 || NET452
                    PublicRsaKeyParameter = GetPublicKeyParameter(publicKey);
#endif
                }

                DataEncoding = encoding.SafeEncodingValue();
            }
        }

        /// <summary>
        /// RSAPkcs8Util
        /// </summary>
        internal class RsaPkcs8Util : RsaUtilBase
        {
            /// <summary>
            /// RSAPkcs8Util
            /// </summary>
            /// <param name="publicKey"></param>
            /// <param name="privateKey"></param>
            /// <param name="keySize"></param>
            public RsaPkcs8Util(string publicKey, string privateKey = null, int keySize = 2048)
                : this(Encoding.UTF8, publicKey, privateKey, keySize) { }

            /// <summary>
            /// RSAPkcs8Util
            /// </summary>
            /// <param name="dataEncoding"></param>
            /// <param name="publicKey"></param>
            /// <param name="privateKey"></param>
            /// <param name="keySize"></param>
            public RsaPkcs8Util(Encoding dataEncoding, string publicKey, string privateKey = null, int keySize = 2048)
            {
                if (string.IsNullOrEmpty(privateKey) && string.IsNullOrEmpty(publicKey))
                {
                    throw new Exception("Public and private keys must not be empty at the same time");
                }

                if (!string.IsNullOrEmpty(privateKey))
                {
#if NET451 || NET452
                    PrivateRsa = new MsRSA {KeySize = keySize};
#else
                    PrivateRsa = MsRSA.Create();
                    PrivateRsa.KeySize = keySize;
#endif
                    PrivateRsa.TouchFromPrivateKeyInPkcs8(privateKey, out var priRsap);

#if NET451 || NET452
                    PrivateRsaKeyParameter = GetPrivateKeyParameter(privateKey);
#endif

                    if (string.IsNullOrEmpty(publicKey))
                    {
#if NET451 || NET452
                        PublicRsa = new MsRSA {KeySize = keySize};
#else
                        PublicRsa = MsRSA.Create();
                        PublicRsa.KeySize = keySize;
#endif
                        var pubRsap = new RSAParameters
                        {
                            Modulus = priRsap.Modulus,
                            Exponent = priRsap.Exponent
                        };
                        PublicRsa.ImportParameters(pubRsap);

#if NET451 || NET452
                        PublicRsaKeyParameter = GetPublicKeyParameter(publicKey);
#endif
                    }
                }

                if (!string.IsNullOrEmpty(publicKey))
                {
#if NET451 || NET452
                    PublicRsa = new MsRSA {KeySize = keySize};
#else
                    PublicRsa = MsRSA.Create();
                    PublicRsa.KeySize = keySize;
#endif
                    PublicRsa.TouchFromPublicKeyInPkcs8(publicKey, out _);

#if NET451 || NET452
                    PublicRsaKeyParameter = GetPublicKeyParameter(publicKey);
#endif
                }

                DataEncoding = dataEncoding.SafeEncodingValue();
            }
        }
    }
}