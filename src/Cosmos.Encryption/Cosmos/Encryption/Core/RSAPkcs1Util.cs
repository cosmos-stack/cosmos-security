#if !NET4511

using System;
using System.Security.Cryptography;
using System.Text;
using Cosmos.Encryption.Core.Internals.Extensions;

/*
 * Reference to:
 *     https://github.com/stulzq/RSAUtil/blob/master/XC.RSAUtil/RsaPkcs1Util.cs
 *     Author:Zhiqiang Li
 */

namespace Cosmos.Encryption.Core {
    /// <summary>
    /// RSAPkcs1Util
    /// </summary>
    // ReSharper disable once InconsistentNaming
    // ReSharper disable  IdentifierTypo
    public class RSAPkcs1Util : RSABase {
        /// <summary>
        /// RSAPkcs1Util
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="privateKey"></param>
        /// <param name="keySize"></param>
        public RSAPkcs1Util(string publicKey, string privateKey = null, int keySize = 2048)
            : this(Encoding.UTF8, publicKey, privateKey, keySize) { }

        /// <summary>
        /// RSAPkcs1Util
        /// </summary>
        /// <param name="encoding"></param>
        /// <param name="publicKey"></param>
        /// <param name="privateKey"></param>
        /// <param name="keySize"></param>
        public RSAPkcs1Util(Encoding encoding, string publicKey, string privateKey = null, int keySize = 2048) {
            if (string.IsNullOrEmpty(privateKey) && string.IsNullOrEmpty(publicKey)) {
                throw new Exception("Public and private keys must not be empty at the same time");
            }

            if (!string.IsNullOrEmpty(privateKey)) {
                PrivateRsa = RSA.Create();
                PrivateRsa.KeySize = keySize;
                PrivateRsa.FromPkcs1PrivateString(privateKey, out var priRsap);

#if NET451
                PrivateRsaKeyParameter = GetPrivateKeyParameter(privateKey);
#endif

                if (string.IsNullOrEmpty(publicKey)) {
                    PublicRsa = RSA.Create();
                    PublicRsa.KeySize = keySize;
                    var pubRasp = new RSAParameters {
                        Modulus = priRsap.Modulus,
                        Exponent = priRsap.Exponent
                    };
                    PublicRsa.ImportParameters(pubRasp);

#if NET451
                    PublicRsaKeyParameter = GetPublicKeyParameter(publicKey);
#endif
                }
            }

            if (!string.IsNullOrEmpty(publicKey)) {
                PublicRsa = RSA.Create();
                PublicRsa.KeySize = keySize;
                PublicRsa.FromPkcs1PublicString(publicKey, out _);

#if NET451
                PublicRsaKeyParameter = GetPublicKeyParameter(publicKey);
#endif
            }

            DataEncoding = encoding ?? Encoding.UTF8;
        }
    }
}

#endif