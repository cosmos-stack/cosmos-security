#if !NET4511
using System;
using System.Security.Cryptography;
using System.Text;
using Cosmos.Encryption.Core.Internals.Extensions;
using Cosmos.Optionals;

/*
 * Reference to:
 *     https://github.com/stulzq/RSAUtil/blob/master/XC.RSAUtil/RsaPkcs8Util.cs
 *     Author:Zhiqiang Li
 */

namespace Cosmos.Encryption.Core {
    /// <summary>
    /// RSAPkcs8Util
    /// </summary>
    // ReSharper disable once InconsistentNaming
    // ReSharper disable  IdentifierTypo
    public class RSAPkcs8Util : RSABase {
        /// <summary>
        /// RSAPkcs8Util
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="privateKey"></param>
        /// <param name="keySize"></param>
        public RSAPkcs8Util(string publicKey, string privateKey = null, int keySize = 2048)
            : this(Encoding.UTF8, publicKey, privateKey, keySize) { }

        /// <summary>
        /// RSAPkcs8Util
        /// </summary>
        /// <param name="dataEncoding"></param>
        /// <param name="publicKey"></param>
        /// <param name="privateKey"></param>
        /// <param name="keySize"></param>
        public RSAPkcs8Util(Encoding dataEncoding, string publicKey, string privateKey = null, int keySize = 2048) {
            if (string.IsNullOrEmpty(privateKey) && string.IsNullOrEmpty(publicKey)) {
                throw new Exception("Public and private keys must not be empty at the same time");
            }

            if (!string.IsNullOrEmpty(privateKey)) {
#if NET451
                PrivateRsa = new RSACryptoServiceProvider {KeySize = keySize};
#else
                PrivateRsa = RSA.Create();
                PrivateRsa.KeySize = keySize;
#endif
                PrivateRsa.FromPkcs8PrivateString(privateKey, out var priRsap);

#if NET451
                PrivateRsaKeyParameter = GetPrivateKeyParameter(privateKey);
#endif

                if (string.IsNullOrEmpty(publicKey)) {
#if NET451
                    PublicRsa = new RSACryptoServiceProvider {KeySize = keySize};
#else
                    PublicRsa = RSA.Create();
                    PublicRsa.KeySize = keySize;
#endif
                    var pubRsap = new RSAParameters {
                        Modulus = priRsap.Modulus,
                        Exponent = priRsap.Exponent
                    };
                    PublicRsa.ImportParameters(pubRsap);

#if NET451
                    PublicRsaKeyParameter = GetPublicKeyParameter(publicKey);
#endif
                }
            }

            if (!string.IsNullOrEmpty(publicKey)) {
#if NET451
                PublicRsa = new RSACryptoServiceProvider {KeySize = keySize};
#else
                PublicRsa = RSA.Create();
                PublicRsa.KeySize = keySize;
#endif
                PublicRsa.FromPkcs8PublicString(publicKey, out _);

#if NET451
                PublicRsaKeyParameter = GetPublicKeyParameter(publicKey);
#endif
            }

            DataEncoding = dataEncoding.SafeValue();
        }
    }
}

#endif