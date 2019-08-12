using System;
using System.Security.Cryptography;
using System.Text;
using Cosmos.Encryption.Core.Internals.Extensions;

/*
 * Reference to:
 *     https://github.com/stulzq/RSAUtil/blob/master/XC.RSAUtil/RsaPkcs8Util.cs
 *     Author:Zhiqiang Li
 */

namespace Cosmos.Encryption.Core
{
    // ReSharper disable once InconsistentNaming
    // ReSharper disable  IdentifierTypo
    public class RSAPkcs8Util : RSABase
    {
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
        public RSAPkcs8Util(Encoding dataEncoding, string publicKey, string privateKey = null, int keySize = 2048)
        {
            if (string.IsNullOrEmpty(privateKey) && string.IsNullOrEmpty(publicKey))
            {
                throw new Exception("Public and private keys must not be empty at the same time");
            }

            if (!string.IsNullOrEmpty(privateKey))
            {
                PrivateRsa = RSA.Create();
                PrivateRsa.KeySize = keySize;
                PrivateRsa.FromPkcs8PrivateString(privateKey, out var priRsap);

                if (string.IsNullOrEmpty(publicKey))
                {
                    PublicRsa = RSA.Create();
                    PublicRsa.KeySize = keySize;
                    var pubRsap = new RSAParameters
                    {
                        Modulus = priRsap.Modulus,
                        Exponent = priRsap.Exponent
                    };
                    PublicRsa.ImportParameters(pubRsap);
                }
            }

            if (!string.IsNullOrEmpty(publicKey))
            {
                PublicRsa = RSA.Create();
                PublicRsa.KeySize = keySize;
                PublicRsa.FromPkcs8PublicString(publicKey, out _);
            }

            DataEncoding = dataEncoding ?? Encoding.UTF8;
        }
    }
}