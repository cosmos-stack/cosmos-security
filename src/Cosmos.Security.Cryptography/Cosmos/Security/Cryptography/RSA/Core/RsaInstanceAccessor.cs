#if NET451 || NET452
using System;
using System.Security.Cryptography;
using MsRSA = System.Security.Cryptography.RSACryptoServiceProvider;
#else
using System;
using MsRSA = System.Security.Cryptography.RSA;
#endif
using Cosmos.Text;

// ReSharper disable InconsistentNaming
// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Cryptography
{
    internal static class RsaInstanceAccessor
    {
#if NET451 || NET452
        private static readonly Func<MsRSA> NewMsRSA = () => new MsRSA();
#else
        private static readonly Func<MsRSA> NewMsRSA = MsRSA.Create;
#endif

        /// <summary>
        /// Create a new instance of <see cref="MsRSA"/> from xml key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static MsRSA NewAndInitWithKeyInXml(string key)
        {
            key.CheckBlank(nameof(key));

            var rsa = NewMsRSA();

            rsa.ImportKeyInLvccXml(key);

            return rsa;
        }


        /// <summary>
        /// Create a new instance of <see cref="MsRSA"/> from json key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static MsRSA NewAndInitWithKeyInJson(string key)
        {
            key.CheckBlank(nameof(key));

            var rsa = NewMsRSA();

            rsa.ImportKeyInJson(key);

            return rsa;
        }

        /// <summary>
        /// Create a new instance of <see cref="MsRSA"/> from Pkcs1 public key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static MsRSA NewAndInitWithPublicKeyInPkcs1(string key)
        {
            key.CheckBlank(nameof(key));

            var rsa = NewMsRSA();

            rsa.TouchFromPublicKeyInPkcs1(key, out _);

            return rsa;
        }

        /// <summary>
        /// Create a new instance of <see cref="MsRSA"/> from Pkcs1 private key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static MsRSA NewAndInitWithPrivateKeyInPkcs1(string key)
        {
            key.CheckBlank(nameof(key));

            var rsa = NewMsRSA();

            rsa.TouchFromPrivateKeyInPkcs1(key, out _);

            return rsa;
        }

        /// <summary>
        /// Create a new instance of <see cref="MsRSA"/> from Pkcs8 public key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static MsRSA NewAndInitWithPublicKeyInPkcs8(string key)
        {
            key.CheckBlank(nameof(key));

            var rsa = NewMsRSA();

            rsa.TouchFromPublicKeyInPkcs8(key, out _);

            return rsa;
        }

        /// <summary>
        /// Create a new instance of <see cref="MsRSA"/> from Pkcs8 private key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static MsRSA NewAndInitWithPrivateKeyInPkcs8(string key)
        {
            key.CheckBlank(nameof(key));

            var rsa = NewMsRSA();

            rsa.TouchFromPrivateKeyInPkcs8(key, out _);

            return rsa;
        }
    }
}