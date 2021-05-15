using System;
using System.Text;
using Cosmos.Conversions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

// ReSharper disable CheckNamespace

namespace Cosmos.Security.Cryptography
{
    public class Sm2Key : IAsymmetricCryptoKey
    {
        /// <summary>
        /// SM2 algorithm default user ID, currently open platform will not use non-default user ID
        /// </summary>
        private const string DefaultUserId = "1234567812345678";

        internal Sm2Key() { }

        internal Sm2Key(ECPoint publicKey, BigInteger privateKey)
        {
            PublicKey = BaseConv.ToBase64(publicKey.GetEncoded()); //Hex.Encode(publicKey.GetEncoded()).GetString(encoding.SafeEncodingValue()).ToUpper();
            PrivateKey = BaseConv.ToBase64(privateKey.ToByteArray()); //Hex.Encode(privateKey.ToByteArray()).GetString(encoding.SafeEncodingValue()).ToUpper();
        }

        internal Sm2Key(string publicKey, string privateKey, AsymmetricKeyMode mode)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
            Mode = mode;
        }

        public AsymmetricKeyMode Mode { get; internal set; }

        public string PublicKey { get; internal set; }

        public string PrivateKey { get; internal set; }

        public bool IncludePublicKey() => PublicKey is not null;

        public bool IncludePrivateKey() => PrivateKey is not null;

        public int Size => 512; //32 * 16

        internal ParametersWithID GetPublicKey()
        {
            var key = PublicKeyFactory.CreateKey(Convert.FromBase64String(PublicKey));
            var parametersWithId = new ParametersWithID(key, Encoding.UTF8.GetBytes(DefaultUserId));
            return parametersWithId;
        }

        internal ParametersWithID GetPrivateKey()
        {
            var key = PrivateKeyFactory.CreateKey(Convert.FromBase64String(PrivateKey));
            var parametersWithId = new ParametersWithID(key, Encoding.UTF8.GetBytes(DefaultUserId));
            return parametersWithId;
        }
    }
}