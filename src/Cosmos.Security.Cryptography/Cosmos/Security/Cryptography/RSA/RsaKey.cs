// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Cryptography
{
    public class RsaKey : IAsymmetricCryptoKey
    {
        internal const string PUBLIC_KEY_START = "-----BEGIN PUBLIC KEY-----";
        internal const string PUBLIC_KEY_END = "-----END PUBLIC KEY-----";

        internal const string PRIVATE_KEY_START = "-----BEGIN PRIVATE KEY-----";
        internal const string PRIVATE_KEY_END = "-----END PRIVATE KEY-----";

        internal const string RSA_PUBLIC_KEY_START = "-----BEGIN RSA PUBLIC KEY-----";
        internal const string RSA_PUBLIC_KEY_END = "-----END RSA PUBLIC KEY-----";

        internal const string RSA_PRIVATE_KEY_START = "-----BEGIN RSA PRIVATE KEY-----";
        internal const string RSA_PRIVATE_KEY_END = "-----END RSA PRIVATE KEY-----";

        internal const string R_N = "\r\n";

        internal RsaKey() { }

        private RsaKey(string publicKey, string privateKey, RsaKeySize size, AsymmetricKeyMode mode)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
            Size = (int) size;
            Mode = mode;
        }

        public AsymmetricKeyMode Mode { get; internal set; }
        
        public RsaKeyFormat Format { get; internal set; }

        public string PublicKey { get; internal set; }

        public string PrivateKey { get; internal set; }

        public string Exponent { get; internal set; }

        public string Modulus { get; internal set; }

        public bool IncludePublicKey() => PublicKey is not null;

        public bool IncludePrivateKey() => PrivateKey is not null;

        public int Size { get; internal set; }

        public IRsaKeyConverter GetRsaKeyConverter() => RsaKeyConverter.GetInstance();

        public static IRsaKeyConverter Converter => RsaKeyConverter.GetInstance();
    }
}