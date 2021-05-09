// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Cryptography
{
    public class DsaKey : IAsymmetricCryptoKey
    {
        private DsaKey(string publicKey, string privateKey, int size, AsymmetricKeyMode mode)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
            Size = size;
            Mode = mode;
        }

        public AsymmetricKeyMode Mode { get; }

        public string PublicKey { get; }

        public string PrivateKey { get; }

        public bool IncludePublicKey() => PublicKey is not null;

        public bool IncludePrivateKey() => PrivateKey is not null;

        public int Size { get; }

        public static DsaKey Create(string publicKey, string privateKey, int size)
        {
            return new DsaKey(publicKey, privateKey, size, AsymmetricKeyMode.Both);
        }

        public static DsaKey CreateFromPublicKey(string key, int size)
        {
            return new DsaKey(key, null, size, AsymmetricKeyMode.PublicKey);
        }

        public static DsaKey CreateFromPrivateKey(string key, int size)
        {
            return new DsaKey(null, key, size, AsymmetricKeyMode.PrivateKey);
        }
    }
}