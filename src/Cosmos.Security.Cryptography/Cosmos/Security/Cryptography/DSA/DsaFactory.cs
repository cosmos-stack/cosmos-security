// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Cryptography
{
    public static class DsaFactory
    {
        public static DsaKey GenerateKey(AsymmetricKeyMode mode, int keySize = 1024) => DsaKeyGenerator.CreateKey(mode, keySize);

        public static DsaKey ReadFromPublicKey(string xmlPublicKey) => DsaKeyGenerator.FromPublicKeyInXml(xmlPublicKey);

        public static DsaKey ReadFromPrivateKey(string xmlPrivateKey) => DsaKeyGenerator.FromPrivateKeyInXml(xmlPrivateKey);

        public static IDSA Create() => new DsaFunction(GenerateKey(AsymmetricKeyMode.Both));

        public static IDSA Create(AsymmetricKeyMode mode) => new DsaFunction(GenerateKey(mode));

        public static IDSA Create(AsymmetricKeyMode mode, int keySize) => new DsaFunction(GenerateKey(mode, keySize));

        public static IDSA Create(DsaKey key) => new DsaFunction(key);
    }
}