using System.Text;
using Factory = Cosmos.Security.Cryptography.DsaFactory;

// ReSharper disable InconsistentNaming

namespace Cosmos.Security.Cryptography
{
    public static class DSA
    {
        public static DsaKey GenerateKey(AsymmetricKeyMode mode, int keySize = 1024) => Factory.GenerateKey(mode, keySize);

        public static DsaKey ReadFromPublicKey(string xmlPublicKey) => Factory.ReadFromPublicKey(xmlPublicKey);

        public static DsaKey ReadFromPrivateKey(string xmlPrivateKey) => Factory.ReadFromPrivateKey(xmlPrivateKey);

        public static IDSA Create() => Factory.Create();

        public static IDSA Create(AsymmetricKeyMode mode) => Factory.Create(mode);

        public static IDSA Create(AsymmetricKeyMode mode, int keySize) => Factory.Create(mode, keySize);

        public static IDSA Create(DsaKey key) => Factory.Create(key);

        public static ISignValue Sign(string text, string privateKey, Encoding encoding = null)
        {
            var key = Factory.ReadFromPrivateKey(privateKey);
            var function = Factory.Create(key);
            return function.Sign(text, encoding);
        }

        public static ISignValue Sign(byte[] buffer, string privateKey)
        {
            var key = Factory.ReadFromPrivateKey(privateKey);
            var function = Factory.Create(key);
            return function.Sign(buffer);
        }

        public static bool Verify(string text, string rgbSignature, string publicKey, Encoding encoding = null)
        {
            var key = Factory.ReadFromPublicKey(publicKey);
            var function = Factory.Create(key);
            return function.Verify(text, rgbSignature, encoding);
        }

        public static bool Verify(byte[] buffer, byte[] rgbSignature, string publicKey)
        {
            var key = Factory.ReadFromPublicKey(publicKey);
            var function = Factory.Create(key);
            return function.Verify(buffer, rgbSignature);
        }
    }
}