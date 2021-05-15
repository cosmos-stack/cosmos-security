using System.Text;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Factory = Cosmos.Security.Cryptography.Sm2Factory;

// ReSharper disable InconsistentNaming

namespace Cosmos.Security.Cryptography
{
    public static class SM2
    {
        public static Sm2Key GenerateKey(AsymmetricKeyMode mode) => Factory.GenerateKey(mode);

        public static Sm2Key GenerateKey(AsymmetricKeyMode mode, string publicKey, string privateKey) => Factory.GenerateKey(mode, publicKey, privateKey);

        public static Sm2Key GeneratePublicKey() => Factory.GeneratePublicKey();

        public static Sm2Key GeneratePublicKey(ECPoint publicPem) => Factory.GeneratePublicKey(publicPem);

        public static Sm2Key GeneratePublicKey(string publicKey) => Factory.GeneratePublicKey(publicKey);

        public static Sm2Key GeneratePrivateKey() => Factory.GeneratePrivateKey();

        public static Sm2Key GeneratePrivateKey(BigInteger privatePem) => Factory.GeneratePrivateKey(privatePem);

        public static Sm2Key GeneratePrivateKey(string privateKey) => Factory.GeneratePrivateKey(privateKey);

        public static ISM2 Create(Sm2Key key) => Factory.Create(key);

        public static ISM2 CreateWithPublicKey(string key) => Factory.CreateWithPublicKey(key);

        public static ISM2 CreateWithPublicKey(ECPoint key) => Factory.CreateWithPublicKey(key);

        public static ISM2 CreateWithPrivateKey(string key) => Factory.CreateWithPrivateKey(key);

        public static ISM2 CreateWithPrivateKey(BigInteger key) => Factory.CreateWithPrivateKey(key);

        public static ICryptoValue Encrypt(string text, string publicKey, Encoding encoding = null)
        {
            var function = CreateWithPublicKey(publicKey);
            return function.Encrypt(text, encoding);
        }

        public static ICryptoValue Decrypt(string text, string privateKey, Encoding encoding = null)
        {
            var function = CreateWithPrivateKey(privateKey);
            return function.Decrypt(text, encoding);
        }

        public static ISignValue Sign(string text, string privateKey, Encoding encoding = null)
        {
            var function = CreateWithPrivateKey(privateKey);
            return function.Sign(text, encoding);
        }

        public static bool Verify(string text, string signature, string publicKey, Encoding encoding = null)
        {
            var function = CreateWithPublicKey(publicKey);
            return function.Verify(text, signature, encoding);
        }
    }
}