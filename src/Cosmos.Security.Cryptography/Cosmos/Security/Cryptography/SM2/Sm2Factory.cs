// ReSharper disable CheckNamespace

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Cosmos.Security.Cryptography
{
    public static class Sm2Factory
    {
        public static Sm2Key GenerateKey(AsymmetricKeyMode mode) => Sm2KeyGenerator.Generate(mode);

        public static Sm2Key GenerateKey(AsymmetricKeyMode mode, string publicKey, string privateKey) => Sm2KeyGenerator.Generate(mode, publicKey, privateKey);

        public static Sm2Key GeneratePublicKey() => Sm2KeyGenerator.GeneratePublicKey();

        public static Sm2Key GeneratePublicKey(ECPoint publicPem) => Sm2KeyGenerator.GeneratePublicKey(publicPem);

        public static Sm2Key GeneratePublicKey(string publicKey) => Sm2KeyGenerator.GeneratePublicKey(publicKey);

        public static Sm2Key GeneratePrivateKey() => Sm2KeyGenerator.GeneratePrivateKey();

        public static Sm2Key GeneratePrivateKey(BigInteger privatePem) => Sm2KeyGenerator.GeneratePrivateKey(privatePem);

        public static Sm2Key GeneratePrivateKey(string privateKey) => Sm2KeyGenerator.GeneratePrivateKey(privateKey);

        public static ISM2 Create(Sm2Key key) => new Sm2Function(key);

        public static ISM2 CreateWithPublicKey(string key) => new Sm2Function(Sm2KeyGenerator.GeneratePublicKey(key));

        public static ISM2 CreateWithPublicKey(ECPoint key) => new Sm2Function(Sm2KeyGenerator.GeneratePublicKey(key));


        public static ISM2 CreateWithPrivateKey(string key) => new Sm2Function(Sm2KeyGenerator.GeneratePrivateKey(key));


        public static ISM2 CreateWithPrivateKey(BigInteger key) => new Sm2Function(Sm2KeyGenerator.GeneratePrivateKey(key));
    }
}