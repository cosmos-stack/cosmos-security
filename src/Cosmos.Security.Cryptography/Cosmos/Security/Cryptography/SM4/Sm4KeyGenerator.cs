using Org.BouncyCastle.Security;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Cryptography
{
    public static class Sm4KeyGenerator
    {
        public static Sm4Key Generate(Sm4Types type = Sm4Types.ECB)
        {
            return Generate(type, 16);
        }

        public static Sm4Key Generate(Sm4Types type, int length)
        {
            if (length <= 0) length = 16;
            var pwd = MakeBytes(length);
            var iv = type switch
            {
                Sm4Types.ECB => new byte[0],
                Sm4Types.CBC => MakeBytes(length),
                _ => new byte[0],
            };

            return new Sm4Key(pwd, iv);
        }

        private static byte[] MakeBytes(int length)
        {
            var rnd = new SecureRandom();
            var output = new byte[length];
            for (var i = 0; i < length; i++) output[i] = (byte) (rnd.Next() % 256);
            return output;
        }
    }
}