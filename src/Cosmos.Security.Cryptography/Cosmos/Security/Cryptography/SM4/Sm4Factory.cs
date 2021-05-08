using System.Text;

namespace Cosmos.Security.Cryptography
{
    public static class Sm4Factory
    {
        public static Sm4Key GenerateKey(Sm4Types type = Sm4Types.ECB) => Sm4KeyGenerator.Generate(type);

        public static Sm4Key GenerateKey(Sm4Types type, int length) => Sm4KeyGenerator.Generate(type, length);

        public static Sm4Key GenerateKey(string pwd, Encoding encoding = null) => new Sm4Key(pwd, encoding);

        public static Sm4Key GenerateKey(string pwd, string iv, Encoding encoding = null) => new Sm4Key(pwd, iv, encoding);

        public static Sm4Key GenerateKey(byte[] pwd) => new Sm4Key(pwd);

        public static Sm4Key GenerateKey(byte[] pwd, byte[] iv) => new Sm4Key(pwd, iv);

        public static ISM4 Create(Sm4Types type = Sm4Types.ECB)
        {
            return type switch
            {
                Sm4Types.ECB => new SM4ECBFunction(GenerateKey(type)),
                Sm4Types.CBC => new SM4CBCFunction(GenerateKey(type)),
                _ => new SM4ECBFunction(GenerateKey(type))
            };
        }

        public static ISM4 Create(Sm4Types type, string pwd, Encoding encoding = null)
        {
            return type switch
            {
                Sm4Types.ECB => new SM4ECBFunction(GenerateKey(pwd, encoding)),
                Sm4Types.CBC => new SM4CBCFunction(GenerateKey(pwd, encoding)),
                _ => new SM4ECBFunction(GenerateKey(pwd, encoding))
            };
        }

        public static ISM4 Create(Sm4Types type, string pwd, string iv, Encoding encoding = null)
        {
            return type switch
            {
                Sm4Types.ECB => new SM4ECBFunction(GenerateKey(pwd, encoding)),
                Sm4Types.CBC => new SM4CBCFunction(GenerateKey(pwd, iv, encoding)),
                _ => new SM4ECBFunction(GenerateKey(pwd, encoding))
            };
        }

        public static ISM4 Create(Sm4Types type, byte[] pwd)
        {
            return type switch
            {
                Sm4Types.ECB => new SM4ECBFunction(GenerateKey(pwd)),
                Sm4Types.CBC => new SM4CBCFunction(GenerateKey(pwd)),
                _ => new SM4ECBFunction(GenerateKey(pwd))
            };
        }

        public static ISM4 Create(Sm4Types type, byte[] pwd, byte[] iv)
        {
            return type switch
            {
                Sm4Types.ECB => new SM4ECBFunction(GenerateKey(pwd)),
                Sm4Types.CBC => new SM4CBCFunction(GenerateKey(pwd, iv)),
                _ => new SM4ECBFunction(GenerateKey(pwd))
            };
        }

        public static ISM4 Create(Sm4Types type, Sm4Key key)
        {
            return type switch
            {
                Sm4Types.ECB => new SM4ECBFunction(key),
                Sm4Types.CBC => new SM4CBCFunction(key),
                _ => new SM4ECBFunction(key)
            };
        }
    }
}