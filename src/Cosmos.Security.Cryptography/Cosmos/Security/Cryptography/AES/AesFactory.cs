using System.Text;

// ReSharper disable CheckNamespace
namespace Cosmos.Security.Cryptography
{
    public static class AesFactory
    {
        public static AesKey GenerateKey(AesTypes type = AesTypes.Aes256) => AesKeyGenerator.Generate(type);

        public static AesKey GenerateKey(AesTypes type, string pwd, string iv, Encoding encoding) => AesKeyGenerator.Generate(type, pwd, iv, encoding);

        public static AesKey GenerateKey(AesTypes type, byte[] pwd, byte[] iv) => AesKeyGenerator.Generate(type, pwd, iv);

        public static IAES Create() => new AesFunction();

        public static IAES Create(AesTypes type) => new AesFunction(GenerateKey(type));

        public static IAES Create(AesTypes type, string pwd, string iv, Encoding encoding = null) => new AesFunction(GenerateKey(type, pwd, iv, encoding));

        public static IAES Create(AesTypes type, byte[] pwd, byte[] iv) => new AesFunction(GenerateKey(type, pwd, iv));

        public static IAES Create(AesTypes type, AesKey key) => new AesFunction(key);
    }
}