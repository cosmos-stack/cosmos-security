using System;
using System.Text;

// ReSharper disable CheckNamespace
namespace Cosmos.Security.Cryptography
{
    public static class DesFactory
    {
        public static DesKey GenerateKey(DesTypes type = DesTypes.DES) => DesKeyGenerator.Generate(type);

        public static DesKey GenerateKey(DesTypes type, string pwd, string iv, Encoding encoding) => DesKeyGenerator.Generate(type, pwd, iv, encoding);

        public static DesKey GenerateKey(DesTypes type, byte[] pwd, byte[] iv) => DesKeyGenerator.Generate(type, pwd, iv);

        public static IDES Create() => new DesFunction();

        public static IDES Create(DesTypes type)
        {
            switch (type)
            {
                case DesTypes.DES:
                    return new DesFunction(GenerateKey());

                case DesTypes.TripleDES128:
                    return new TripleDesFunction(GenerateKey(DesTypes.TripleDES128));

                case DesTypes.TripleDES192:
                    return new TripleDesFunction(GenerateKey(DesTypes.TripleDES192));

                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }

        public static IDES Create(DesTypes type, string pwd, string iv, Encoding encoding = null)
        {
            switch (type)
            {
                case DesTypes.DES:
                    return new DesFunction(GenerateKey(DesTypes.DES, pwd, iv, encoding));

                case DesTypes.TripleDES128:
                    return new TripleDesFunction(GenerateKey(DesTypes.TripleDES128, pwd, iv, encoding));

                case DesTypes.TripleDES192:
                    return new TripleDesFunction(GenerateKey(DesTypes.TripleDES192, pwd, iv, encoding));

                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }

        public static IDES Create(DesTypes type, byte[] pwd, byte[] iv)
        {
            switch (type)
            {
                case DesTypes.DES:
                    return new DesFunction(GenerateKey(DesTypes.DES, pwd, iv));

                case DesTypes.TripleDES128:
                    return new TripleDesFunction(GenerateKey(DesTypes.TripleDES128, pwd, iv));

                case DesTypes.TripleDES192:
                    return new TripleDesFunction(GenerateKey(DesTypes.TripleDES192, pwd, iv));

                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }

        public static IDES Create(DesTypes type, DesKey key)
        {
            switch (type)
            {
                case DesTypes.DES:
                    return new DesFunction(key);

                case DesTypes.TripleDES128:
                    return new TripleDesFunction(key);

                case DesTypes.TripleDES192:
                    return new TripleDesFunction(key);

                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }
    }
}