using System;
using System.Text;

// ReSharper disable CheckNamespace

namespace Cosmos.Security.Cryptography
{
    public static class TeaFactory
    {
        public static TeaKey GenerateKey() => TeaKeyGenerator.Generate();

        public static TeaKey GenerateKey(string pwd, Encoding encoding) => TeaKeyGenerator.Generate(pwd, encoding);

        public static TeaKey GenerateKey(byte[] pwd) => TeaKeyGenerator.Generate(pwd);

        public static ITEA Create() => new TEAFunction(GenerateKey());

        public static ITEA Create(TeaTypes type)
        {
            switch (type)
            {
                case TeaTypes.TEA:
                    return new TEAFunction(GenerateKey());

                case TeaTypes.XTEA:
                    return new XTEAFunction(GenerateKey());

                case TeaTypes.XXTEA:
                    return new XXTEAFunction(GenerateKey());

                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }

        public static ITEA Create(TeaTypes type, string pwd, Encoding encoding = null)
        {
            switch (type)
            {
                case TeaTypes.TEA:
                    return new TEAFunction(GenerateKey(pwd, encoding));

                case TeaTypes.XTEA:
                    return new XTEAFunction(GenerateKey(pwd, encoding));

                case TeaTypes.XXTEA:
                    return new XXTEAFunction(GenerateKey(pwd, encoding));

                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }

        public static ITEA Create(TeaTypes type, byte[] pwd)
        {
            switch (type)
            {
                case TeaTypes.TEA:
                    return new TEAFunction(GenerateKey(pwd));

                case TeaTypes.XTEA:
                    return new XTEAFunction(GenerateKey(pwd));

                case TeaTypes.XXTEA:
                    return new XXTEAFunction(GenerateKey(pwd));

                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }

        public static ITEA Create(TeaTypes type, TeaKey key)
        {
            switch (type)
            {
                case TeaTypes.TEA:
                    return new TEAFunction(key);

                case TeaTypes.XTEA:
                    return new XTEAFunction(key);

                case TeaTypes.XXTEA:
                    return new XXTEAFunction(key);

                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }
    }
}