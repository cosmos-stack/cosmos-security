using System;
using System.Text;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Cryptography
{
    public static class RcFactory
    {
        public static RcKey GenerateKey() => RcKeyGenerator.Generate();

        public static RcKey GenerateKey(string pwd, Encoding encoding) => RcKeyGenerator.Generate(pwd, encoding);

        public static RcKey GenerateKey(byte[] pwd) => RcKeyGenerator.Generate(pwd);

        public static IRC Create() => new RC4Function(GenerateKey());

        public static IRC Create(RcTypes type)
        {
            switch (type)
            {
                case RcTypes.RC4:
                    return new RC4Function(GenerateKey());

                case RcTypes.RCX:
                    return new RCXFunction(GenerateKey());

                case RcTypes.RCY:
                    return new RCYFunction(GenerateKey());

                case RcTypes.ThreeRCX:
                    return new ThreeRCXFunction(GenerateKey());

                case RcTypes.ThreeRCY:
                    return new ThreeRCYFunction(GenerateKey());

                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }

        public static IRC Create(RcTypes type, string pwd, Encoding encoding = null)
        {
            switch (type)
            {
                case RcTypes.RC4:
                    return new RC4Function(GenerateKey(pwd, encoding));

                case RcTypes.RCX:
                    return new RCXFunction(GenerateKey(pwd, encoding));

                case RcTypes.RCY:
                    return new RCYFunction(GenerateKey(pwd, encoding));

                case RcTypes.ThreeRCX:
                    return new ThreeRCXFunction(GenerateKey(pwd, encoding));

                case RcTypes.ThreeRCY:
                    return new ThreeRCYFunction(GenerateKey(pwd, encoding));

                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }

        public static IRC Create(RcTypes type, byte[] pwd)
        {
            switch (type)
            {
                case RcTypes.RC4:
                    return new RC4Function(GenerateKey(pwd));

                case RcTypes.RCX:
                    return new RCXFunction(GenerateKey(pwd));

                case RcTypes.RCY:
                    return new RCYFunction(GenerateKey(pwd));

                case RcTypes.ThreeRCX:
                    return new ThreeRCXFunction(GenerateKey(pwd));

                case RcTypes.ThreeRCY:
                    return new ThreeRCYFunction(GenerateKey(pwd));

                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }

        public static IRC Create(RcTypes type, RcKey key)
        {
            switch (type)
            {
                case RcTypes.RC4:
                    return new RC4Function(key);

                case RcTypes.RCX:
                    return new RCXFunction(key);

                case RcTypes.RCY:
                    return new RCYFunction(key);

                case RcTypes.ThreeRCX:
                    return new ThreeRCXFunction(key);

                case RcTypes.ThreeRCY:
                    return new ThreeRCYFunction(key);

                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }
    }
}