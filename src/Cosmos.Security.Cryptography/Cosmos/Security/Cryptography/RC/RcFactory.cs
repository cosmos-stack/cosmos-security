using System;
using System.Text;
using Cosmos.Security.Cryptography.Core.Internals;

namespace Cosmos.Security.Cryptography
{
    public static class RcFactory
    {
        public static RcKey GenerateKey(RcTypes type = RcTypes.RC4) => new RcKey(RandomStringGenerator.Generate(8));

        public static RcKey GenerateKey(RcTypes type, string pwd, Encoding encoding) => new RcKey(pwd, encoding);

        public static RcKey GenerateKey(RcTypes type, byte[] pwd) => new RcKey(pwd);

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
                    return new RC4Function(GenerateKey(type, pwd, encoding));

                case RcTypes.RCX:
                    return new RCXFunction(GenerateKey(type, pwd, encoding));

                case RcTypes.RCY:
                    return new RCYFunction(GenerateKey(type, pwd, encoding));

                case RcTypes.ThreeRCX:
                    return new ThreeRCXFunction(GenerateKey(type, pwd, encoding));

                case RcTypes.ThreeRCY:
                    return new ThreeRCYFunction(GenerateKey(type, pwd, encoding));

                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }

        public static IRC Create(RcTypes type, byte[] pwd)
        {
            switch (type)
            {
                case RcTypes.RC4:
                    return new RC4Function(GenerateKey(type, pwd));

                case RcTypes.RCX:
                    return new RCXFunction(GenerateKey(type, pwd));

                case RcTypes.RCY:
                    return new RCYFunction(GenerateKey(type, pwd));

                case RcTypes.ThreeRCX:
                    return new ThreeRCXFunction(GenerateKey(type, pwd));

                case RcTypes.ThreeRCY:
                    return new ThreeRCYFunction(GenerateKey(type, pwd));

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