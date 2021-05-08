using System.Text;
using Factory = Cosmos.Security.Cryptography.TeaFactory;

// ReSharper disable InconsistentNaming

namespace Cosmos.Security.Cryptography
{
    public static class TEA
    {
        public static TeaKey GenerateKey() => Factory.GenerateKey();

        public static TeaKey GenerateKey(string pwd, Encoding encoding) => Factory.GenerateKey(pwd, encoding);

        public static TeaKey GenerateKey(byte[] pwd) => Factory.GenerateKey(pwd);

        public static ITEA Create() => Factory.Create();

        public static ITEA Create(TeaTypes type) => Factory.Create(type);

        public static ITEA Create(TeaTypes type, string pwd, Encoding encoding = null) => Factory.Create(type, pwd, encoding);

        public static ITEA Create(TeaTypes type, byte[] pwd) => Factory.Create(type, pwd);

        public static ITEA Create(TeaTypes type, TeaKey key) => Factory.Create(type, key);
    }
}