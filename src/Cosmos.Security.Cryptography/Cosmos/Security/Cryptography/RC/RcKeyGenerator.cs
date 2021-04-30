using System.Text;
using Cosmos.Security.Cryptography.Core.Internals;

// ReSharper disable CheckNamespace

namespace Cosmos.Security.Cryptography
{
    public static class RcKeyGenerator
    {
        public static RcKey Generate() => new(RandomStringGenerator.Generate(8));

        public static RcKey Generate(string pwd, Encoding encoding) => new(pwd, encoding);

        public static RcKey Generate(byte[] pwd) => new(pwd);
    }
}