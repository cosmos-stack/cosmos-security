using System.Text;
using Cosmos.Security.Cryptography.Core.Internals;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Cryptography
{
    public static class TeaKeyGenerator
    {
        public static TeaKey Generate() => new(RandomStringGenerator.Generate(16));

        public static TeaKey Generate(string pwd, Encoding encoding) => new(pwd, encoding);

        public static TeaKey Generate(byte[] pwd) => new(pwd);
    }
}