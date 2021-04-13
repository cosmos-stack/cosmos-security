using System.Text;
using Cosmos.Optionals;

// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Verification
{
    public static class HmacFactory
    {
        public static HmacFunction Create(HmacTypes type, byte[] key) => new(type, key);

        public static HmacFunction Create(HmacTypes type, string key, Encoding encoding = null) => new(type, encoding.SafeEncodingValue().GetBytes(key));
    }
}