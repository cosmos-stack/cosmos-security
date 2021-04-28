using System.Text;
using Cosmos.Optionals;

// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Verification
{
    public static class HmacFactory
    {
        public static IHMAC Create(HmacTypes type, byte[] key) => new HmacFunction(type, key);

        public static IHMAC Create(HmacTypes type, string key, Encoding encoding = null) => new HmacFunction(type, encoding.SafeEncodingValue().GetBytes(key));
    }
}