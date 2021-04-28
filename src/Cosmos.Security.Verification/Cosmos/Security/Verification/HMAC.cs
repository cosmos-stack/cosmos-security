using System.Text;
using Factory = Cosmos.Security.Verification.HmacFactory;

// ReSharper disable InconsistentNaming

namespace Cosmos.Security.Verification
{
    public static class HMAC
    {
        public static IHMAC Create(HmacTypes type, byte[] key) => Factory.Create(type, key);

        public static IHMAC Create(HmacTypes type, string key, Encoding encoding = null) => Factory.Create(type, key, encoding);
    }
}