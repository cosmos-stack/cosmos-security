using System;
using System.Collections.Generic;
using System.Text;
using Cosmos.Encryption;

namespace Cosmos.Extensions
{
    public static partial class Extensions
    {
        public static string ToMD4(this string data, Encoding encoding = null) => MD4HashingProvider.Signature(data, encoding);

        public static byte[] ToMD4(this byte[] data) => MD4HashingProvider.SignatureHash(data);
    }
}
