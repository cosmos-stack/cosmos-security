using System;
using System.Security.Cryptography;
using System.Text;
using Cosmos.Optionals;

namespace Cosmos.Security.Cryptography.Core.SymmetricAlgorithmImpls
{
    internal static class SymmetricKeyHelper
    {
        public static byte[] ComputeRealValue(byte[] originalBytes, byte[] saltBytes, int size)
        {
            if (originalBytes.Length == 0)
                return new byte[0];

            var len = size / 8;

            if (saltBytes is null || saltBytes.Length == 0)
            {
                var encoding = Encoding.UTF8;
                var retBytes = new byte[len];
                Array.Copy(encoding.GetBytes(encoding.GetString(originalBytes).PadRight(len)), retBytes, len);
                return retBytes;
            }

            var rfcOriginStringData = new Rfc2898DeriveBytes(originalBytes, saltBytes, 1000);
            return rfcOriginStringData.GetBytes(len);
        }

        public static byte[] ComputeRealValue(string originalString, byte[] saltBytes, Encoding encoding, int size)
        {
            if (string.IsNullOrWhiteSpace(originalString))
                return new byte[0];

            encoding = encoding.SafeEncodingValue();

            var len = size / 8;

            if (saltBytes is null || saltBytes.Length == 0)
            {
                var retBytes = new byte[len];
                Array.Copy(encoding.GetBytes(originalString.PadRight(len)), retBytes, len);
                return retBytes;
            }

            var rfcOriginStringData = new Rfc2898DeriveBytes(encoding.GetBytes(originalString), saltBytes, 1000);
            return rfcOriginStringData.GetBytes(len);
        }
    }
}