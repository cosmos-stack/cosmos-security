using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Cosmos.Security.Verification.CRC
{
    /// <summary>
    /// CRC Hash Function Provider
    /// </summary>
    public static class CrcFunctionProvider
    {
        public static IHashValue ComputeHash(byte[] data, CrcTypes type = CrcTypes.Crc32)
        {
            return CrcFactory.Create(type).ComputeHash(data);
        }

        public static IHashValue ComputeHash(byte[] data, CancellationToken cancellationToken)
        {
            return CrcFactory.Create().ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(byte[] data, CrcTypes type, CancellationToken cancellationToken)
        {
            return CrcFactory.Create(type).ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(byte[] data, int offset, int count)
        {
            return CrcFactory.Create().ComputeHash(data, offset, count);
        }

        public static IHashValue ComputeHash(byte[] data, int offset, int count, CancellationToken cancellationToken)
        {
            return CrcFactory.Create().ComputeHash(data, offset, count, cancellationToken);
        }

        public static IHashValue ComputeHash(byte[] data, int offset, int count, CrcTypes type, CancellationToken cancellationToken)
        {
            return CrcFactory.Create(type).ComputeHash(data, offset, count, cancellationToken);
        }

        public static IHashValue ComputeHash(string data, CrcTypes type = CrcTypes.Crc32)
        {
            return CrcFactory.Create(type).ComputeHash(data);
        }

        public static IHashValue ComputeHash(string data, Encoding encoding, CrcTypes type = CrcTypes.Crc32)
        {
            return CrcFactory.Create(type).ComputeHash(data, encoding);
        }

        public static IHashValue ComputeHash(string data, CancellationToken cancellationToken)
        {
            return CrcFactory.Create().ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(string data, CrcTypes type, CancellationToken cancellationToken)
        {
            return CrcFactory.Create(type).ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(string data, Encoding encoding, CancellationToken cancellationToken)
        {
            return CrcFactory.Create().ComputeHash(data, encoding, cancellationToken);
        }

        public static IHashValue ComputeHash(string data, Encoding encoding, CrcTypes type, CancellationToken cancellationToken)
        {
            return CrcFactory.Create(type).ComputeHash(data, encoding, cancellationToken);
        }

        public static IHashValue ComputeHash(ArraySegment<byte> data, CrcTypes type = CrcTypes.Crc32)
        {
            return CrcFactory.Create(type).ComputeHash(data);
        }

        public static IHashValue ComputeHash(ArraySegment<byte> data, CancellationToken cancellationToken)
        {
            return CrcFactory.Create().ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(ArraySegment<byte> data, CrcTypes type, CancellationToken cancellationToken)
        {
            return CrcFactory.Create(type).ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(Stream data, CrcTypes type = CrcTypes.Crc32)
        {
            return CrcFactory.Create(type).ComputeHash(data);
        }

        public static IHashValue ComputeHash(Stream data, CancellationToken cancellationToken)
        {
            return CrcFactory.Create().ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(Stream data, CrcTypes type, CancellationToken cancellationToken)
        {
            return CrcFactory.Create(type).ComputeHash(data, cancellationToken);
        }

        public static Task<IHashValue> ComputeHashAsync(Stream data, CrcTypes type = CrcTypes.Crc32)
        {
            return CrcFactory.Create(type).ComputeHashAsync(data);
        }

        public static Task<IHashValue> ComputeHashAsync(Stream data, CancellationToken cancellationToken)
        {
            return CrcFactory.Create().ComputeHashAsync(data, cancellationToken);
        }

        public static Task<IHashValue> ComputeHashAsync(Stream data, CrcTypes type, CancellationToken cancellationToken)
        {
            return CrcFactory.Create(type).ComputeHashAsync(data, cancellationToken);
        }
    }
}