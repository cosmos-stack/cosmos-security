using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Cosmos.Security.Verification.MessageDigest
{
    /// <summary>
    /// Message Digest Hash Function Provider
    /// </summary>
    public static class MdFunctionProvider
    {
        public static IHashValue ComputeHash(byte[] data, MdTypes type = MdTypes.Md5)
        {
            return MdFactory.Create(type).ComputeHash(data);
        }

        public static IHashValue ComputeHash(byte[] data, CancellationToken cancellationToken)
        {
            return MdFactory.Create().ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(byte[] data, MdTypes type, CancellationToken cancellationToken)
        {
            return MdFactory.Create(type).ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(byte[] data, int offset, int count)
        {
            return MdFactory.Create().ComputeHash(data, offset, count);
        }

        public static IHashValue ComputeHash(byte[] data, int offset, int count, CancellationToken cancellationToken)
        {
            return MdFactory.Create().ComputeHash(data, offset, count, cancellationToken);
        }

        public static IHashValue ComputeHash(byte[] data, int offset, int count, MdTypes type, CancellationToken cancellationToken)
        {
            return MdFactory.Create(type).ComputeHash(data, offset, count, cancellationToken);
        }

        public static IHashValue ComputeHash(string data, MdTypes type = MdTypes.Md5)
        {
            return MdFactory.Create(type).ComputeHash(data);
        }

        public static IHashValue ComputeHash(string data, Encoding encoding, MdTypes type = MdTypes.Md5)
        {
            return MdFactory.Create(type).ComputeHash(data, encoding);
        }

        public static IHashValue ComputeHash(string data, CancellationToken cancellationToken)
        {
            return MdFactory.Create().ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(string data, MdTypes type, CancellationToken cancellationToken)
        {
            return MdFactory.Create(type).ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(string data, Encoding encoding, CancellationToken cancellationToken)
        {
            return MdFactory.Create().ComputeHash(data, encoding, cancellationToken);
        }

        public static IHashValue ComputeHash(string data, Encoding encoding, MdTypes type, CancellationToken cancellationToken)
        {
            return MdFactory.Create(type).ComputeHash(data, encoding, cancellationToken);
        }

        public static IHashValue ComputeHash(ArraySegment<byte> data, MdTypes type = MdTypes.Md5)
        {
            return MdFactory.Create(type).ComputeHash(data);
        }

        public static IHashValue ComputeHash(ArraySegment<byte> data, CancellationToken cancellationToken)
        {
            return MdFactory.Create().ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(ArraySegment<byte> data, MdTypes type, CancellationToken cancellationToken)
        {
            return MdFactory.Create(type).ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(Stream data, MdTypes type = MdTypes.Md5)
        {
            return MdFactory.Create(type).ComputeHash(data);
        }

        public static IHashValue ComputeHash(Stream data, CancellationToken cancellationToken)
        {
            return MdFactory.Create().ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(Stream data, MdTypes type, CancellationToken cancellationToken)
        {
            return MdFactory.Create(type).ComputeHash(data, cancellationToken);
        }

        public static Task<IHashValue> ComputeHashAsync(Stream data, MdTypes type = MdTypes.Md5)
        {
            return MdFactory.Create(type).ComputeHashAsync(data);
        }

        public static Task<IHashValue> ComputeHashAsync(Stream data, CancellationToken cancellationToken)
        {
            return MdFactory.Create().ComputeHashAsync(data, cancellationToken);
        }

        public static Task<IHashValue> ComputeHashAsync(Stream data, MdTypes type, CancellationToken cancellationToken)
        {
            return MdFactory.Create(type).ComputeHashAsync(data, cancellationToken);
        }
    }
}