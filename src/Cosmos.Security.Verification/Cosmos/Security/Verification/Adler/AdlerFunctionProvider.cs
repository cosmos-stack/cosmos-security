using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Cosmos.Security.Verification.Adler
{
    public static class AdlerFunctionProvider
    {
        public static IHashValue ComputeHash(byte[] data, AdlerTypes type = AdlerTypes.Adler32)
        {
            return AdlerFactory.Create(type).ComputeHash(data);
        }

        public static IHashValue ComputeHash(byte[] data, CancellationToken cancellationToken)
        {
            return AdlerFactory.Create().ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(byte[] data, AdlerTypes type, CancellationToken cancellationToken)
        {
            return AdlerFactory.Create(type).ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(byte[] data, int offset, int count)
        {
            return AdlerFactory.Create().ComputeHash(data, offset, count);
        }

        public static IHashValue ComputeHash(byte[] data, int offset, int count, CancellationToken cancellationToken)
        {
            return AdlerFactory.Create().ComputeHash(data, offset, count, cancellationToken);
        }

        public static IHashValue ComputeHash(byte[] data, int offset, int count, AdlerTypes type, CancellationToken cancellationToken)
        {
            return AdlerFactory.Create(type).ComputeHash(data, offset, count, cancellationToken);
        }

        public static IHashValue ComputeHash(string data, AdlerTypes type = AdlerTypes.Adler32)
        {
            return AdlerFactory.Create(type).ComputeHash(data);
        }

        public static IHashValue ComputeHash(string data, Encoding encoding, AdlerTypes type = AdlerTypes.Adler32)
        {
            return AdlerFactory.Create(type).ComputeHash(data, encoding);
        }

        public static IHashValue ComputeHash(string data, CancellationToken cancellationToken)
        {
            return AdlerFactory.Create().ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(string data, AdlerTypes type, CancellationToken cancellationToken)
        {
            return AdlerFactory.Create(type).ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(string data, Encoding encoding, CancellationToken cancellationToken)
        {
            return AdlerFactory.Create().ComputeHash(data, encoding, cancellationToken);
        }

        public static IHashValue ComputeHash(string data, Encoding encoding, AdlerTypes type, CancellationToken cancellationToken)
        {
            return AdlerFactory.Create(type).ComputeHash(data, encoding, cancellationToken);
        }

        public static IHashValue ComputeHash(ArraySegment<byte> data, AdlerTypes type = AdlerTypes.Adler32)
        {
            return AdlerFactory.Create(type).ComputeHash(data);
        }

        public static IHashValue ComputeHash(ArraySegment<byte> data, CancellationToken cancellationToken)
        {
            return AdlerFactory.Create().ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(ArraySegment<byte> data, AdlerTypes type, CancellationToken cancellationToken)
        {
            return AdlerFactory.Create(type).ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(Stream data, AdlerTypes type = AdlerTypes.Adler32)
        {
            return AdlerFactory.Create(type).ComputeHash(data);
        }

        public static IHashValue ComputeHash(Stream data, CancellationToken cancellationToken)
        {
            return AdlerFactory.Create().ComputeHash(data, cancellationToken);
        }

        public static IHashValue ComputeHash(Stream data, AdlerTypes type, CancellationToken cancellationToken)
        {
            return AdlerFactory.Create(type).ComputeHash(data, cancellationToken);
        }

        public static Task<IHashValue> ComputeHashAsync(Stream data, AdlerTypes type = AdlerTypes.Adler32)
        {
            return AdlerFactory.Create(type).ComputeHashAsync(data);
        }

        public static Task<IHashValue> ComputeHashAsync(Stream data, CancellationToken cancellationToken)
        {
            return AdlerFactory.Create().ComputeHashAsync(data, cancellationToken);
        }

        public static Task<IHashValue> ComputeHashAsync(Stream data, AdlerTypes type, CancellationToken cancellationToken)
        {
            return AdlerFactory.Create(type).ComputeHashAsync(data, cancellationToken);
        }
    }
}