using System;
using System.IO;
using System.Text;
using Cosmos.Security.Encryption.Core;
using Cosmos.Optionals;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Encryption
{
    /// <summary>
    /// MurmurHash3 hashing provider
    /// Reference to:
    ///     https://github.com/odinmillion/MurmurHash.Net/blob/master/src/MurmurHash.Net/MurmurHash3.cs
    ///
    /// Reference to:
    ///     https://github.com/darrenkopp/murmurhash-net/blob/master/MurmurHash/MurmurHash.cs
    ///     Author: Darren Kopp
    ///     Apache License 2.0
    /// </summary>
    public static class MurmurHash3Provider
    {
        /// <summary>
        /// Signature
        /// </summary>
        /// <param name="data"></param>
        /// <param name="seed"></param>
        /// <param name="encoding"></param>
        /// <param name="types"></param>
        /// <param name="preference"></param>
        /// <param name="managed"></param>
        /// <returns></returns>
        public static uint Signature(string data, uint seed, Encoding encoding = null,
            MurmurHash3Types types = MurmurHash3Types.FAST,
            MurmurHash3Preference preference = MurmurHash3Preference.AUTO,
            MurmurHash3Managed managed = MurmurHash3Managed.TRUE)
        {
            Checker.Data(data);

            var bytes = encoding.SafeEncodingValue().GetBytes(data);

            return SignatureCore(bytes, seed, types, preference, managed);
        }

        /// <summary>
        /// Signature
        /// </summary>
        /// <param name="data"></param>
        /// <param name="seed"></param>
        /// <param name="types"></param>
        /// <param name="preference"></param>
        /// <param name="managed"></param>
        /// <returns></returns>
        public static uint Signature(byte[] data, uint seed,
            MurmurHash3Types types = MurmurHash3Types.FAST,
            MurmurHash3Preference preference = MurmurHash3Preference.AUTO,
            MurmurHash3Managed managed = MurmurHash3Managed.TRUE)
        {
            Checker.Buffer(data);
            return SignatureCore(data, seed, types, preference, managed);
        }

        /// <summary>
        /// Signature hash
        /// </summary>
        /// <param name="data"></param>
        /// <param name="seed"></param>
        /// <param name="encoding"></param>
        /// <param name="types"></param>
        /// <param name="preference"></param>
        /// <param name="managed"></param>
        /// <returns></returns>
        public static byte[] SignatureHash(string data, uint seed, Encoding encoding = null,
            MurmurHash3Types types = MurmurHash3Types.FAST,
            MurmurHash3Preference preference = MurmurHash3Preference.AUTO,
            MurmurHash3Managed managed = MurmurHash3Managed.TRUE)
        {
            return BitConverter.GetBytes(Signature(data, seed, encoding, types, preference, managed));
        }

        /// <summary>
        /// Signature hash
        /// </summary>
        /// <param name="data"></param>
        /// <param name="seed"></param>
        /// <param name="types"></param>
        /// <param name="preference"></param>
        /// <param name="managed"></param>
        /// <returns></returns>
        public static byte[] SignatureHash(byte[] data, uint seed,
            MurmurHash3Types types = MurmurHash3Types.FAST,
            MurmurHash3Preference preference = MurmurHash3Preference.AUTO,
            MurmurHash3Managed managed = MurmurHash3Managed.TRUE)
        {
            return BitConverter.GetBytes(Signature(data, seed, types, preference, managed));
        }

        private static uint SignatureCore(byte[] data, uint seed, MurmurHash3Types types, MurmurHash3Preference preference, MurmurHash3Managed managed)
        {
            switch (types)
            {
                case MurmurHash3Types.FAST:
                {
                    return MurmurHash3Core.FastMode.Hash32(data.AsSpan(), seed);
                }

                case MurmurHash3Types.L_32:
                {
                    var l32 = MurmurHash3Core.CreateL32(seed, managed);
                    var h32 = l32.ComputeHash(data);
                    return BitConverter.ToUInt32(h32, 0);
                }

                case MurmurHash3Types.L_128:
                {
                    var l128 = MurmurHash3Core.CreateL128(seed, managed, preference);
                    var h128 = l128.ComputeHash(data);
                    return BitConverter.ToUInt32(h128, 0);
                }

                default:
                    throw new NotImplementedException("Unknown type for MurmurHash3 hash provider.");
            }
        }

        /// <summary>
        /// Create a new instance of <see cref="MurmurHash3InputStream"/>.
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="seed"></param>
        /// <param name="managed"></param>
        /// <param name="types"></param>
        /// <param name="preference"></param>
        /// <returns></returns>
        public static MurmurHash3InputStream CreateInputStream(Stream stream, uint seed = 0,
            MurmurHash3Managed managed = MurmurHash3Managed.TRUE,
            MurmurHash3Types types = MurmurHash3Types.L_128,
            MurmurHash3Preference preference = MurmurHash3Preference.AUTO)
            => new MurmurHash3InputStream(stream, seed, managed, types, preference);

        /// <summary>
        /// Create a new instance of <see cref="MurmurHash3OutputStream"/>.
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="seed"></param>
        /// <param name="managed"></param>
        /// <param name="types"></param>
        /// <param name="preference"></param>
        /// <returns></returns>
        public static MurmurHash3OutputStream CreateOutputStream(Stream stream, uint seed = 0,
            MurmurHash3Managed managed = MurmurHash3Managed.TRUE,
            MurmurHash3Types types = MurmurHash3Types.L_128,
            MurmurHash3Preference preference = MurmurHash3Preference.AUTO)
            => new MurmurHash3OutputStream(stream, seed, managed, types, preference);

        /// <summary>
        /// Verify
        /// </summary>
        /// <param name="comparison"></param>
        /// <param name="data"></param>
        /// <param name="seed"></param>
        /// <param name="encoding"></param>
        /// <param name="types"></param>
        /// <param name="preference"></param>
        /// <param name="managed"></param>
        /// <returns></returns>
        public static bool Verify(uint comparison, string data, uint seed, Encoding encoding = null,
            MurmurHash3Types types = MurmurHash3Types.FAST,
            MurmurHash3Preference preference = MurmurHash3Preference.AUTO,
            MurmurHash3Managed managed = MurmurHash3Managed.TRUE)
            => comparison == Signature(data, seed, encoding, types, preference, managed);

        /// <summary>
        /// Verify
        /// </summary>
        /// <param name="comparison"></param>
        /// <param name="data"></param>
        /// <param name="seed"></param>
        /// <param name="types"></param>
        /// <param name="preference"></param>
        /// <param name="managed"></param>
        /// <returns></returns>
        public static bool Verify(uint comparison, byte[] data, uint seed,
            MurmurHash3Types types = MurmurHash3Types.FAST,
            MurmurHash3Preference preference = MurmurHash3Preference.AUTO,
            MurmurHash3Managed managed = MurmurHash3Managed.TRUE)
            => comparison == Signature(data, seed, types, preference, managed);
    }
}