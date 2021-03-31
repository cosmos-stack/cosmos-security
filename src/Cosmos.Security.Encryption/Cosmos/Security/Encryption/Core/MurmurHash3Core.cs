using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Cosmos.Security.Encryption.Core
{
    /// <summary>
    /// MurmurHash3 core services
    /// Reference to:
    ///     https://github.com/darrenkopp/murmurhash-net/blob/master/MurmurHash/MurmurHash.cs
    ///     Author: Darren Kopp
    ///     Apache License 2.0
    /// </summary>
    internal static partial class MurmurHash3Core
    {
        /// <summary>
        /// Create MurmurHash3 32
        /// </summary>
        /// <param name="seed"></param>
        /// <param name="managed"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        internal static MurmurHash3L32 CreateL32(uint seed, MurmurHash3Managed managed)
        {
            switch (managed)
            {
                case MurmurHash3Managed.TRUE:
                    return new MurmurHash3L32ManagedX86(seed);

                case MurmurHash3Managed.FALSE:
                    return new MurmurHash3L32UnmanagedX86(seed);

                default:
                    throw new InvalidOperationException("Unknown MurmurHash3 L32 managed mode");
            }
        }

        /// <summary>
        /// Create MurmurHash3 128
        /// </summary>
        /// <param name="seed"></param>
        /// <param name="managed"></param>
        /// <param name="preference"></param>
        /// <returns></returns>
        [SuppressMessage("ReSharper", "InconsistentNaming")]
        internal static MurmurHash3L128 CreateL128(uint seed, MurmurHash3Managed managed, MurmurHash3Preference preference)
        {
            var algorithm = managed switch
            {
                MurmurHash3Managed.TRUE  => __pick(s => new MurmurHash3L128ManagedX86(s), s => new MurmurHash3L128ManagedX64(s)),
                MurmurHash3Managed.FALSE => __pick(s => new MurmurHash3L128UnmanagedX86(s), s => new MurmurHash3L128UnmanagedX64(s)),
                _                        => throw new InvalidOperationException("Unknown managed type.")
            };

            return algorithm as MurmurHash3L128;

            HashAlgorithm __pick<T32, T64>(Func<uint, T32> __factory32, Func<uint, T64> __factory64)
            where T32 : HashAlgorithm where T64 : HashAlgorithm
            {
                switch (preference)
                {
                    case MurmurHash3Preference.X64:
                        return __factory64(seed);

                    case MurmurHash3Preference.X86:
                        return __factory32(seed);

                    default:
                        if (__is64BitProcess())
                            return __factory64(seed);
                        return __factory32(seed);
                }
            }

            bool __is64BitProcess()
            {
#if NET451
                return Environment.Is64BitProcess;
#elif NET40 ||NET35
                return IntPtr.Size == 8;
#else
                return false;
#endif
            }
        }
    }
}