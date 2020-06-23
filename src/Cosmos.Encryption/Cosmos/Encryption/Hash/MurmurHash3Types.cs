using System.Diagnostics.CodeAnalysis;

// ReSharper disable once CheckNamespace
namespace Cosmos.Encryption
{
    /// <summary>
    /// The type of MurmurHash3 hashing algorithm
    /// Reference to:
    ///     https://github.com/darrenkopp/murmurhash-net/blob/master/MurmurHash/MurmurHash.cs
    ///     Author: Darren Kopp
    ///     Apache License 2.0
    /// </summary>
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    public enum MurmurHash3Types
    {
        /// <summary>
        /// Fast mode
        /// </summary>
        FAST,

        /// <summary>
        /// Murmur32 mode
        /// </summary>
        L_32,

        /// <summary>
        /// Murmur128 mode
        /// </summary>
        L_128
    }
}