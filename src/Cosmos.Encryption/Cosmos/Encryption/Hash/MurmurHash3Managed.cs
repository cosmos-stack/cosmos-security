using System.Diagnostics.CodeAnalysis;

// ReSharper disable once CheckNamespace
namespace Cosmos.Encryption {
    /// <summary>
    /// MurmurHash3 managed
    /// Reference to:
    ///     https://github.com/darrenkopp/murmurhash-net/blob/master/MurmurHash/MurmurHash.cs
    ///     Author: Darren Kopp
    ///     Apache License 2.0
    /// </summary>
    [SuppressMessage("ReSharper", "UnusedMember.Global")]
    public enum MurmurHash3Managed {
        /// <summary>
        /// Managed mode
        /// </summary>
        TRUE,

        /// <summary>
        /// Unmanaged mode
        /// </summary>
        FALSE,
    }
}