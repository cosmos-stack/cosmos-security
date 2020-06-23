// ReSharper disable once CheckNamespace

namespace Cosmos.Encryption
{
    /// <summary>
    /// Preference of MurmurHash3 hashing algorithm 
    /// Reference to:
    ///     https://github.com/darrenkopp/murmurhash-net/blob/master/MurmurHash/MurmurHash.cs
    ///     Author: Darren Kopp
    ///     Apache License 2.0
    /// </summary>
    public enum MurmurHash3Preference
    {
        /// <summary>
        /// Auto
        /// </summary>
        // ReSharper disable once InconsistentNaming
        AUTO,

        /// <summary>
        /// x64
        /// </summary>
        X64,

        /// <summary>
        /// x86
        /// </summary>
        X86
    }
}