using System;
using System.IO;
using System.Security.Cryptography;
using Cosmos.Encryption.Core;

// ReSharper disable once CheckNamespace
namespace Cosmos.Encryption {
    /// <summary>
    /// MurmurHash3 output stream
    /// Reference to:
    ///     https://github.com/darrenkopp/murmurhash-net/blob/master/MurmurHash/MurmurHash.cs
    ///     Author: Darren Kopp
    ///     Apache License 2.0
    /// </summary>
    public class MurmurHash3OutputStream : Stream {
        // ReSharper disable once InconsistentNaming
        private static readonly byte[] DEFAULT_FINAL_TRANFORM = new byte[0];
        private readonly Stream _underlyingStream;
        private readonly HashAlgorithm _algorithm;

        /// <inheritdoc />
        public MurmurHash3OutputStream(Stream underlyingStream, uint seed = 0,
            MurmurHash3Managed managed = MurmurHash3Managed.TRUE,
            MurmurHash3Types types = MurmurHash3Types.L_128,
            MurmurHash3Preference preference = MurmurHash3Preference.AUTO) {
            _underlyingStream = underlyingStream;
            _algorithm = types switch {
                MurmurHash3Types.L_32  => (HashAlgorithm) MurmurHash3Core.CreateL32(seed, managed),
                MurmurHash3Types.L_128 => (HashAlgorithm) MurmurHash3Core.CreateL128(seed, managed, preference),
                _                      => throw new InvalidOperationException("Invalid operation because only support L32 and L128")
            };
        }

        /// <summary>
        /// Hash
        /// </summary>
        public byte[] Hash {
            get {
                _algorithm.TransformFinalBlock(DEFAULT_FINAL_TRANFORM, 0, 0);
                return _algorithm.Hash;
            }
        }

        /// <inheritdoc />
        public override bool CanRead => false;

        /// <inheritdoc />
        public override bool CanSeek => false;

        /// <inheritdoc />
        public override bool CanWrite => true;

        /// <inheritdoc />
        public override long Length => _underlyingStream.Length;

        /// <inheritdoc />
        public override long Position {
            get => _underlyingStream.Position;
            set => throw new NotSupportedException();
        }

        /// <inheritdoc />
        public override void Flush() => _underlyingStream.Flush();

        /// <inheritdoc />
        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException("This stream does not support reading.");

        /// <inheritdoc />
        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException("This stream does not support seeking, it is forward-only.");

        /// <inheritdoc />
        public override void SetLength(long value) => _underlyingStream.SetLength(value);

        /// <inheritdoc />
        public override void Write(byte[] buffer, int offset, int count) {
            _algorithm.TransformBlock(buffer, offset, count, null, 0);
            _underlyingStream.Write(buffer, offset, count);
        }

        /// <inheritdoc />
        protected override void Dispose(bool disposing) {
            if (disposing)
                _algorithm.Dispose();
            base.Dispose(disposing);
        }
    }
}