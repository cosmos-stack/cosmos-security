using System;
using System.Security.Cryptography;

namespace Cosmos.Encryption.Core {
    /// <summary>
    /// MurmurHash3 core services
    /// Reference to:
    ///     https://github.com/darrenkopp/murmurhash-net/blob/master/MurmurHash/MurmurHash.cs
    ///     Author: Darren Kopp
    ///     Apache License 2.0
    /// </summary>
    internal static partial class MurmurHash3Core {
        public abstract class MurmurHash3L32 : HashAlgorithm {
            protected const uint C1 = 0xcc9e2d51;
            protected const uint C2 = 0x1b873593;

            private readonly uint _seed;

            protected MurmurHash3L32(uint seed) {
                _seed = seed;
                Reset();
            }

            public override int HashSize => 32;

            public uint Seed => _seed;

            protected uint H1 { get; set; }

            protected int Length { get; set; }

            private void Reset() {
                H1 = _seed;
                Length = 0;
            }

            public override void Initialize() {
                Reset();
            }

            protected override byte[] HashFinal() {
                H1 = (H1 ^ (uint) Length).FMix();
                return BitConverter.GetBytes(H1);
            }
        }

        public class MurmurHash3L32ManagedX86 : MurmurHash3L32 {

            public MurmurHash3L32ManagedX86(uint seed = 0) : base(seed) { }

            protected override void HashCore(byte[] array, int ibStart, int cbSize) {
                Length += cbSize;
                Body(array, ibStart, cbSize);
            }

            private void Body(byte[] data, int start, int length) {
                var remainder = length & 3;
                var alignedLength = start + (length - remainder);

                for (var i = start; i < alignedLength; i += 4) {
                    H1 = (((H1 ^ (((data.ToUInt32(i) * C1).RotateLeft(15)) * C2)).RotateLeft(13)) * 5) + 0xe6546b64;
                }

                if (remainder > 0)
                    Tail(data, alignedLength, remainder);
            }

            private void Tail(byte[] tail, int position, int remainder) {
                //create our keys and initialize to 0
                uint k1 = 0;

                //determine how many bytes we have left to work with based on length
                switch (remainder) {
                    case 3:
                        k1 ^= (uint) tail[position + 2] << 16;
                        goto case 2;

                    case 2:
                        k1 ^= (uint) tail[position + 1] << 8;
                        goto case 1;

                    case 1:
                        k1 ^= tail[position];
                        break;
                }

                H1 ^= (k1 * C1).RotateLeft(15) * C2;
            }
        }

        public class MurmurHash3L32UnmanagedX86 : MurmurHash3L32 {

            public MurmurHash3L32UnmanagedX86(uint seed = 0) : base(seed) { }

            protected override void HashCore(byte[] array, int ibStart, int cbSize) {
                Length += cbSize;
                Body(array, ibStart, cbSize);
            }

            private void Body(byte[] data, int start, int length) {

                if (length == 0)
                    return;

                var remainder = length & 3;
                int blocks = length / 4;

                unsafe {
                    //grab pointer to first byte in array
                    fixed (byte* d = &data[start]) {
                        uint* b = (uint*) d;

                        while (blocks-- > 0)
                            H1 = (((H1 ^ (((*b++ * C1).RotateLeft(15)) * C2)).RotateLeft(13)) * 5) + 0xe6546b64;

                        if (remainder > 0)
                            Tail(d + (length - remainder), remainder);
                    }
                }
            }

            private unsafe void Tail(byte* tail, int remainder) {
                //create our keys and initialize to 0
                uint k1 = 0;

                //determine how many bytes we have left to work with based on length
                switch (remainder) {
                    case 3:
                        k1 ^= (uint) tail[2] << 16;
                        goto case 2;

                    case 2:
                        k1 ^= (uint) tail[1] << 8;
                        goto case 1;

                    case 1:
                        k1 ^= tail[0];
                        break;
                }

                H1 ^= (k1 * C1).RotateLeft(15) * C2;
            }
        }
    }
}