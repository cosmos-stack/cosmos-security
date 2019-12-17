using System;
using System.Security.Cryptography;

// ReSharper disable ShiftExpressionRealShiftCountIsZero

namespace Cosmos.Encryption.Core {
    /// <summary>
    /// MurmurHash3 core services
    /// Reference to:
    ///     https://github.com/darrenkopp/murmurhash-net/blob/master/MurmurHash/MurmurHash.cs
    ///     Author: Darren Kopp
    ///     Apache License 2.0
    /// </summary>
    internal static partial class MurmurHash3Core {
        public abstract class MurmurHash3L128 : HashAlgorithm {

            private readonly uint _seed;

            protected MurmurHash3L128(uint seed) {
                _seed = seed;
            }

            public override int HashSize => 128;

            public uint Seed => _seed;
        }

        public class MurmurHash3L128ManagedX64 : MurmurHash3L128 {
            const ulong C1 = 0x87c37b91114253d5;
            const ulong C2 = 0x4cf5ad432745937f;

            internal MurmurHash3L128ManagedX64(uint seed = 0) : base(seed) {
                Reset();
            }

            private int Length { get; set; }
            private ulong H1 { get; set; }
            private ulong H2 { get; set; }

            private void Reset() {
                // initialize hash values to seed values
                H1 = H2 = Seed;
                // reset our length back to 0
                Length = 0;
            }

            public override void Initialize() {
                Reset();
            }

            protected override void HashCore(byte[] array, int ibStart, int cbSize) {
                // increment our length
                Length += cbSize;
                Body(array, ibStart, cbSize);
            }

            private void Body(byte[] data, int start, int length) {
                int remainder = length & 15;
                int alignedLength = start + (length - remainder);
                for (int i = start; i < alignedLength; i += 16) {
                    H1 ^= (data.ToUInt64(i) * C1).RotateLeft(31) * C2;
                    H1 = (H1.RotateLeft(27) + H2) * 5 + 0x52dce729;

                    H2 ^= (data.ToUInt64(i + 8) * C2).RotateLeft(33) * C1;
                    H2 = (H2.RotateLeft(31) + H1) * 5 + 0x38495ab5;
                }

                if (remainder > 0)
                    Tail(data, alignedLength, remainder);
            }

            private void Tail(byte[] tail, int start, int remaining) {
                // create our keys and initialize to 0
                ulong k1 = 0, k2 = 0;

                // determine how many bytes we have left to work with based on length
                switch (remaining) {
                    case 15:
                        k2 ^= (ulong) tail[start + 14] << 48;
                        goto case 14;
                    case 14:
                        k2 ^= (ulong) tail[start + 13] << 40;
                        goto case 13;
                    case 13:
                        k2 ^= (ulong) tail[start + 12] << 32;
                        goto case 12;
                    case 12:
                        k2 ^= (ulong) tail[start + 11] << 24;
                        goto case 11;
                    case 11:
                        k2 ^= (ulong) tail[start + 10] << 16;
                        goto case 10;
                    case 10:
                        k2 ^= (ulong) tail[start + 9] << 8;
                        goto case 9;
                    case 9:
                        k2 ^= (ulong) tail[start + 8] << 0;
                        goto case 8;
                    case 8:
                        k1 ^= (ulong) tail[start + 7] << 56;
                        goto case 7;
                    case 7:
                        k1 ^= (ulong) tail[start + 6] << 48;
                        goto case 6;
                    case 6:
                        k1 ^= (ulong) tail[start + 5] << 40;
                        goto case 5;
                    case 5:
                        k1 ^= (ulong) tail[start + 4] << 32;
                        goto case 4;
                    case 4:
                        k1 ^= (ulong) tail[start + 3] << 24;
                        goto case 3;
                    case 3:
                        k1 ^= (ulong) tail[start + 2] << 16;
                        goto case 2;
                    case 2:
                        k1 ^= (ulong) tail[start + 1] << 8;
                        goto case 1;
                    case 1:
                        k1 ^= (ulong) tail[start] << 0;
                        break;
                }

                H2 ^= (k2 * C2).RotateLeft(33) * C1;
                H1 ^= (k1 * C1).RotateLeft(31) * C2;
            }

            protected override byte[] HashFinal() {
                ulong len = (ulong) Length;
                H1 ^= len;
                H2 ^= len;

                H1 += H2;
                H2 += H1;

                H1 = H1.FMix();
                H2 = H2.FMix();

                H1 += H2;
                H2 += H1;

                var result = new byte[16];
                Array.Copy(BitConverter.GetBytes(H1), 0, result, 0, 8);
                Array.Copy(BitConverter.GetBytes(H2), 0, result, 8, 8);

                return result;
            }
        }

        public class MurmurHash3L128ManagedX86 : MurmurHash3L128 {
            const uint C1 = 0x239b961bU;
            const uint C2 = 0xab0e9789U;
            const uint C3 = 0x38b34ae5U;
            const uint C4 = 0xa1e38b93U;

            internal MurmurHash3L128ManagedX86(uint seed = 0) : base(seed) {
                Reset();
            }

            private uint H1 { get; set; }
            private uint H2 { get; set; }
            private uint H3 { get; set; }
            private uint H4 { get; set; }
            private int Length { get; set; }

            private void Reset() {
                // initialize hash values to seed values
                H1 = H2 = H3 = H4 = Seed;
                Length = 0;
            }

            public override void Initialize() {
                Reset();
            }

            protected override void HashCore(byte[] array, int ibStart, int cbSize) {
                // store the length of the hash (for use later)
                Length += cbSize;
                Body(array, ibStart, cbSize);
            }

            private void Body(byte[] data, int start, int length) {
                int remainder = length & 15;
                int alignedLength = start + (length - remainder);
                for (int i = start; i < alignedLength; i += 16) {
                    uint k1 = data.ToUInt32(i),
                         k2 = data.ToUInt32(i + 4),
                         k3 = data.ToUInt32(i + 8),
                         k4 = data.ToUInt32(i + 12);

                    H1 ^= (k1 * C1).RotateLeft(15) * C2;
                    H1 = (H1.RotateLeft(19) + H2) * 5 + 0x561ccd1b;

                    H2 ^= (k2 * C2).RotateLeft(16) * C3;
                    H2 = (H2.RotateLeft(17) + H3) * 5 + 0x0bcaa747;

                    H3 ^= (k3 * C3).RotateLeft(17) * C4;
                    H3 = (H3.RotateLeft(15) + H4) * 5 + 0x96cd1c35;

                    H4 ^= (k4 * C4).RotateLeft(18) * C1;
                    H4 = (H4.RotateLeft(13) + H1) * 5 + 0x32ac3b17;
                }

                if (remainder > 0)
                    Tail(data, alignedLength, remainder);
            }

            private void Tail(byte[] tail, int position, int remainder) {
                // create our keys and initialize to 0
                uint k1 = 0, k2 = 0, k3 = 0, k4 = 0;

                // determine how many bytes we have left to work with based on length
                switch (remainder) {
                    case 15:
                        k4 ^= (uint) tail[position + 14] << 16;
                        goto case 14;
                    case 14:
                        k4 ^= (uint) tail[position + 13] << 8;
                        goto case 13;
                    case 13:
                        k4 ^= (uint) tail[position + 12] << 0;
                        goto case 12;
                    case 12:
                        k3 ^= (uint) tail[position + 11] << 24;
                        goto case 11;
                    case 11:
                        k3 ^= (uint) tail[position + 10] << 16;
                        goto case 10;
                    case 10:
                        k3 ^= (uint) tail[position + 9] << 8;
                        goto case 9;
                    case 9:
                        k3 ^= (uint) tail[position + 8] << 0;
                        goto case 8;
                    case 8:
                        k2 ^= (uint) tail[position + 7] << 24;
                        goto case 7;
                    case 7:
                        k2 ^= (uint) tail[position + 6] << 16;
                        goto case 6;
                    case 6:
                        k2 ^= (uint) tail[position + 5] << 8;
                        goto case 5;
                    case 5:
                        k2 ^= (uint) tail[position + 4] << 0;
                        goto case 4;
                    case 4:
                        k1 ^= (uint) tail[position + 3] << 24;
                        goto case 3;
                    case 3:
                        k1 ^= (uint) tail[position + 2] << 16;
                        goto case 2;
                    case 2:
                        k1 ^= (uint) tail[position + 1] << 8;
                        goto case 1;
                    case 1:
                        k1 ^= (uint) tail[position] << 0;
                        break;
                }

                H4 ^= (k4 * C4).RotateLeft(18) * C1;
                H3 ^= (k3 * C3).RotateLeft(17) * C4;
                H2 ^= (k2 * C2).RotateLeft(16) * C3;
                H1 ^= (k1 * C1).RotateLeft(15) * C2;
            }

            protected override byte[] HashFinal() {
                uint len = (uint) Length;
                H1 ^= len;
                H2 ^= len;
                H3 ^= len;
                H4 ^= len;

                H1 += (H2 + H3 + H4);
                H2 += H1;
                H3 += H1;
                H4 += H1;

                H1 = H1.FMix();
                H2 = H2.FMix();
                H3 = H3.FMix();
                H4 = H4.FMix();

                H1 += (H2 + H3 + H4);
                H2 += H1;
                H3 += H1;
                H4 += H1;

                var result = new byte[16];
                Array.Copy(BitConverter.GetBytes(H1), 0, result, 0, 4);
                Array.Copy(BitConverter.GetBytes(H2), 0, result, 4, 4);
                Array.Copy(BitConverter.GetBytes(H3), 0, result, 8, 4);
                Array.Copy(BitConverter.GetBytes(H4), 0, result, 12, 4);

                return result;
            }
        }

        public class MurmurHash3L128UnmanagedX64 : MurmurHash3L128 {
            const ulong C1 = 0x87c37b91114253d5UL;
            const ulong C2 = 0x4cf5ad432745937fUL;

            internal MurmurHash3L128UnmanagedX64(uint seed = 0) : base(seed) {
                Reset();
            }

            private ulong H1 { get; set; }
            private ulong H2 { get; set; }
            private int Length { get; set; }

            private void Reset() {
                // initialize hash values to seed values
                H1 = H2 = Seed;
                Length = 0;
            }

            public override void Initialize() {
                Reset();
            }

            protected override void HashCore(byte[] array, int ibStart, int cbSize) {
                // store the length of the hash (for use later)
                Length += cbSize;
                Body(array, ibStart, cbSize);
            }

            private void Body(byte[] data, int start, int length) {
                if (length == 0)
                    return;

                int remainder = length & 15;
                int blocks = length / 16;

                unsafe {
                    fixed (byte* d = &data[start]) {
                        ulong* current = (ulong*) d;

                        while (blocks-- > 0) {
                            // a variant of original algorithm optimized for processor instruction pipelining
                            H1 ^= (*current++ * C1).RotateLeft(31) * C2;
                            H1 = (H1.RotateLeft(27) + H2) * 5 + 0x52dce729;

                            H2 ^= (*current++ * C2).RotateLeft(33) * C1;
                            H2 = (H2.RotateLeft(31) + H1) * 5 + 0x38495ab5;
                        }

                        if (remainder > 0)
                            Tail(d + (length - remainder), remainder);
                    }
                }
            }

            private unsafe void Tail(byte* tail, int remaining) {
                // create our keys and initialize to 0
                ulong k1 = 0, k2 = 0;

                // determine how many bytes we have left to work with based on length
                switch (remaining) {
                    case 15:
                        k2 ^= (ulong) tail[14] << 48;
                        goto case 14;
                    case 14:
                        k2 ^= (ulong) tail[13] << 40;
                        goto case 13;
                    case 13:
                        k2 ^= (ulong) tail[12] << 32;
                        goto case 12;
                    case 12:
                        k2 ^= (ulong) tail[11] << 24;
                        goto case 11;
                    case 11:
                        k2 ^= (ulong) tail[10] << 16;
                        goto case 10;
                    case 10:
                        k2 ^= (ulong) tail[9] << 8;
                        goto case 9;
                    case 9:
                        k2 ^= (ulong) tail[8] << 0;
                        goto case 8;
                    case 8:
                        k1 ^= (ulong) tail[7] << 56;
                        goto case 7;
                    case 7:
                        k1 ^= (ulong) tail[6] << 48;
                        goto case 6;
                    case 6:
                        k1 ^= (ulong) tail[5] << 40;
                        goto case 5;
                    case 5:
                        k1 ^= (ulong) tail[4] << 32;
                        goto case 4;
                    case 4:
                        k1 ^= (ulong) tail[3] << 24;
                        goto case 3;
                    case 3:
                        k1 ^= (ulong) tail[2] << 16;
                        goto case 2;
                    case 2:
                        k1 ^= (ulong) tail[1] << 8;
                        goto case 1;
                    case 1:
                        k1 ^= (ulong) tail[0] << 0;
                        break;
                }

                H2 ^= (k2 * C2).RotateLeft(33) * C1;
                H1 ^= (k1 * C1).RotateLeft(31) * C2;
            }

            protected override byte[] HashFinal() {
                ulong len = (ulong) Length;
                H1 ^= len;
                H2 ^= len;

                H1 += H2;
                H2 += H1;

                H1 = H1.FMix();
                H2 = H2.FMix();

                H1 += H2;
                H2 += H1;

                var result = new byte[16];
                unsafe {
                    fixed (byte* h = result) {
                        ulong* r = (ulong*) h;

                        r[0] = H1;
                        r[1] = H2;
                    }
                }

                return result;
            }
        }

        public class MurmurHash3L128UnmanagedX86 : MurmurHash3L128 {
            const uint C1 = 0x239b961b;
            const uint C2 = 0xab0e9789;
            const uint C3 = 0x38b34ae5;
            const uint C4 = 0xa1e38b93;

            internal MurmurHash3L128UnmanagedX86(uint seed = 0) : base(seed) {
                Reset();
            }

            private uint H1 { get; set; }
            private uint H2 { get; set; }
            private uint H3 { get; set; }
            private uint H4 { get; set; }
            private int Length { get; set; }

            private void Reset() {
                // initialize hash values to seed values
                H1 = H2 = H3 = H4 = Seed;
                Length = 0;
            }

            public override void Initialize() {
                Reset();
            }

            protected override void HashCore(byte[] array, int ibStart, int cbSize) {
                // store the length of the hash (for use later)
                Length += cbSize;
                Body(array, ibStart, cbSize);
            }

            private void Body(byte[] data, int start, int length) {
                if (length == 0)
                    return;

                int remainder = length & 15;
                int blocks = length / 16;

                unsafe {
                    fixed (byte* d = &data[start]) {
                        // grab a reference to blocks
                        uint* b = (uint*) d;
                        while (blocks-- > 0) {
                            // K1 - consume first integer
                            H1 ^= (*b++ * C1).RotateLeft(15) * C2;
                            H1 = (H1.RotateLeft(19) + H2) * 5 + 0x561ccd1b;

                            // K2 - consume second integer
                            H2 ^= (*b++ * C2).RotateLeft(16) * C3;
                            H2 = (H2.RotateLeft(17) + H3) * 5 + 0x0bcaa747;

                            // K3 - consume third integer
                            H3 ^= (*b++ * C3).RotateLeft(17) * C4;
                            H3 = (H3.RotateLeft(15) + H4) * 5 + 0x96cd1c35;

                            // K4 - consume fourth integer
                            H4 ^= (*b++ * C4).RotateLeft(18) * C1;
                            H4 = (H4.RotateLeft(13) + H1) * 5 + 0x32ac3b17;
                        }

                        if (remainder > 0)
                            Tail(d + (length - remainder), remainder);
                    }
                }
            }

            private unsafe void Tail(byte* tail, int remainder) {
                // create our keys and initialize to 0
                uint k1 = 0, k2 = 0, k3 = 0, k4 = 0;

                // determine how many bytes we have left to work with based on length
                switch (remainder) {
                    case 15:
                        k4 ^= (uint) tail[14] << 16;
                        goto case 14;
                    case 14:
                        k4 ^= (uint) tail[13] << 8;
                        goto case 13;
                    case 13:
                        k4 ^= (uint) tail[12] << 0;
                        goto case 12;
                    case 12:
                        k3 ^= (uint) tail[11] << 24;
                        goto case 11;
                    case 11:
                        k3 ^= (uint) tail[10] << 16;
                        goto case 10;
                    case 10:
                        k3 ^= (uint) tail[9] << 8;
                        goto case 9;
                    case 9:
                        k3 ^= (uint) tail[8] << 0;
                        goto case 8;
                    case 8:
                        k2 ^= (uint) tail[7] << 24;
                        goto case 7;
                    case 7:
                        k2 ^= (uint) tail[6] << 16;
                        goto case 6;
                    case 6:
                        k2 ^= (uint) tail[5] << 8;
                        goto case 5;
                    case 5:
                        k2 ^= (uint) tail[4] << 0;
                        goto case 4;
                    case 4:
                        k1 ^= (uint) tail[3] << 24;
                        goto case 3;
                    case 3:
                        k1 ^= (uint) tail[2] << 16;
                        goto case 2;
                    case 2:
                        k1 ^= (uint) tail[1] << 8;
                        goto case 1;
                    case 1:
                        k1 ^= (uint) tail[0] << 0;
                        break;
                }

                H4 ^= (k4 * C4).RotateLeft(18) * C1;
                H3 ^= (k3 * C3).RotateLeft(17) * C4;
                H2 ^= (k2 * C2).RotateLeft(16) * C3;
                H1 ^= (k1 * C1).RotateLeft(15) * C2;
            }

            protected override byte[] HashFinal() {
                uint len = (uint) Length;
                // pipelining friendly algorithm
                H1 ^= len;
                H2 ^= len;
                H3 ^= len;
                H4 ^= len;

                H1 += (H2 + H3 + H4);
                H2 += H1;
                H3 += H1;
                H4 += H1;

                H1 = H1.FMix();
                H2 = H2.FMix();
                H3 = H3.FMix();
                H4 = H4.FMix();

                H1 += (H2 + H3 + H4);
                H2 += H1;
                H3 += H1;
                H4 += H1;

                var result = new byte[16];
                unsafe {
                    fixed (byte* h = result) {
                        var r = (uint*) h;

                        r[0] = H1;
                        r[1] = H2;
                        r[2] = H3;
                        r[3] = H4;
                    }
                }

                return result;
            }
        }
    }
}