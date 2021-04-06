using System;
using System.Collections.Generic;
using System.Linq;

namespace Cosmos.Security.Verification.SHA
{
    public partial class ShaFunction
    {
        private static uint[] H0Sha224 =
        {
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
        };

        private static ulong[] H0Sha512_224 =
        {
            0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
            0x0f6d2b697bd44da8, 0x77e36f7304c48942, 0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1
        };

        private static ulong[] H0Sha512_256 =
        {
            0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd,
            0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2
        };

        private static uint[] K256 =
        {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        private static ulong[] K512 =
        {
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        };

        #region #region Hash Algorithms

        static uint[] CreateMessageScheduleSha256(Block512 block)
        {
            // The message schedule.
            var W = new uint[64];

            // Prepare the message schedule W.
            // The first 16 words in W are the same as the words of the block.
            // The remaining 64-16 = 48 words in W are functions of the previously defined words. 
            for (var t = 0; t < 64; t++)
            {
                if (t < 16)
                {
                    W[t] = block.words[t];
                }
                else
                {
                    W[t] = sigma1_256(W[t - 2]) + W[t - 7] + sigma0_256(W[t - 15]) + W[t - 16];
                }
            }

            return W;
        }

        static ulong[] CreateMessageScheduleSha512(Block1024 block)
        {
            // The message schedule.
            var W = new ulong[80];

            // Prepare the message schedule W.
            // The first 16 words in W are the same as the words of the block.
            // The remaining 80-16 =64 words in W are functions of the previously defined words. 
            for (int t = 0; t < 80; t++)
            {
                if (t < 16)
                {
                    W[t] = block.words[t];
                }
                else
                {
                    W[t] = sigma1_512(W[t - 2]) + W[t - 7] + sigma0_512(W[t - 15]) + W[t - 16];
                }
            }

            return W;
        }

        #endregion

        #region Plaintext preprocessing functions

        static byte[] PadPlainText512(byte[] plaintext)
        {
            // After padding the total bits of the output will be divisible by 512.
            int numberBits = plaintext.Length * 8;
            int t = (numberBits + 8 + 64) / 512;

            // Note that 512 * (t + 1) is the least multiple of 512 greater than (numberBits + 8 + 64)
            // Therefore the number of zero bits we need to add is
            int k = 512 * (t + 1) - (numberBits + 8 + 64);

            // Since numberBits % 8 = 0, we know k % 8 = 0. So n = k / 8 is the number of zero bytes to add.
            int n = k / 8;

            var paddedText = plaintext.ToList();

            // Start the padding by concatenating 1000_0000 = 0x80 = 128
            paddedText.Add(0x80);

            // Next add n zero bytes
            for (var i = 0; i < n; i++)
            {
                paddedText.Add(0);
            }

            // Now add 8 bytes (64 bits) to represent the length of the message in bits
            byte[] B = BitConverter.GetBytes((ulong) numberBits);
            Array.Reverse(B);

            for (var i = 0; i < B.Length; i++)
            {
                paddedText.Add(B[i]);
            }

            return paddedText.ToArray();
        }

        static byte[] PadPlainText1024(byte[] plaintext)
        {
            // After padding the total bits of the output will be divisible by 1024.
            int numberBits = plaintext.Length * 8;
            int t = (numberBits + 8 + 128) / 1024;

            // Note that 1024 * (t + 1) is the least multiple of 1024 greater than (numberBits + 8 + 128)
            // Therefore the number of zero bits we need to add is
            int k = 1024 * (t + 1) - (numberBits + 8 + 128);

            // Since numberBits % 8 = 0, we know k % 8 = 0. So n = k / 8 is the number of zero bytes to add.
            int n = k / 8;

            List<byte> paddedtext = plaintext.ToList();

            // Start the padding by concatenating 1000_0000 = 0x80 = 128
            paddedtext.Add(0x80);

            // Next add n zero bytes
            for (int i = 0; i < n; i++)
            {
                paddedtext.Add(0);
            }

            // Now add 16 bytes (128 bits) to represent the length of the message in bits.
            // C# does not have 128 bit integer.
            // For now just add 8 zero bytes and then 8 bytes to represent the int
            for (int i = 0; i < 8; i++)
            {
                paddedtext.Add(0);
            }

            byte[] B = BitConverter.GetBytes((ulong) numberBits);
            Array.Reverse(B);

            for (int i = 0; i < B.Length; i++)
            {
                paddedtext.Add(B[i]);
            }

            return paddedtext.ToArray();
        }

        private static Block512[] ConvertPaddedTextToBlock512Array(byte[] paddedText)
        {
            var numberBlocks = (paddedText.Length * 8) / 512;
            var blocks = new Block512[numberBlocks];

            for (var i = 0; i < numberBlocks; i++)
            {
                var b = new byte[64]; // 64 * 8 = 512
                for (var j = 0; j < 64; j++)
                    b[j] = paddedText[i * 64 + j];
                blocks[i] = new Block512(ShaUtilities.ByteArrayToWord32Array(b));
            }

            return blocks;
        }

        static Block1024[] ConvertPaddedMessageToBlock1024Array(byte[] M)
        {
            // We are assuming M is padded, so the number of bits in M is divisible by 1024 
            int numberBlocks = (M.Length * 8) / 1024; // same as: M.Length / 128
            Block1024[] blocks = new Block1024[numberBlocks];

            for (int i = 0; i < numberBlocks; i++)
            {
                // First extract the relavant subarray from M
                byte[] B = new byte[128]; // 128 * 8 = 1024

                for (int j = 0; j < 128; j++)
                {
                    B[j] = M[i * 128 + j];
                }

                ulong[] words = ShaUtilities.ByteArrayToWord64Array(B);
                blocks[i] = new Block1024(words);
            }

            return blocks;
        }

        #endregion

        #region Functions used in the hashing process.

        // should have 0 <= n < 32
        private static uint RotR(int n, uint x) => (x >> n) | (x << 32 - n);

        // should have 0 <= n < 64
        private static ulong RotR(int n, ulong x) => (x >> n) | (x << 64 - n);

        // should have 0 <= n < 32
        private static uint ShR(int n, uint x) => (x >> n);

        // should have 0 <= n < 64
        private static ulong ShR(int n, ulong x) => (x >> n);

        private static uint Ch(uint x, uint y, uint z) => (x & y) ^ (~x & z);

        private static ulong Ch(ulong x, ulong y, ulong z) => (x & y) ^ (~x & z);

        private static uint Maj(uint x, uint y, uint z) => (x & y) ^ (x & z) ^ (y & z);

        private static ulong Maj(ulong x, ulong y, ulong z) => (x & y) ^ (x & z) ^ (y & z);

        private static uint Sigma0_256(uint x) => RotR(2, x) ^ RotR(13, x) ^ RotR(22, x);

        private static uint Sigma1_256(uint x) => RotR(6, x) ^ RotR(11, x) ^ RotR(25, x);

        private static uint sigma1_256(uint x) => RotR(17, x) ^ RotR(19, x) ^ ShR(10, x);

        private static uint sigma0_256(uint x) => RotR(7, x) ^ RotR(18, x) ^ ShR(3, x);

        private static ulong Sigma0_512(ulong x) => RotR(28, x) ^ RotR(34, x) ^ RotR(39, x);

        private static ulong Sigma1_512(ulong x) => RotR(14, x) ^ RotR(18, x) ^ RotR(41, x);

        private static ulong sigma0_512(ulong x) => RotR(1, x) ^ RotR(8, x) ^ ShR(7, x);

        private static ulong sigma1_512(ulong x) => RotR(19, x) ^ RotR(61, x) ^ ShR(6, x);

        #endregion

        #region Block Helper Class

        private class Block512
        {
            // A Block512 consists of an array of 16 elements of type Word32.
            public uint[] words;

            public Block512(uint[] words)
            {
                this.words = words.Length == 16 ? words : null;
            }
        }

        private class Block1024
        {
            // A Block1024 consists of an array of 16 elements of type Word64.
            public ulong[] words;

            public Block1024(ulong[] words)
            {
                this.words = words.Length == 16 ? words : null;
            }
        }

        #endregion

        private static class ShaUtilities
        {
            public static byte[] Word32ArrayToByteArray(uint[] words)
            {
                var b = new List<byte>();
                foreach (var t in words)
                    b.AddRange(Word32ToByteArray(t));
                return b.ToArray();
            }

            public static byte[] Word64ArrayToByteArray(ulong[] words)
            {
                List<byte> b = new List<byte>();

                for (int i = 0; i < words.Length; i++)
                {
                    b.AddRange(Word64ToByteArray(words[i]));
                }

                return b.ToArray();
            }

            // Returns an array of 4 bytes.
            public static byte[] Word32ToByteArray(uint x)
            {
                byte[] b = BitConverter.GetBytes(x);
                Array.Reverse(b);
                return b;
            }

            // Returns an array of 8 bytes.
            public static byte[] Word64ToByteArray(ulong x)
            {
                byte[] b = BitConverter.GetBytes(x);
                Array.Reverse(b);
                return b;
            }

            public static uint[] ByteArrayToWord32Array(byte[] b)
            {
                // We assume B is not null, is not empty and number elements is divisible by 4
                var numberBytes = b.Length;
                var n = numberBytes / 4; // 4 bytes for each Word32
                var word32Array = new uint[n];
                for (var i = 0; i < n; i++)
                    word32Array[i] = ByteArrayToWord32(b, 4 * i);
                return word32Array;
            }

            public static ulong[] ByteArrayToWord64Array(byte[] b)
            {
                // We assume B is not null, is not empty and number elements is divisible by 8
                var numberWords = b.Length / 8; // 8 bytes for each Word32
                var word64Array = new ulong[numberWords];
                for (var i = 0; i < numberWords; i++)
                    word64Array[i] = ByteArrayToWord64(b, 8 * i);
                return word64Array;
            }

            public static uint ByteArrayToWord32(byte[] b, int startIndex)
            {
                // We assume: 0 <= startIndex < B. Length, and startIndex + 4 <= B.Length

                uint c = 256;
                uint output = 0;

                for (var i = startIndex; i < startIndex + 4; i++)
                    output = output * c + b[i];

                return output;
            }

            public static ulong ByteArrayToWord64(byte[] b, int startIndex)
            {
                // We assume: 0 <= startIndex < B. Length, and startIndex + 8 <= B.Length
                ulong c = 256;
                ulong output = 0;

                for (var i = startIndex; i < startIndex + 8; i++)
                    output = output * c + b[i];

                return output;
            }
        }
    }
}