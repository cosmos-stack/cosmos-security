using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Cosmos.Security.Verification.SHA
{
    using Word32 = System.UInt32;
    using Word64 = System.UInt64;

    public partial class ShaFunction
    {
        private static uint[] H0Sha224 =
        {
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
        };

        private static Word32[] K256 =
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

        #endregion

        #region Functions used in the hashing process.

        // should have 0 <= n < 32
        static uint RotR(int n, uint x) => (x >> n) | (x << 32 - n);

        // should have 0 <= n < 32
        static uint ShR(int n, uint x) => (x >> n);

        static uint Ch(uint x, uint y, uint z) => (x & y) ^ (~x & z);

        static uint Maj(uint x, uint y, uint z) => (x & y) ^ (x & z) ^ (y & z);

        static uint Sigma0_256(uint x) => RotR(2, x) ^ RotR(13, x) ^ RotR(22, x);

        static uint Sigma1_256(uint x) => RotR(6, x) ^ RotR(11, x) ^ RotR(25, x);

        static uint sigma1_256(uint x) => RotR(17, x) ^ RotR(19, x) ^ ShR(10, x);

        static uint sigma0_256(uint x) => RotR(7, x) ^ RotR(18, x) ^ ShR(3, x);

        #endregion

        #region Block512 Helper Class

        private class Block512
        {
            // A Block512 consists of an array of 16 elements of type Word32.
            public Word32[] words;

            public Block512(Word32[] words)
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

            // Returns an array of 4 bytes.
            public static byte[] Word32ToByteArray(uint x)
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
                {
                    word32Array[i] = ByteArrayToWord32(b, 4 * i);
                }

                return word32Array;
            }

            public static uint ByteArrayToWord32(byte[] b, int startIndex)
            {
                // We assume: 0 <= startIndex < B. Length, and startIndex + 4 <= B.Length

                uint c = 256;
                uint output = 0;

                for (var i = startIndex; i < startIndex + 4; i++)
                {
                    output = output * c + b[i];
                }

                return output;
            }
        }
    }
}