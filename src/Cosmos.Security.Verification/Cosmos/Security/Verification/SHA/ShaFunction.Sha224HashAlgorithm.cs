using System;
using System.Security.Cryptography;
using Cosmos.Collections;

namespace Cosmos.Security.Verification.SHA
{
    public partial class ShaFunction
    {
        /// <summary>
        /// SHA 224 Crypto Service Provider
        /// </summary>
        private class SHA224CryptoServiceProvider : HashAlgorithm
        {
            private const int numberBits = 224;

            private Block512[] blocks;

            private byte[] hashValue;

            protected override void HashCore(byte[] array, int ibStart, int cbSize)
            {
                blocks = ConvertPaddedTextToBlock512Array(PadPlainText512(array));

                // Define the hash variables and set their initial values.
                var H = new uint[8];
                Array.Copy(H0Sha224, 0, H, 0, 8);

                for (var i = 0; i < blocks.Length; i++)
                {
                    var W = CreateMessageScheduleSha256(blocks[i]);

                    // Set the working variables a,...,h to the current hash values.
                    uint a = H[0];
                    uint b = H[1];
                    uint c = H[2];
                    uint d = H[3];
                    uint e = H[4];
                    uint f = H[5];
                    uint g = H[6];
                    uint h = H[7];

                    for (var t = 0; t < 64; t++)
                    {
                        uint T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[t] + W[t];
                        uint T2 = Sigma0_256(a) + Maj(a, b, c);
                        h = g;
                        g = f;
                        f = e;
                        e = d + T1;
                        d = c;
                        c = b;
                        b = a;
                        a = T1 + T2;
                    }

                    // Update the current value of the hash H after processing block i.
                    H[0] += a;
                    H[1] += b;
                    H[2] += c;
                    H[3] += d;
                    H[4] += e;
                    H[5] += f;
                    H[6] += g;
                    H[7] += h;
                }

                // Concatenate all the uint Hash Values
                hashValue = ShaUtilities.Word32ArrayToByteArray(H);
            }

            protected override byte[] HashFinal()
            {
                // The number of bytes in the final output hash 
                int numberBytes = numberBits / 8;
                byte[] truncatedHash = new byte[numberBytes];
                Array.Copy(hashValue, truncatedHash, numberBytes);

                return truncatedHash;
            }

            public override void Initialize()
            {
                blocks.Clear();
                blocks = default;
            }
        }
    }
}