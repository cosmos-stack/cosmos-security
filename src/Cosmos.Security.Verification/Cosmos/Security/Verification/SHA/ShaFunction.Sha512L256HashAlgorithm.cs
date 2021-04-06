using System;
using System.Security.Cryptography;
using Cosmos.Collections;

namespace Cosmos.Security.Verification.SHA
{
    public partial class ShaFunction
    {
        /// <summary>
        /// SHA512/256 Crypto Service Provider
        /// </summary>
        private class SHA512L256CryptoServiceProvider : HashAlgorithm
        {
            private const int numberBits = 256;

            private Block1024[] blocks;

            private byte[] hashValue;
            
            public override void Initialize()
            {
                blocks.Clear();
                blocks = default;
            }

            protected override void HashCore(byte[] array, int ibStart, int cbSize)
            {
                blocks = ConvertPaddedMessageToBlock1024Array(PadPlainText1024(array));

                // Define the hash variables and set their initial values.
                var H = new ulong[8];
                Array.Copy(H0Sha512_256, 0, H, 0, 8);

                for (int i = 0; i < blocks.Length; i++)
                {
                    ulong[] W = CreateMessageScheduleSha512(blocks[i]);

                    // Set the working variables a,...,h to the current hash values.
                    ulong a = H[0];
                    ulong b = H[1];
                    ulong c = H[2];
                    ulong d = H[3];
                    ulong e = H[4];
                    ulong f = H[5];
                    ulong g = H[6];
                    ulong h = H[7];

                    for (int t = 0; t < 80; t++)
                    {
                        ulong T1 = h + Sigma1_512(e) + Ch(e, f, g) + K512[t] + W[t];
                        ulong T2 = Sigma0_512(a) + Maj(a, b, c);
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

                // Concatenate all the ulong Hash Values
                hashValue = ShaUtilities.Word64ArrayToByteArray(H);
            }

            protected override byte[] HashFinal()
            {
                // The number of bytes in the final output hash 
                int numberBytes = numberBits / 8;
                byte[] truncatedHash = new byte[numberBytes];
                Array.Copy(hashValue, truncatedHash, numberBytes);

                return truncatedHash;
            }
        }
    }
}