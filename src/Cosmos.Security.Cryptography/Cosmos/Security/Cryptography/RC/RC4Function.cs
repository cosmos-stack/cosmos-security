using System;
using System.Linq;
using System.Threading;
using Cosmos.Security.Cryptography.Core.SymmetricAlgorithmImpls;

// ReSharper disable CheckNamespace
// ReSharper disable InconsistentNaming

namespace Cosmos.Security.Cryptography
{
    internal class RC4Function : SymmetricCryptoFunction<RcKey>, IRC
    {
        public RC4Function(RcKey key)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }

        public override RcKey Key { get; }

        public override int KeySize => Key.Size;

        protected override ICryptoValue EncryptInternal(ArraySegment<byte> originalBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var data = GetBytes(originalBytes);
            var cipher = EncryptCore(data, Key.GetKey());
            return CreateCryptoValue(data, cipher, CryptoMode.Encrypt);
        }

        protected override ICryptoValue DecryptInternal(ArraySegment<byte> cipherBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var cipher = GetBytes(cipherBytes);
            var original = EncryptCore(cipher, Key.GetKey());
            return CreateCryptoValue(original, cipher, CryptoMode.Decrypt);
        }

        private static byte[] EncryptCore(byte[] data, byte[] key)
        {
            var s = Initalize(key);
            int i = 0, j = 0;

            return data.Select(b =>
            {
                i = (i + 1) & 255;
                j = (j + s[i]) & 255;
                Swap(s, i, j);
                return (byte) (b ^ s[(s[i] + s[j]) & 255]);
            }).ToArray();
        }

        private static byte[] Initalize(byte[] key)
        {
            var s = Enumerable.Range(0, 256).Select(i => (byte) i).ToArray();
            for (int i = 0, j = 0; i < 256; i++)
            {
                j = (j + key[i % key.Length] + s[i]) & 255;
                Swap(s, i, j);
            }

            return s;
        }

        private static void Swap(byte[] s, int i, int j)
        {
            var b = s[i];
            s[i] = s[j];
            s[j] = b;
        }

        private static byte[] GetBytes(ArraySegment<byte> bytes)
        {
            var ret = new byte[bytes.Count];
            Array.Copy(bytes.Array!, bytes.Offset, ret, 0, bytes.Count);
            return ret;
        }
    }
}