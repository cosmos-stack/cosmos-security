using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public partial class ShaFunction
    {
        /// <summary>
        /// SHA224 Crypto Service Provider
        /// </summary>
        private class SHA224CryptoServiceProvider : HashAlgorithm
        {
            private readonly Sha224Digest _digest;

            public SHA224CryptoServiceProvider()
            {
                _digest = new Sha224Digest();
            }

            public override int HashSize => 224;

            public override void Initialize()
            {
                HashValue = new byte[_digest.GetDigestSize()];
            }

            protected override void HashCore(byte[] array, int ibStart, int cbSize)
            {
                if (HashValue is null)
                    Initialize();
                _digest.BlockUpdate(array, ibStart, cbSize);
            }

            protected override byte[] HashFinal()
            {
                _digest.DoFinal(HashValue, 0);
                return HashValue;
            }
        }
    }
}