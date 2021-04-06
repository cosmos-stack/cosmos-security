using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;

namespace Cosmos.Security.Verification.SHA
{
    public partial class ShaFunction
    {
        /// <summary>
        /// SHA512/t Crypto Service Provider
        /// </summary>
        private class SHA512tCryptoServiceProvider : HashAlgorithm
        {
            private readonly Sha512tDigest _digest;
            private readonly int _hashSize;

            public SHA512tCryptoServiceProvider(int hashSize)
            {
                _hashSize = hashSize;
                _digest = new Sha512tDigest(hashSize);
            }

            public override int HashSize => _hashSize;

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