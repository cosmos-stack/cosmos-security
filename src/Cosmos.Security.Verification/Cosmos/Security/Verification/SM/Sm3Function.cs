using System;
#if NETFRAMEWORK
using System.Linq;
#endif
using System.Security.Cryptography;
using System.Threading;
using Cosmos.Security.Verification.Core;
using Org.BouncyCastle.Crypto.Digests;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public class Sm3Function : StreamableHashFunctionBase
    {
        public override int HashSizeInBits => 256;

        internal Sm3Function() { }

        public override IBlockTransformer CreateBlockTransformer() => new Sm3BlockTransformer();

        #region Internal Implementation of BlockTransformer

        private class Sm3BlockTransformer : BlockTransformerBase<Sm3BlockTransformer>
        {
            private byte[] _hashValue;

            public Sm3BlockTransformer() { }

            protected override void CopyStateTo(Sm3BlockTransformer other)
            {
                base.CopyStateTo(other);

                other._hashValue = _hashValue;
            }

            protected override void TransformByteGroupsInternal(ArraySegment<byte> data)
            {
                using var hash = new SM3CryptoServiceProvider();
                _hashValue = hash.ComputeHash(data.ToArray());
            }

            protected override IHashValue FinalizeHashValueInternal(CancellationToken cancellationToken)
            {
                return new HashValue(_hashValue, 256);
            }
        }

        #endregion

        /// <summary>
        /// SM3 Crypto Service Provider
        /// </summary>
        private class SM3CryptoServiceProvider : HashAlgorithm
        {
            private readonly SM3Digest _digest;

            public SM3CryptoServiceProvider()
            {
                _digest = new SM3Digest();
            }

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