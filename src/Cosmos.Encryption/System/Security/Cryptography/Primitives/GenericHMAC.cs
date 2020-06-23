// ReSharper disable RedundantUsingDirective
// ReSharper disable InconsistentNaming

/*
 * A copy of https://github.com/linnaea/Cryptography.GM
 *     Author: Linnaea Von Lavia
 *     Site: http://linnaea.moe/
 */

using System.Linq;
using System.Reflection;

namespace System.Security.Cryptography.Primitives
{
    internal class GenericHMAC<T> : HMAC where T : HashAlgorithm
    {
#if !(NETSTANDARD2_0 || NETSTANDARD2_1)
        // ReSharper disable StaticMemberInGenericType
        private static readonly MethodInfo _hashCore;

        private static readonly MethodInfo _hashFinal;
        // ReSharper restore StaticMemberInGenericType

        static GenericHMAC()
        {
            var typeMethods = typeof(T).GetRuntimeMethods()
               .Where(v => !v.IsPrivate && !v.IsPublic && v.IsVirtual && !v.IsStatic).ToArray();
            _hashCore = typeMethods.Single(v => v.Name == nameof(HashCore) && v.GetParameters().Length == 3);
            _hashFinal = typeMethods.Single(v => v.Name == nameof(HashFinal) && v.GetParameters().Length == 0);
        }
#endif

        private readonly int _blockBytes;
        private readonly byte[] _rgbInner;
        private readonly byte[] _rgbOuter;
#if NET451
        private byte[] _keyValue = new byte[0];
#else
        private byte[] _keyValue = Array.Empty<byte>();
#endif
        private bool _hashing;

        protected readonly T Hasher;

        public sealed override int HashSize => Hasher.HashSize;

        public GenericHMAC(T hasher, int blockBytes, byte[] rgbKey)
        {
            Hasher = hasher;
            _blockBytes = blockBytes;
            _rgbInner = new byte[blockBytes];
            _rgbOuter = new byte[blockBytes];
            Key = rgbKey;
        }

        public sealed override byte[] Key
        {
            get => (byte[]) _keyValue.Clone();
            set
            {
                if (_hashing)
                {
                    throw new InvalidOperationException("Cannot change key during hash operation");
                }

                if (value.Length > _blockBytes)
                {
                    _keyValue = Hasher.ComputeHash(value);
                }
                else
                {
                    _keyValue = (byte[]) value.Clone();
                }

                for (var i = 0; i < _blockBytes; i++)
                {
                    _rgbInner[i] = 0x36;
                    _rgbOuter[i] = 0x5C;
                }

                for (var i = 0; i < _keyValue.Length; i++)
                {
                    _rgbInner[i] ^= _keyValue[i];
                    _rgbOuter[i] ^= _keyValue[i];
                }
            }
        }

        public sealed override void Initialize()
        {
            Hasher.Initialize();
            _hashing = false;
        }

#if NETSTANDARD2_0 || NETSTANDARD2_1
        protected virtual void AddHashData(byte[] rgb, int ib, int cb) => Hasher.TransformBlock(rgb, ib, cb, null, 0);
        protected virtual byte[] FinalizeInnerHash()
        {
            Hasher.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return Hasher.Hash;
        }
#elif NET451
        protected virtual void AddHashData(byte[] rgb, int ib, int cb) => _hashCore.Invoke(Hasher, new object[] {rgb, ib, cb});
        protected virtual byte[] FinalizeInnerHash() => (byte[]) _hashFinal.Invoke(Hasher, new object[0]);
#else
        protected virtual void AddHashData(byte[] rgb, int ib, int cb) => _hashCore.Invoke(Hasher, new object[] {rgb, ib, cb});
        protected virtual byte[] FinalizeInnerHash() => (byte[]) _hashFinal.Invoke(Hasher, Array.Empty<object>());
#endif

        private void EnsureStarted()
        {
            if (_hashing) return;
            AddHashData(_rgbInner, 0, _blockBytes);
            _hashing = true;
        }

        protected sealed override void HashCore(byte[] rgb, int ib, int cb)
        {
            EnsureStarted();
            AddHashData(rgb, ib, cb);
        }

        protected sealed override byte[] HashFinal()
        {
            EnsureStarted();
            var hashInner = FinalizeInnerHash();
            Hasher.Initialize();
            AddHashData(_rgbOuter, 0, _blockBytes);
            AddHashData(hashInner, 0, hashInner.Length);
            _hashing = false;
            return FinalizeInnerHash();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) Hasher.Dispose();
            base.Dispose(disposing);
        }
    }
}