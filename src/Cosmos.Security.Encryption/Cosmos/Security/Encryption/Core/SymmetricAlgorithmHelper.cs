using System;
using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

#if !NETFRAMEWORK && !NETSTANDARD2_0
using System.Diagnostics.CodeAnalysis;
#endif

namespace Cosmos.Security.Encryption.Core
{
    /// <summary>
    /// The high-performance encapsulation of the symmetric encryption algorithm supports high concurrency
    /// and high resource reuse rate. The unused resources in 5 minutes are automatically released,
    /// which is about 8 times faster than the official instance.<br />
    /// 对称加密算法的高性能封装，支持高并发，资源重复利用率高，5 分钟未使用的资源自动释放，比官方实例快 8 倍左右。
    /// </summary>
    internal static class SymmetricAlgorithmHelper
    {
        /// <summary>
        /// Indicates how long the object has not been used and needs to be released.
        /// The unit is milliseconds. <br />
        /// 指示对象多长时间未使用需要释放。单位毫秒。
        /// </summary>
        public static int DisposeInterval = 1000 * 60 * 5;

        static readonly ConcurrentDictionary<AlgorithmInfo, EncryptorSet> Encryptors = new ConcurrentDictionary<AlgorithmInfo, EncryptorSet>();

        static Encryptor GetOrCreateEncryptor(Type algorithmType, byte[] key)
        {
            return Encryptors.GetOrAdd(new AlgorithmInfo(algorithmType, key), (algorithmInfo) => new EncryptorSet(algorithmInfo)).Value;
        }

        static SymmetricAlgorithm CreateInstance(Type algorithmType)
        {
            var createMethod = algorithmType.GetMethod(
                nameof(HashAlgorithm.Create),
                BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly,
                Type.DefaultBinder,
                Type.EmptyTypes,
                null);

            if (createMethod != null)
            {
                return (SymmetricAlgorithm) createMethod.Invoke(null, null);
            }
            else
            {
                return (SymmetricAlgorithm) Activator.CreateInstance(algorithmType);
            }
        }

        /// <summary>
        /// Use the specified symmetric algorithm and key for encryption.<br />
        /// 使用指定对称算法和密钥进行加密。
        /// </summary>
        /// <typeparam name="TSymmetricAlgorithm">对称算法</typeparam>
        /// <param name="source">原文</param>
        /// <param name="key">密钥</param>
        /// <returns>返回密文</returns>
        public static byte[] Encrypt<TSymmetricAlgorithm>(ArraySegment<byte> source, byte[] key) where TSymmetricAlgorithm : SymmetricAlgorithm
        {
            return GetOrCreateEncryptor(typeof(TSymmetricAlgorithm), key).Encrypt(source);
        }

        /// <summary>
        /// Use the specified symmetric algorithm and key for decryption.<br />
        /// 使用指定的对称算法和密钥进行解密。
        /// </summary>
        /// <typeparam name="TSymmetricAlgorithm">对称算法</typeparam>
        /// <param name="source">密文</param>
        /// <param name="key">密钥</param>
        /// <returns>返回原文</returns>
        public static byte[] Decrypt<TSymmetricAlgorithm>(ArraySegment<byte> source, byte[] key) where TSymmetricAlgorithm : SymmetricAlgorithm
        {
            return GetOrCreateEncryptor(typeof(TSymmetricAlgorithm), key).Decrypt(source);
        }

        /// <summary>
        /// Create a key that specifies a symmetric algorithm.<br />
        /// 创建一个指定对称算法的密钥。
        /// </summary>
        /// <typeparam name="TSymmetricAlgorithm">对称算法</typeparam>
        /// <returns>返回密钥</returns>
        public static byte[] CreateKey<TSymmetricAlgorithm>()
        {
            return CreateInstance(typeof(TSymmetricAlgorithm)).Key;
        }

        sealed class EncryptorSet : IDisposable
        {
            readonly AlgorithmInfo _algorithmInfo;

            ThreadLocal<Encryptor> _threadLocal;

            DateTime _lastUse;

            public EncryptorSet(AlgorithmInfo algorithmInfo)
            {
                _algorithmInfo = algorithmInfo;
                _threadLocal = new ThreadLocal<Encryptor>(ValueFactory, true);

                _lastUse = DateTime.Now;

                DisposeCheckLoop();
            }

            Encryptor ValueFactory()
            {
                return new Encryptor(_algorithmInfo, () => _lastUse = DateTime.Now);
            }

            public Encryptor Value => _threadLocal.Value;

            public void Dispose()
            {
                var threadLocal = _threadLocal;

                _threadLocal = null;

                foreach (var encryptor in threadLocal.Values)
                {
                    encryptor.Dispose();
                }

                threadLocal.Dispose();
            }

            async void DisposeCheckLoop()
            {
                while (true)
                {
                    var timespan = _lastUse.AddMilliseconds(DisposeInterval) - DateTime.Now;

                    if (timespan.Ticks <= 0)
                    {
                        Encryptors.TryRemove(_algorithmInfo, out _);

                        Dispose();

                        break;
                    }
                    else
                    {
                        await Task.Delay(timespan);
                    }
                }
            }
        }

        sealed class Encryptor : IDisposable
        {
            readonly Action _useCallback;
            readonly SymmetricAlgorithm _symmetricAlgorithm;

            ICryptoTransform _decryptor;
            ICryptoTransform _encryptor;

            public Encryptor(AlgorithmInfo algorithmInfo, Action useCallback)
            {
                _useCallback = useCallback;
                _symmetricAlgorithm = CreateInstance(algorithmInfo.AlgorithmType);
                _symmetricAlgorithm.Key = algorithmInfo.Key;
            }

            public byte[] Encrypt(ArraySegment<byte> source)
            {
                _useCallback();

                return (_encryptor ??= _symmetricAlgorithm.CreateEncryptor()).TransformFinalBlock(source.Array!, source.Offset, source.Count);
            }

            public byte[] Decrypt(ArraySegment<byte> source)
            {
                _useCallback();

                return (_decryptor ??= _symmetricAlgorithm.CreateDecryptor()).TransformFinalBlock(source.Array!, source.Offset, source.Count);
            }

            public void Dispose()
            {
                _decryptor?.Dispose();
                _encryptor?.Dispose();

                _symmetricAlgorithm.Dispose();
            }
        }

        readonly struct AlgorithmInfo : IEquatable<AlgorithmInfo>
        {
            public readonly Type AlgorithmType;
            public readonly byte[] Key;

            public AlgorithmInfo(Type algorithmType, byte[] key)
            {
                AlgorithmType = algorithmType;
                Key = key;
            }

#if NETFRAMEWORK || NETSTANDARD2_0
            public bool Equals(AlgorithmInfo other)
#else
            public bool Equals([AllowNull] AlgorithmInfo other)
#endif
            {
                if (AlgorithmType != other.AlgorithmType)
                {
                    return false;
                }

                if (Key == other.Key)
                {
                    return true;
                }

                return Key.AsSpan().SequenceEqual(other.Key);
            }

            public override bool Equals(object obj)
            {
                if (obj is AlgorithmInfo other)
                {
                    return Equals(other);
                }

                return false;
            }

            public override int GetHashCode()
            {
                switch (Key.Length)
                {
                    case 0:
                        return AlgorithmType.GetHashCode();
                    case 1:
                    case 2:
                    case 3:
                        return (int) ((uint) AlgorithmType.GetHashCode() ^ (Unsafe.As<byte, uint>(ref Key[0]) & (~(uint.MaxValue << (Key.Length * 8)))));
                    default:
                        /* 如果密钥有固定的前缀，这个算法则不适用 */
                        return AlgorithmType.GetHashCode() ^ Unsafe.As<byte, int>(ref Key[0]);
                }
            }
        }
    }
}