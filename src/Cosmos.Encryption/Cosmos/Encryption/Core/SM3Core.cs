using System;
using System.Security.Cryptography;

/*
 * Reference to:
 *      SM3CryptographicHashAlgorithm
 *      URL: https://github.com/GlitterX/SM3CryptographicHashAlgorithm
 *      Author: GlitterX
 *      MIT
 */

// ReSharper disable InconsistentNaming
namespace Cosmos.Encryption.Core {
    internal class SM3Core : HashAlgorithm {
        /// <summary>
        ///     哈希值大小（以字节数为单位）
        /// </summary>
        public const int HashSizeInBytes = 32;

        /// <summary>
        ///     分组块大小（以字节数为单位）
        /// </summary>
        public const int GroupBlockSizeInBytes = 64;

        /// <summary>
        ///     初始状态向量
        /// </summary>
        private static readonly uint[] IV =
            {0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E};

        /// <summary>
        ///     填充数据
        /// </summary>
        private static readonly byte[] SM3Padding = {
            0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };

        /// <summary>
        ///     4字节数据单元存储器
        /// </summary>
        private readonly byte[] _m = new byte[4];

        /// <summary>
        ///     当前状态向量
        /// </summary>
        private readonly uint[] _v = new uint[8];

        /// <summary>
        ///     内部数据缓冲区
        /// </summary>
        private readonly uint[] _w = new uint[68];

        /// <summary>
        ///     已处理的字节计数
        /// </summary>
        private ulong _bytesCount;

        /// <summary>
        ///     缓冲区M存储位置偏移量
        /// </summary>
        private int _mOff;

        /// <summary>
        ///     缓冲区X存储位置偏移量
        /// </summary>
        private int _wOff;

        /// <summary>
        ///     构造函数
        /// </summary>
        public SM3Core() {
            Initialize();
        }

        /// <summary>
        ///     拷贝构造函数
        /// </summary>
        /// <param name="source">要复制的对象实例</param>
        public SM3Core(SM3Core source) {
            _bytesCount = source._bytesCount;
            _wOff = source._wOff;
            if (_wOff > 0) {
                Array.Copy(source._w, _w, _wOff);
            }

            _mOff = source._mOff;
            if (_mOff > 0) {
                Array.Copy(source._m, _m, _mOff);
            }

            // 拷贝状态向量
            Array.Copy(source._v, _v, _v.Length);
        }

        /// <summary>
        ///     算法名称
        /// </summary>
        public string AlgorithmName => "SM3";

        /// <summary>
        ///     哈希值大小（以位为单位）
        /// </summary>
        public new int HashSize => 256;

        /// <summary>
        ///     创建 SM3 的默认实现的实例
        /// </summary>
        /// <returns>SM3 的新实例</returns>
        public new static SM3Core Create() {
            return new SM3Core();
        }

        /// <summary>
        ///     创建 SM3 的指定实现的实例
        /// </summary>
        /// <param name="hashName">要使用的 SM3 的特定实现的名称，支持的值有"SM3"、"System.Security.Cryptography.SM3"</param>
        /// <returns>使用指定实现的 SM3 的新实例</returns>
        public new static SM3Core Create(string hashName) {
            if (string.Equals(hashName, "SM3", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(hashName, "System.Security.Cryptography.SM3", StringComparison.OrdinalIgnoreCase)) {
                return new SM3Core();
            }

            return null;
        }

        /// <summary>
        ///     类初始化
        /// </summary>
        public sealed override void Initialize() {
            _bytesCount = 0;
            _wOff = 0;
            _mOff = 0;

            // 初始化状态向量
            Array.Copy(IV, _v, _v.Length);

            // 清除敏感数据
            Array.Clear(_w, 0, _w.Length);
        }

        /// <summary>
        ///     将数据路由到哈希算法以计算哈希值
        /// </summary>
        /// <param name="input">要计算其哈希代码的输入</param>
        /// <param name="offset">字节数组中的偏移量，从该位置开始使用数据</param>
        /// <param name="length">字节数组中用作数据的字节数</param>
        protected override void HashCore(byte[] input, int offset, int length) {
            while (_mOff != 0 && length > 0) {
                Update(input[offset]);
                offset++;
                length--;
            }

            while (length >= 4) {
                ProcessWord(input, offset);
                offset += 4;
                length -= 4;
                _bytesCount += 4;
            }

            while (length > 0) {
                Update(input[offset]);
                offset++;
                length--;
            }
        }

        /// <summary>
        ///     完成最终计算，并返回数据流的正确哈希值
        /// </summary>
        /// <returns>计算所得的哈希代码</returns>
        protected override byte[] HashFinal() {
            Finish();
            var output = new byte[32];
            var i = 0;
            foreach (var n in _v) {
                output[i++] = (byte) (n >> 24);
                output[i++] = (byte) (n >> 16);
                output[i++] = (byte) (n >> 8);
                output[i++] = (byte) (n & 0xFF);
            }

            Initialize();
            return output;
        }

        /// <summary>
        ///     处理单个数据
        /// </summary>
        /// <param name="input">输入的单字节数据</param>
        private void Update(byte input) {
            _m[_mOff++] = input;
            if (_mOff == 4) {
                ProcessWord(_m, 0);
                _mOff = 0;
            }

            _bytesCount++;
        }

        /// <summary>
        ///     处理批量数据
        /// </summary>
        /// <param name="input">包含输入数据的字节数组</param>
        /// <param name="offset">数据在字节数组中的起始偏移量</param>
        /// <param name="length">数据长度</param>
        public void BlockUpdate(byte[] input, int offset, int length) {
            HashCore(input, offset, length);
        }

        /// <summary>
        ///     处理批量数据
        /// </summary>
        /// <param name="input">包含输入数据的字节数组</param>
        public void BlockUpdate(byte[] input) {
            HashCore(input, 0, input.Length);
        }

        /// <summary>
        ///     完成最终计算，并返回数据流的正确哈希值
        /// </summary>
        /// <returns>计算所得的哈希代码</returns>
        public byte[] DoFinal() {
            return HashFinal();
        }

        /// <summary>
        ///     完成最终计算，并返回数据流的正确哈希值
        /// </summary>
        /// <param name="input">包含输入数据的字节数组</param>
        /// <param name="offset">数据在字节数组中的起始偏移量</param>
        /// <param name="length">数据长度</param>
        /// <returns>计算所得的哈希代码</returns>
        public byte[] DoFinal(byte[] input, int offset, int length) {
            HashCore(input, offset, length);
            return HashFinal();
        }

        /// <summary>
        ///     完成最终计算，并返回数据流的正确哈希值
        /// </summary>
        /// <param name="input">包含输入数据的字节数组</param>
        /// <returns>计算所得的哈希代码</returns>
        public byte[] DoFinal(byte[] input) {
            HashCore(input, 0, input.Length);
            return HashFinal();
        }

        private void ProcessWord(byte[] input, int offset) {
            _w[_wOff++] = (uint) ((input[offset] << 24) | (input[offset + 1] << 16) | (input[offset + 2] << 8) |
                                  input[offset + 3]);
            if (_wOff == 16) {
                ProcessBlock();
            }
        }

        private void ProcessBlock() {
            var w1 = new uint[64];

            // 消息扩展（生成132个4字节数据）
            // a：将消息分组B(i)划分为16个4字节整型数据

            // b：W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL(W[j-3],15)) ^ ROTL(W[j - 13],7) ^ W[j-6]
            for (var j = 16; j < 68; j++) {
                _w[j] = P1(_w[j - 16] ^ _w[j - 9] ^ Rotl(_w[j - 3], 15)) ^ Rotl(_w[j - 13], 7) ^ _w[j - 6];
            }

            // c：W1[j] = W[j] ^ W[j+4]
            for (var j = 0; j < 64; j++) {
                w1[j] = _w[j] ^ _w[j + 4];
            }

            // 压缩函数
            var a = _v[0];
            var b = _v[1];
            var c = _v[2];
            var d = _v[3];
            var e = _v[4];
            var f = _v[5];
            var g = _v[6];
            var h = _v[7];
            for (var j = 0; j < 16; j++) {
                var q = Rotl(a, 12);
                var ss1 = Rotl(q + e + Rotl(0x79CC4519, j), 7);
                var ss2 = ss1 ^ q;
                var tt1 = FF0(a, b, c) + d + ss2 + w1[j];
                var tt2 = GG0(e, f, g) + h + ss1 + _w[j];
                d = c;
                c = Rotl(b, 9);
                b = a;
                a = tt1;
                h = g;
                g = Rotl(f, 19);
                f = e;
                e = P0(tt2);
            }

            for (var j = 16; j < 64; j++) {
                var q = Rotl(a, 12);
                var ss1 = Rotl(q + e + Rotl(0x7A879D8A, j), 7);
                var ss2 = ss1 ^ q;
                var tt1 = FF1(a, b, c) + d + ss2 + w1[j];
                var tt2 = GG1(e, f, g) + h + ss1 + _w[j];
                d = c;
                c = Rotl(b, 9);
                b = a;
                a = tt1;
                h = g;
                g = Rotl(f, 19);
                f = e;
                e = P0(tt2);
            }

            _v[0] ^= a;
            _v[1] ^= b;
            _v[2] ^= c;
            _v[3] ^= d;
            _v[4] ^= e;
            _v[5] ^= f;
            _v[6] ^= g;
            _v[7] ^= h;

            // 重置缓冲区
            _wOff = 0;
        }

        private void Finish() {
            // 计算实际消息比特长度
            var bitsLength = _bytesCount << 3;

            // 计算填充字节数
            var leftBytes = (_wOff << 2) + _mOff;
            var paddingBytes = leftBytes < 56 ? 56 - leftBytes : 120 - leftBytes;

            // 加入填充数据块
            HashCore(SM3Padding, 0, paddingBytes);

            // 加入实际消息比特长度
            var l = BitConverter.GetBytes(bitsLength);
            Array.Reverse(l);
            HashCore(l, 0, 8);
        }

        // 四字节无符号整数位循环左移位操作
        private static uint Rotl(uint x, int n) {
            return (x << n) | (x >> (32 - n));
        }

        // 布尔函数
        private uint FF0(uint x, uint y, uint z) {
            return x ^ y ^ z;
        }

        private uint FF1(uint x, uint y, uint z) {
            return (x & y) | (x & z) | (y & z);
        }

        private uint GG0(uint x, uint y, uint z) {
            return x ^ y ^ z;
        }

        private uint GG1(uint x, uint y, uint z) {
            return (x & y) | (~x & z);
        }

        // 置换函数
        private uint P0(uint x) {
            return x ^ Rotl(x, 9) ^ Rotl(x, 17);
        }

        private uint P1(uint x) {
            return x ^ Rotl(x, 15) ^ Rotl(x, 23);
        }
    }
}