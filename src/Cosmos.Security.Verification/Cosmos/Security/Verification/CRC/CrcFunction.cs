using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using Cosmos.Security.Verification.Core;

namespace Cosmos.Security.Verification.CRC
{
    public class CrcFunction : StreamableHashFunctionBase
    {
        private readonly CrcTypes _crcType;
        private readonly CrcConfig _crcConfig;
        private static readonly ConcurrentDictionary<(int, UInt64, bool), IReadOnlyList<UInt64>> DataDivisionTableCache = new();

        internal CrcFunction(CrcTypes type)
        {
            _crcType = type;
            _crcConfig = CrcTable.Map(type);
        }

        public override int HashSizeInBits => _crcConfig.HashSizeInBits;

        public CrcTypes CrcType => _crcType;

        public override IBlockTransformer CreateBlockTransformer() => new CrcBlockTransformer(_crcConfig);

        #region Internal Implementation of BlockTransformer

        internal class CrcBlockTransformer : BlockTransformerBase<CrcBlockTransformer>
        {
            private int _hashSizeInBits;
            private IReadOnlyList<ulong> _crcTable;
            private int _mostSignificantShift;
            private bool _reflectIn;
            private bool _reflectOut;
            private ulong _xOrOut;

            private ulong _hashValue;

            public CrcBlockTransformer() { }

            public CrcBlockTransformer(CrcConfig config)
            {
                _hashSizeInBits = config.HashSizeInBits;
                _crcTable = GetDataDivisionTable(_hashSizeInBits, config.Polynomial, config.ReflectIn);

                // _mostSignificantShift
                {
                    // How much hash must be right-shifted to get the most significant byte (HashSize >= 8) or bit (HashSize < 8)
                    if (_hashSizeInBits < 8)
                        _mostSignificantShift = _hashSizeInBits - 1;
                    else
                        _mostSignificantShift = _hashSizeInBits - 8;
                }

                _reflectIn = config.ReflectIn;
                _reflectOut = config.ReflectOut;
                _xOrOut = config.XOrOut;


                // _hashValue
                {
                    var initialValue = config.InitialValue;

                    if (config.ReflectIn)
                        initialValue = ReflectBits(initialValue, _hashSizeInBits);

                    _hashValue = initialValue;
                }
            }


            protected override void CopyStateTo(CrcBlockTransformer other)
            {
                base.CopyStateTo(other);

                other._hashSizeInBits = _hashSizeInBits;
                other._crcTable = _crcTable;
                other._mostSignificantShift = _mostSignificantShift;
                other._reflectIn = _reflectIn;
                other._reflectOut = _reflectOut;
                other._xOrOut = _xOrOut;

                other._hashValue = _hashValue;
            }

            protected override void TransformByteGroupsInternal(ArraySegment<byte> data)
            {
                var dataArray = data.Array;
                var dataOffset = data.Offset;
                var endOffset = dataOffset + data.Count;

                var tempHashValue = _hashValue;

                var tempHashSizeInBits = _hashSizeInBits;
                var tempReflectIn = _reflectIn;
                var tempCrcTable = _crcTable;
                var tempMostSignificantShift = _mostSignificantShift;

                for (var currentOffset = dataOffset; currentOffset < endOffset; ++currentOffset)
                {
                    if (tempHashSizeInBits >= 8)
                    {
                        // Process per byte, treating hash differently based on input endianness
                        if (tempReflectIn)
                            tempHashValue = (tempHashValue >> 8) ^ tempCrcTable[(byte) tempHashValue ^ dataArray[currentOffset]];
                        else
                            tempHashValue = (tempHashValue << 8) ^ tempCrcTable[((byte) (tempHashValue >> tempMostSignificantShift)) ^ dataArray[currentOffset]];
                    }
                    else
                    {
                        // Process per bit, treating hash differently based on input endianness
                        for (var currentBit = 0; currentBit < 8; ++currentBit)
                        {
                            if (tempReflectIn)
                                tempHashValue = (tempHashValue >> 1) ^ tempCrcTable[(byte) (tempHashValue & 1) ^ ((byte) (dataArray[currentOffset] >> currentBit) & 1)];
                            else
                                tempHashValue = (tempHashValue << 1) ^ tempCrcTable[(byte) ((tempHashValue >> tempMostSignificantShift) & 1) ^ ((byte) (dataArray[currentOffset] >> (7 - currentBit)) & 1)];
                        }
                    }
                }

                _hashValue = tempHashValue;
            }

            protected override IHashValue FinalizeHashValueInternal(CancellationToken cancellationToken)
            {
                var finalHashValue = _hashValue;

                // Account for mixed-endianness
                if (_reflectIn ^ _reflectOut)
                    finalHashValue = ReflectBits(finalHashValue, _hashSizeInBits);


                finalHashValue ^= _xOrOut;

                return new HashValue(
                    ToBytes(finalHashValue, _hashSizeInBits),
                    _hashSizeInBits);
            }

            private static IReadOnlyList<ulong> GetDataDivisionTable(int hashSizeInBits, ulong polynomial, bool reflectIn)
            {
                return DataDivisionTableCache.GetOrAdd(
                    (hashSizeInBits, polynomial, reflectIn),
                    GetDataDivisionTableInternal);
            }

            private static IReadOnlyList<ulong> GetDataDivisionTableInternal((int, ulong, bool) cacheKey)
            {
                var hashSizeInBits = cacheKey.Item1;
                var polynomial = cacheKey.Item2;
                var reflectIn = cacheKey.Item3;


                var perBitCount = 8;

                if (hashSizeInBits < 8)
                    perBitCount = 1;


                var crcTable = new ulong[1 << perBitCount];
                var mostSignificantBit = 1UL << (hashSizeInBits - 1);


                for (uint x = 0; x < crcTable.Length; ++x)
                {
                    ulong curValue = x;

                    if (perBitCount > 1 && reflectIn)
                        curValue = ReflectBits(curValue, perBitCount);


                    curValue <<= (hashSizeInBits - perBitCount);


                    for (var y = 0; y < perBitCount; ++y)
                    {
                        if ((curValue & mostSignificantBit) > 0UL)
                            curValue = (curValue << 1) ^ polynomial;
                        else
                            curValue <<= 1;
                    }


                    if (reflectIn)
                        curValue = ReflectBits(curValue, hashSizeInBits);


                    curValue &= (ulong.MaxValue >> (64 - hashSizeInBits));

                    crcTable[x] = curValue;
                }


                return crcTable;
            }


            private static byte[] ToBytes(ulong value, int bitLength)
            {
                value &= (ulong.MaxValue >> (64 - bitLength));


                var valueBytes = new byte[(bitLength + 7) / 8];

                for (var x = 0; x < valueBytes.Length; ++x)
                {
                    valueBytes[x] = (byte) value;
                    value >>= 8;
                }

                return valueBytes;
            }

            private static ulong ReflectBits(ulong value, int bitLength)
            {
                var reflectedValue = 0UL;

                for (var x = 0; x < bitLength; ++x)
                {
                    reflectedValue <<= 1;

                    reflectedValue |= (value & 1);

                    value >>= 1;
                }

                return reflectedValue;
            }
        }

        #endregion
    }
}