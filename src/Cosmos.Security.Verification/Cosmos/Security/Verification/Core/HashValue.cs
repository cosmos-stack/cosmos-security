using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Cosmos.Conversions;
using Cosmos.Optionals;

namespace Cosmos.Security.Verification.Core
{
    /// <summary>
    /// Hash value
    /// </summary>
    public class HashValue : IHashValue
    {
        public HashValue(IEnumerable<byte> hash, int bitLength)
        {
            if (hash is null)
                throw new ArgumentNullException(nameof(hash));
            if (bitLength < 1)
                throw new ArgumentOutOfRangeException(nameof(bitLength), $"{nameof(bitLength)} must be greater than or equal to 1.");
            Hash = ForceConvertToArray(hash, bitLength);
            BitLength = bitLength;
        }

        public int BitLength { get; }

        public byte[] Hash { get; }

        public BitArray AsBitArray()
        {
            return new(Hash)
            {
                Length = BitLength
            };
        }

        public string AsHexString()
        {
            return AsHexString(false);
        }

        public string AsHexString(bool uppercase)
        {
            var stringBuilder = new StringBuilder(Hash.Length);
            var formatString = uppercase ? "X2" : "x2";

            foreach (var byteValue in Hash)
                stringBuilder.Append(byteValue.ToString(formatString));

            return stringBuilder.ToString();
        }

        public string AsBinString()
        {
            return AsBinString(false);
        }

        public string AsBinString(bool complementZero)
        {
            var result = Conversions.ScaleConv.HexToBin(AsHexString());

            if (complementZero == false || result.Length == BitLength)
                return result;

            return result.PadLeft(BitLength, '0');
        }

        public string AsBase64String()
        {
            return BaseConv.ToBase64(Hash);
        }

        public string AsString()
        {
            return AsString(Encoding.UTF8);
        }

        public string AsString(Encoding encoding)
        {
            return encoding.SafeEncodingValue().GetString(Hash);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = 17;

                hashCode = (hashCode * 31) ^ BitLength.GetHashCode();

                foreach (var value in Hash)
                    hashCode = (hashCode * 31) ^ value.GetHashCode();

                return hashCode;
            }
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as IHashValue);
        }

        public bool Equals(IHashValue other)
        {
            if (other == null || other.BitLength != BitLength)
                return false;

            return Hash.SequenceEqual(other.Hash);
        }

        private static byte[] ForceConvertToArray(IEnumerable<byte> hash, int bitLength)
        {
            var byteLength = (bitLength + 7) / 8;

            if ((bitLength % 8) == 0)
            {
                if (hash is IReadOnlyCollection<byte> hashByteCollection)
                {
                    if (hashByteCollection.Count == byteLength)
                        return hash.ToArray();
                }

                if (hash is byte[] hashByteArray)
                {
                    var newHashArray = new byte[byteLength];
                    {
                        Array.Copy(hashByteArray, newHashArray, Math.Min(byteLength, hashByteArray.Length));
                    }

                    return newHashArray;
                }
            }


            byte finalByteMask = (byte) ((1 << (bitLength % 8)) - 1);
            {
                if (finalByteMask == 0)
                    finalByteMask = 255;
            }


            var coercedArray = new byte[byteLength];

            var currentIndex = 0;
            using var hashEnumerator = hash.GetEnumerator();

            while (currentIndex < byteLength && hashEnumerator.MoveNext())
            {
                if (currentIndex == (byteLength - 1))
                    coercedArray[currentIndex] = (byte) (hashEnumerator.Current & finalByteMask);
                else
                    coercedArray[currentIndex] = hashEnumerator.Current;


                currentIndex += 1;
            }

            return coercedArray;
        }
    }
}