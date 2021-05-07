using System;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    internal struct UInt128
    {
        public UInt64 Low { get; set; }
        public UInt64 High { get; set; }

        public UInt128(UInt64 low) : this(low, 0) { }

        public UInt128(UInt64 low, UInt64 high)
        {
            Low = low;
            High = high;
        }

        public static UInt128 operator +(UInt128 a, UInt128 b)
        {
            var carryOver = 0UL;
            var lowResult = unchecked(a.Low + b.Low);

            if (lowResult < a.Low)
                carryOver = 1UL;

            return new UInt128(lowResult, a.High + b.High + carryOver);
        }
    }
}