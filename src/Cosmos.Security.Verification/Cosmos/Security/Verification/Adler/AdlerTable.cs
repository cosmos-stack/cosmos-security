using System;

namespace Cosmos.Security.Verification.Adler
{
    internal static class AdlerTable
    {
        private static (int, uint, ulong, uint, int) Dict(AdlerTypes type)
        {
            return type switch
            {
                AdlerTypes.Adler32 => (32, 65521U, 0, 5552, 0),
                AdlerTypes.Adler64 => (64, 0, 4294967291, 363898415, 363898400),
                _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
            };
        }

        public static AdlerConfig Map(AdlerTypes type)
        {
            (int hashSize, uint mod32, ulong mod64, uint nMax, int maxPart) = Dict(type);

            return new AdlerConfig
            {
                HashSizeInBits = hashSize,
                Mod32 = mod32,
                Mod64 = mod64,
                NMax = nMax,
                MaxPart = maxPart
            };
        }
    }
}