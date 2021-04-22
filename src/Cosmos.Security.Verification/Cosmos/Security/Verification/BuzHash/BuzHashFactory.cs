using Factory = Cosmos.Security.Verification.BuzHashFactory;

// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Verification
{
    /// <summary>
    /// Enumeration of possible directions a circular shift can be defined for.
    /// </summary>
    public enum CircularShiftDirection
    {
        /// <summary>
        /// Shift bits left.
        /// </summary>
        Left,

        /// <summary>
        /// Shift bits right.
        /// </summary>
        Right
    }

    public static class BuzHashFactory
    {
        public static BuzHashFunction Create(BuzHashTypes type = BuzHashTypes.BuzHashBit64)
        {
            return Create(type, BuzHashConfig.Default);
        }

        public static BuzHashFunction Create(BuzHashTypes type, BuzHashConfig config)
        {
            config.CheckNull(nameof(config));
            config = config.Clone();
            config.HashSizeInBits = (int) type;
            return new(config);
        }
    }
}