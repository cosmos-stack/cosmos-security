using Cosmos.Security.Verification.Core;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    /// <summary>
    /// SpookyHash Function Factory
    /// </summary>
    public class SpookyHashFactory
    {
        public static StreamableHashFunctionBase Create(SpookyHashTypes type = SpookyHashTypes.SpookyHash2Bit128)
        {
            return Create(type, new SpookyHashConfig());
        }

        public static StreamableHashFunctionBase Create(SpookyHashTypes type, SpookyHashConfig config)
        {
            config.CheckNull(nameof(config));
            config = config.Clone();
            config.HashSizeInBits = (int) type % 1000;
            return ((int) type / 1000) switch
            {
                1 => new SpookyHash1Function(config),
                2 => new SpookyHash2Function(config),
                _ => new SpookyHash2Function(config),
            };
        }
    }
}