using System;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public static class MetroHashFactory
    {
        public static IMetroHash Create(MetroHashTypes type = MetroHashTypes.MetroHashBit64)
        {
            return Create(type, new MetroHashConfig());
        }

        public static IMetroHash Create(MetroHashTypes type, MetroHashConfig config)
        {
            if (config is null)
                throw new ArgumentNullException(nameof(config));

            return type switch
            {
                MetroHashTypes.MetroHashBit64 => new MetroHash064Function(config),
                MetroHashTypes.MetroHashBit128 => new MetroHash128Function(config),
                _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
            };
        }
    }
}