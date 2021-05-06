// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Verification
{
    public static class FnvFactory
    {
        public static IFNV Create(FnvTypes type = FnvTypes.Fnv1aBit64)
        {
            return Create(type, FnvConfig.GetPredefinedConfig((int) type % 10000));
        }

        public static IFNV Create(FnvTypes type, FnvConfig config)
        {
            config.CheckNull(nameof(config));
            config = config.Clone();

            if ((int) type % 10000 != config.HashSizeInBits)
                config = FnvConfig.GetPredefinedConfig((int) type % 10000);

            return ((int) type / 10000) switch
            {
                1 => new Fnv1Function(config),
                2 => new Fnv1AFunction(config),
                _ => new Fnv1AFunction(config)
            };
        }
    }
}