// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Verification
{
    public interface IMurmurHashFunction<out TConfig> : IHashFunction
    {
        TConfig Config { get; }
    }

    public interface IStreamableMurmurHahFunction<out TConfig> : IMurmurHashFunction<TConfig>, IStreamableHashFunction { }
}