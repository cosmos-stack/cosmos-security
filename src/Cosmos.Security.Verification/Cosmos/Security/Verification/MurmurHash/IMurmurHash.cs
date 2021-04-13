// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public interface IMurmurHash<out TConfig> : IHashFunction
    {
        TConfig Config { get; }
    }

    public interface IStreamableMurmurHah<out TConfig> : IMurmurHash<TConfig>, IStreamableHashFunction { }
}