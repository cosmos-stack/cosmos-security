namespace Cosmos.Security.Verification.MurmurHash
{
    public interface IMurmurHash<out TConfig> : IHashFunction
    {
        TConfig Config { get; }
    }

    public interface IStreamableMurmurHah<out TConfig> : IMurmurHash<TConfig>, IStreamableHashFunction { }
}