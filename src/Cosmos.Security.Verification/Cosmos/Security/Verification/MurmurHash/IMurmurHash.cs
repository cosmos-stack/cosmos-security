// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Verification
{
    public interface IMurmurHash : IHashAlgorithm { }

    public interface IStreamableMurmurHash : IMurmurHash, IStreamableHashAlgorithm, IHashAlgorithm { }
}