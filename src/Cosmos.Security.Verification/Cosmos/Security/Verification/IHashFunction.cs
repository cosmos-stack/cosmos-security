namespace Cosmos.Security.Verification
{
    public interface IHashFunction : IHashAlgorithm
    {
        int HashSizeInBits { get; }
    }
}