namespace Cosmos.Security.Cryptography
{
    public interface ISymmetricCryptoFunction : ISymmetricCryptoAlgorithm
    {
        int KeySize { get; }
    }
}