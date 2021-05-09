namespace Cosmos.Security.Cryptography
{
    public interface IAsymmetricSignFunction : IAsymmetricSignAlgorithm
    {
        int KeySize { get; }
    }

    public interface IAsymmetricCryptoFunction : IAsymmetricSignFunction, IAsymmetricCryptoAlgorithm { }
}