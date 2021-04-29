namespace Cosmos.Security.Cryptography
{
    public interface ISymmetricCryptoKey : ICryptoKey
    {
        /// <summary>
        /// Key
        /// </summary>
        byte[] Key { get; }

        /// <summary>
        /// Size of key
        /// </summary>
        int Size { get; }
    }

    public interface ISymmetricCryptoKeyWithInitializationVector : ISymmetricCryptoKey
    {
        /// <summary>
        /// Initialization Vector
        /// </summary>
        byte[] IV { get; }
    }
}