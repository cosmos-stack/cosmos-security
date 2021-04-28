namespace Cosmos.Security.Verification
{
    public interface IStreamableHashFunction : IHashFunction, IStreamableHashAlgorithm
    {
        IBlockTransformer CreateBlockTransformer();
    }
}