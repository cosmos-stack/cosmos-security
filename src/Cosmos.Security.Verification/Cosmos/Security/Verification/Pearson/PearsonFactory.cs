// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    /// <summary>
    /// Pearson Hash Function Factory
    /// </summary>
    public static class PearsonFactory
    {
        public static PearsonFunction Create()
        {
            return Create(PearsonConfig.Default);
        }

        public static PearsonFunction Create(PearsonConfig config)
        {
            return new(config);
        }
    }
}