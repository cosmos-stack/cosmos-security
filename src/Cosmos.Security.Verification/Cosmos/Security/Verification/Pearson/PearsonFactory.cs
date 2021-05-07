// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Verification
{
    /// <summary>
    /// Pearson Hash Function Factory
    /// </summary>
    public static class PearsonFactory
    {
        public static IPearson Create() => Create(PearsonConfig.Default);

        public static IPearson Create(PearsonConfig config) => new PearsonFunction(config);
    }
}