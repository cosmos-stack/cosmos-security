using Factory = Cosmos.Security.Verification.PearsonFactory;

namespace Cosmos.Security.Verification
{
    /// <summary>
    /// Pearson Hash Function Factory
    /// </summary>
    public static class Pearson
    {
        public static IPearson Create() => Factory.Create();

        public static IPearson Create(PearsonConfig config) => Factory.Create(config);
    }
}