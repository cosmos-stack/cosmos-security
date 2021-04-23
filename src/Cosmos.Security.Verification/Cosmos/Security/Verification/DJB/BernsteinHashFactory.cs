using Cosmos.Security.Verification.Core;

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public static class BernsteinHashFactory
    {
        public static StreamableHashFunctionBase Create(BernsteinHashTypes type = BernsteinHashTypes.Time33)
        {
            return type switch
            {
                BernsteinHashTypes.Time33 => new Time33Function(),
                BernsteinHashTypes.BernsteinHash => new BernsteinHashFunction(),
                BernsteinHashTypes.ModifiedBernsteinHash => new ModifiedBernsteinHashFunction(),
                _ => new BernsteinHashFunction()
            };
        }
    }
}