

// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
{
    public static class BernsteinHashFactory
    {
        public static IBernsteinHash Create(BernsteinHashTypes type = BernsteinHashTypes.Time33)
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