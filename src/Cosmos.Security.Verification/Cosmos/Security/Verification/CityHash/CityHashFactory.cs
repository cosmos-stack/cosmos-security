// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Verification
{
    public static class CityHashFactory
    {
        public static CityHashFunction Create(CityHashTypes type = CityHashTypes.CityHashBit32) => new(type);
    }
}