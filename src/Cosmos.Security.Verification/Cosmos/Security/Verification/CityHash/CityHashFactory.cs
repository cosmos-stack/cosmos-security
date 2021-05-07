// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Verification
{
    public static class CityHashFactory
    {
        public static ICityHash Create(CityHashTypes type = CityHashTypes.CityHashBit32) => new CityHashFunction(type);
    }
}