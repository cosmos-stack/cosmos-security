using Factory = Cosmos.Security.Verification.CityHashFactory;

namespace Cosmos.Security.Verification
{
    public static class CityHash
    {
        public static ICityHash Create(CityHashTypes type = CityHashTypes.CityHashBit32) => Factory.Create(type);
    }
}