using Factory = Cosmos.Security.Cryptography.CeaserFactory;

namespace Cosmos.Security.Cryptography
{
    public static class Ceaser
    {
        public static ICeaser Create(int key) => Factory.Create(key);
    }
}