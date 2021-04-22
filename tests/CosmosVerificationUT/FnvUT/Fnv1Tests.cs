using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace FnvUT
{
    [Trait("FnvUT", "Fnv1Tests")]
    public class Fnv1Tests
    {
        [Theory]
        [InlineData("Alex Boy", "471156ED")]
        public void Fnv1_Bit32_Test(string data, string hex)
        {
            var function = FnvFactory.Create(FnvTypes.Fnv1Bit32);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Alex Boy", "C70C4742BC247CF9")]
        public void Fnv1_Bit64_Test(string data, string hex)
        {
            var function = FnvFactory.Create(FnvTypes.Fnv1Bit64);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Alex Boy", "372B35EF2BF768CE5A9965376A1E26FB")]
        public void Fnv1_Bit128_Test(string data, string hex)
        {
            var function = FnvFactory.Create(FnvTypes.Fnv1Bit128);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Alex Boy", "C7D565CC31ACEB5C68619ADE1BC147686780128EB55CA02456830C9D8A9239F6")]
        public void Fnv1_Bit256_Test(string data, string hex)
        {
            var function = FnvFactory.Create(FnvTypes.Fnv1Bit256);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Alex Boy", "B78B2CF3D928CADB1C081349D23DBB193269294BBEB7328979527C55B37ECBF1036B538C8EB41799638800ECCA98A24BC3E575BB31D4E5A5A73FFB219A9F72C8")]
        public void Fnv1_Bit512_Test(string data, string hex)
        {
            var function = FnvFactory.Create(FnvTypes.Fnv1Bit512);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Alex Boy", "D38C74D01124D6E9F69395020F1010D59F431E09B729F79AA5192942AD54AD875C55C0B30AD769DBE2C89F000000000000000000000000000000000000000000000000000000000000000000000000000000000000E4DC272B734021683C230ADA24F4BA9D99D0B29D5BFB86D4EF5199BAFE1A23D9FED4D63EBAFAD37717B20F")]
        public void Fnv1_Bit1024_Test(string data, string hex)
        {
            var function = FnvFactory.Create(FnvTypes.Fnv1Bit1024);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }
    }
}