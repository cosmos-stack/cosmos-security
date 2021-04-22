using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace FnvUT
{
    [Trait("FnvUT", "Fnv1aTests")]
    public class Fnv1aTests
    {
        [Theory]
        [InlineData("Alex Boy", "B306C224")]
        public void Fnv1_Bit32_Test(string data, string hex)
        {
            var function = FnvFactory.Create(FnvTypes.Fnv1aBit32);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Alex Boy", "B341E7F4253B7265")]
        public void Fnv1_Bit64_Test(string data, string hex)
        {
            var function = FnvFactory.Create(FnvTypes.Fnv1aBit64);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Alex Boy", "23BD776755AE669DA89A65538BB5069C")]
        public void Fnv1_Bit128_Test(string data, string hex)
        {
            var function = FnvFactory.Create(FnvTypes.Fnv1aBit128);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Alex Boy", "3328FD36A09FB3ADC6649ADE1BC147686780128EB588C011B19B95B5F8A539F6")]
        public void Fnv1_Bit256_Test(string data, string hex)
        {
            var function = FnvFactory.Create(FnvTypes.Fnv1aBit256);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Alex Boy", "EBADD43E020E01BE78051349D23DBB193269294BBEB7328979527C55B37ECBF1036B538C8EB41799638800E88708C1ACF5AFB1AB31D4E5A5A73FFB219A9F72C8")]
        public void Fnv1_Bit512_Test(string data, string hex)
        {
            var function = FnvFactory.Create(FnvTypes.Fnv1aBit512);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory]
        [InlineData("Alex Boy", "6B896311B2D832F3299C95020F1010D59F431E09B729F79AA5192942AD54AD875C55C0B30AD769DBE2C89F00000000000000000000000000000000000000000000000000000000000000000000000000000000000050BA947A30A1CDB966230ADA24F4BA9D99D0B29D5BFB86D4EF5199BAFE1A23D9FED4D63EBAFAD37717B20F")]
        public void Fnv1_Bit1024_Test(string data, string hex)
        {
            var function = FnvFactory.Create(FnvTypes.Fnv1aBit1024);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }
    }
}