using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace ElfUT
{
    [Trait("ElfUT", "Elf64Tests")]
    public class Elf64Tests
    {
        [Theory(DisplayName = "ELF64")]
        [InlineData("image", "D5377000")]
        [InlineData("image0", "807D0307")]
        [InlineData("image1", "817D0307")]
        public void Elf64Test(string data, string hex)
        {
            var function = Elf64Factory.Create();
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }
    }
}