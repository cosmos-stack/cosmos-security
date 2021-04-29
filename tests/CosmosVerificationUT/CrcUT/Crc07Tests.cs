using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace CrcUT
{
    [Trait("CrcUT", "CRC-07")]
    public class Crc07Tests
    {
        [Theory(DisplayName = "CRC-7")]
        [InlineData("N", "1A", "0011010")]
        [InlineData("Ni", "18", "0011000")]
        [InlineData("Nic", "66", "1100110")]
        [InlineData("Nice", "32", "0110010")]
        [InlineData("Nice ", "40", "1000000")]
        [InlineData("Nice B", "37", "0110111")]
        [InlineData("Nice Bo", "09", "0001001")]
        [InlineData("Nice Boa", "54", "1010100")]
        [InlineData("Nice Boat", "50", "1010000")]
        public void Crc7Test(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc7);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
            hashVal.GetBinString(true).ShouldBe(bin);
        }
        
        [Theory(DisplayName = "CRC-7/ROHC")]
        [InlineData("N", "4F", "1001111")]
        [InlineData("Ni", "3D", "0111101")]
        [InlineData("Nic", "5D", "1011101")]
        [InlineData("Nice", "25", "0100101")]
        [InlineData("Nice ", "55", "1010101")]
        [InlineData("Nice B", "72", "1110010")]
        [InlineData("Nice Bo", "2B", "0101011")]
        [InlineData("Nice Boa", "1C", "0011100")]
        [InlineData("Nice Boat", "34", "0110100")]
        public void Crc7RohcTest(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc7Rohc);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
            hashVal.GetBinString(true).ShouldBe(bin);
        }
        
        [Theory(DisplayName = "CRC-7/MMC")]
        [InlineData("N", "1A", "0011010")]
        [InlineData("Ni", "18", "0011000")]
        [InlineData("Nic", "66", "1100110")]
        [InlineData("Nice", "32", "0110010")]
        [InlineData("Nice ", "40", "1000000")]
        [InlineData("Nice B", "37", "0110111")]
        [InlineData("Nice Bo", "09", "0001001")]
        [InlineData("Nice Boa", "54", "1010100")]
        [InlineData("Nice Boat", "50", "1010000")]
        public void Crc7MmcTest(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc7Mmc);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
            hashVal.GetBinString(true).ShouldBe(bin);
        }
    }
}