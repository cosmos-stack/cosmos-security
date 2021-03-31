using Cosmos.Security.Verification.CRC;
using Shouldly;
using Xunit;

namespace CrcUT
{
    [Trait("CrcUT", "CRC-06")]
    public class Crc06Tests
    {
        [Theory(DisplayName = "CRC-6/CDMA2000-A")]
        [InlineData("N", "19", "011001")]
        [InlineData("Ni", "1F", "011111")]
        [InlineData("Nic", "2C", "101100")]
        [InlineData("Nice", "19", "011001")]
        [InlineData("Nice ", "3A", "111010")]
        [InlineData("Nice B", "0E", "001110")]
        [InlineData("Nice Bo", "2E", "101110")]
        [InlineData("Nice Boa", "21", "100001")]
        [InlineData("Nice Boat", "3F", "111111")]
        public void Crc6Cdma2000ATest(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc6Cdma2000A);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString(true).ShouldBe(bin);
        }
        
        [Theory(DisplayName = "CRC-6/CDMA2000-B")]
        [InlineData("N", "3A", "111010")]
        [InlineData("Ni", "2D", "101101")]
        [InlineData("Nic", "1D", "011101")]
        [InlineData("Nice", "30", "110000")]
        [InlineData("Nice ", "16", "010110")]
        [InlineData("Nice B", "01", "000001")]
        [InlineData("Nice Bo", "0D", "001101")]
        [InlineData("Nice Boa", "39", "111001")]
        [InlineData("Nice Boat", "1D", "011101")]
        public void Crc6Cdma2000BTest(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc6Cdma2000B);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString(true).ShouldBe(bin);
        }
        
        [Theory(DisplayName = "CRC-6/DARC")]
        [InlineData("N", "1B", "011011")]
        [InlineData("Ni", "24", "100100")]
        [InlineData("Nic", "17", "010111")]
        [InlineData("Nice", "24", "100100")]
        [InlineData("Nice ", "1F", "011111")]
        [InlineData("Nice B", "31", "110001")]
        [InlineData("Nice Bo", "2A", "101010")]
        [InlineData("Nice Boa", "36", "110110")]
        [InlineData("Nice Boat", "3A", "111010")]
        public void Crc6DarcTest(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc6Darc);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString(true).ShouldBe(bin);
        }
        
        [Theory(DisplayName = "CRC-6/ITU")]
        [InlineData("N", "02", "000010")]
        [InlineData("Ni", "2B", "101011")]
        [InlineData("Nic", "1B", "011011")]
        [InlineData("Nice", "08", "001000")]
        [InlineData("Nice ", "0F", "001111")]
        [InlineData("Nice B", "3E", "111110")]
        [InlineData("Nice Bo", "0A", "001010")]
        [InlineData("Nice Boa", "2B", "101011")]
        [InlineData("Nice Boat", "10", "010000")]
        public void Crc6ItuTest(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc6Itu);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString(true).ShouldBe(bin);
        }
    }
}