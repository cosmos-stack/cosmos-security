using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace CrcUT
{
    [Trait("CrcUT", "CRC-05")]
    public class Crc05Tests
    {
        [Theory(DisplayName = "CRC-5/EPC")]
        [InlineData("N", "1F", "11111")]
        [InlineData("Ni", "0A", "01010")]
        [InlineData("Nic", "15", "10101")]
        [InlineData("Nice", "0F", "01111")]
        [InlineData("Nice ", "08", "01000")]
        [InlineData("Nice B", "12", "10010")]
        [InlineData("Nice Bo", "13", "10011")]
        [InlineData("Nice Boa", "0C", "01100")]
        [InlineData("Nice Boat", "10", "10000")]
        public void Crc5EpcTest(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc5Epc);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString(true).ShouldBe(bin);
        }
        
        [Theory(DisplayName = "CRC-5/ITU")]
        [InlineData("N", "1E", "11110")]
        [InlineData("Ni", "1D", "11101")]
        [InlineData("Nic", "09", "01001")]
        [InlineData("Nice", "0A", "01010")]
        [InlineData("Nice ", "07", "00111")]
        [InlineData("Nice B", "04", "00100")]
        [InlineData("Nice Bo", "1F", "11111")]
        [InlineData("Nice Boa", "09", "01001")]
        [InlineData("Nice Boat", "00", "00000")]
        public void Crc5ItuTest(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc5Itu);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString(true).ShouldBe(bin);
        }
        
        [Theory(DisplayName = "CRC-5/USB")]
        [InlineData("N", "0D", "01101")]
        [InlineData("Ni", "1F", "11111")]
        [InlineData("Nic", "02", "00010")]
        [InlineData("Nice", "0D", "01101")]
        [InlineData("Nice ", "10", "10000")]
        [InlineData("Nice B", "01", "00001")]
        [InlineData("Nice Bo", "08", "01000")]
        [InlineData("Nice Boa", "0B", "01011")]
        [InlineData("Nice Boat", "10", "10000")]
        public void Crc5UsbTest(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc5Usb);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString(true).ShouldBe(bin);
        }
    }
}