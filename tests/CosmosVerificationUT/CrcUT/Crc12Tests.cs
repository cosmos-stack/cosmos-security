using Cosmos.Security.Verification.CRC;
using Shouldly;
using Xunit;

namespace CrcUT
{
    [Trait("CrcUT", "Crc12Tests")]
    public class Crc12Tests
    {
        [Theory(DisplayName = "CRC-12/3GPP")]
        [InlineData("Nice", "4400", "100010000000000", "100010000000000")]
        [InlineData("Nice Boat", "750E", "111010100001110", "111010100001110")]
        public void Crc123gppTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc123Gpp);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }


        [Theory(DisplayName = "CRC-12/CDMA2000")]
        [InlineData("Nice", "3506", "11010100000110", "11010100000110")]
        [InlineData("Nice Boat", "D803", "1101100000000011", "1101100000000011")]
        public void Crc12Cdma2000Test(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc12Cdma2000);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }


        [Theory(DisplayName = "CRC-12/DECT")]
        [InlineData("Nice", "2002", "10000000000010", "10000000000010")]
        [InlineData("Nice Boat", "E70A", "1110011100001010", "1110011100001010")]
        public void Crc12DectTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc12Dect);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
    }
}