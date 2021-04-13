using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace CrcUT
{
    [Trait("CrcUT", "Crc08Tests")]
    public class Crc08Tests
    {
        [Theory(DisplayName = "CRC-8")]
        [InlineData("Nice", "56", "01010110")]
        [InlineData("Nice Boat", "4B", "01001011")]
        public void Crc8Tests(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc8);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString(true).ShouldBe(bin);
        }

        [Theory(DisplayName = "CRC-8/CDMA2000")]
        [InlineData("Nice", "42", "01000010")]
        [InlineData("Nice Boat", "90", "10010000")]
        public void Crc8Cdma2000Tests(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc8Cdma2000);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString(true).ShouldBe(bin);
        }

        [Theory(DisplayName = "CRC-8/DARC")]
        [InlineData("Nice", "94", "10010100")]
        [InlineData("Nice Boat", "28", "00101000")]
        public void Crc8DarcTests(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc8Darc);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString(true).ShouldBe(bin);
        }

        [Theory(DisplayName = "CRC-8/DVB-S2")]
        [InlineData("Nice", "ED", "11101101")]
        [InlineData("Nice Boat", "AA", "10101010")]
        public void Crc8DvbS2Tests(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc8DvbS2);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString(true).ShouldBe(bin);
        }

        [Theory(DisplayName = "CRC-8/EUB")]
        [InlineData("Nice", "7B", "01111011")]
        [InlineData("Nice Boat", "49", "01001001")]
        public void Crc8EubTests(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc8Ebu);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString(true).ShouldBe(bin);
        }

        [Theory(DisplayName = "CRC-8/I-CODE")]
        [InlineData("Nice", "85", "10000101")]
        [InlineData("Nice Boat", "A6", "10100110")]
        public void Crc8ICodeTests(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc8ICode);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString(true).ShouldBe(bin);
        }

        [Theory(DisplayName = "CRC-8/Itu")]
        [InlineData("Nice", "03", "00000011")]
        [InlineData("Nice Boat", "1E", "00011110")]
        public void Crc8ItuTests(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc8Itu);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString(true).ShouldBe(bin);
        }

        [Theory(DisplayName = "CRC-8/MAXIM")]
        [InlineData("Nice", "8B", "10001011")]
        [InlineData("Nice Boat", "59", "01011001")]
        public void Crc8DMaximTests(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc8Maxim);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString(true).ShouldBe(bin);
        }

        [Theory(DisplayName = "CRC-8/ROHC")]
        [InlineData("Nice", "CF", "11001111")]
        [InlineData("Nice Boat", "21", "00100001")]
        public void Crc8RohcTests(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc8Rohc);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString(true).ShouldBe(bin);
        }

        [Theory(DisplayName = "CRC-8/WCDMA")]
        [InlineData("Nice", "5A", "01011010")]
        [InlineData("Nice Boat", "A0", "10100000")]
        public void Crc8WcdmaTests(string data, string hex, string bin)
        {
            var function = CrcFactory.Create(CrcTypes.Crc8Wcdma);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString(true).ShouldBe(bin);
        }
    }
}