using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace CrcUT
{
    [Trait("CrcUT", "Crc64Tests")]
    public class Crc64Tests
    {
        [Theory(DisplayName = "CRC-64")]
        [InlineData("Nice", "BC0FB53C8D18AA3F", "100001111110000010010101100001101110010111001110101010111000001", "0100001111110000010010101100001101110010111001110101010111000001")]
        [InlineData("Nice Boat", "CD59391188A237D3", "11001010100110110001101110111001110111010111011100100000101101", "0011001010100110110001101110111001110111010111011100100000101101")]
        public void Crc64Test(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc64);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-64/WE")]
        [InlineData("Nice", "93AAD490F5C053ED", "110110001010101001010110110111100001010001111111010110000010011", "0110110001010101001010110110111100001010001111111010110000010011")]
        [InlineData("Nice Boat", "80DAD4EB34249BDD", "111111100100101001010110001010011001011110110110110010000100011", "0111111100100101001010110001010011001011110110110110010000100011")]
        public void Crc64WeTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc64We);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }   
        
        [Theory(DisplayName = "CRC-64/XZ")]
        [InlineData("Nice", "2B94371EBF12B582", "10101110010100001101110001111010111111000100101011010110000010", "0010101110010100001101110001111010111111000100101011010110000010")]
        [InlineData("Nice Boat", "1EDD69088C935B13", "1111011011101011010010000100010001100100100110101101100010011", "0001111011011101011010010000100010001100100100110101101100010011")]
        public void Crc64XzTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc64Xz);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
    }
}