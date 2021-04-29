using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace CrcUT
{
    [Trait("CrcUT", "CRC-32")]
    public class Crc32Tests
    {
        [Theory(DisplayName = "CRC-32")]
        [InlineData("Nice", "0EAD816E", "1110101011011000000101101110", "00001110101011011000000101101110")]
        [InlineData("Nice Boat", "56634345", "1010110011000110100001101000101", "01010110011000110100001101000101")]
        public void Crc32Test(string data, string hax, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc32);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hax);
            hashVal.GetBinString().ShouldBe(bin);
            hashVal.GetBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-32/BZIP2")]
        [InlineData("Nice", "DD9FA03A", "11011101100111111010000000111010", "11011101100111111010000000111010")]
        [InlineData("Nice Boat", "AE0788FB", "10101110000001111000100011111011", "10101110000001111000100011111011")]
        public void Crc32BZip2Test(string data, string hax, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc32Bzip2);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hax);
            hashVal.GetBinString().ShouldBe(bin);
            hashVal.GetBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-32C")]
        [InlineData("Nice", "23B8BD8A", "100011101110001011110110001010", "00100011101110001011110110001010")]
        [InlineData("Nice Boat", "191A0494", "11001000110100000010010010100", "00011001000110100000010010010100")]
        public void Crc32CTest(string data, string hax, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc32C);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hax);
            hashVal.GetBinString().ShouldBe(bin);
            hashVal.GetBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-32D")]
        [InlineData("Nice", "685FC30A", "1101000010111111100001100001010", "01101000010111111100001100001010")]
        [InlineData("Nice Boat", "24C20D01", "100100110000100000110100000001", "00100100110000100000110100000001")]
        public void Crc32DTest(string data, string hax, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc32D);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hax);
            hashVal.GetBinString().ShouldBe(bin);
            hashVal.GetBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-32/Jamcrc")]
        [InlineData("Nice", "F1527E91", "11110001010100100111111010010001", "11110001010100100111111010010001")]
        [InlineData("Nice Boat", "A99CBCBA", "10101001100111001011110010111010", "10101001100111001011110010111010")]
        public void Crc32JamcrcTest(string data, string hax, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc32Jamcrc);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hax);
            hashVal.GetBinString().ShouldBe(bin);
            hashVal.GetBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-32/MPEG-2")]
        [InlineData("Nice", "22605FC5", "100010011000000101111111000101", "00100010011000000101111111000101")]
        [InlineData("Nice Boat", "51F87704", "1010001111110000111011100000100", "01010001111110000111011100000100")]
        public void Crc32Mpeg2Test(string data, string hax, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc32Mpeg2);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hax);
            hashVal.GetBinString().ShouldBe(bin);
            hashVal.GetBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-32/Posix")]
        [InlineData("Nice", "A642A4FD", "10100110010000101010010011111101", "10100110010000101010010011111101")]
        [InlineData("Nice Boat", "36685F71", "110110011010000101111101110001", "00110110011010000101111101110001")]
        public void Crc32PosixTest(string data, string hax, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc32Posix);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hax);
            hashVal.GetBinString().ShouldBe(bin);
            hashVal.GetBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-32Q")]
        [InlineData("Nice", "7B9A760E", "1111011100110100111011000001110", "01111011100110100111011000001110")]
        [InlineData("Nice Boat", "9D162B41", "10011101000101100010101101000001", "10011101000101100010101101000001")]
        public void Crc32QTest(string data, string hax, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc32Q);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hax);
            hashVal.GetBinString().ShouldBe(bin);
            hashVal.GetBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-32/Xfer")]
        [InlineData("Nice", "B8FFC861", "10111000111111111100100001100001", "10111000111111111100100001100001")]
        [InlineData("Nice Boat", "B82012FB", "10111000001000000001001011111011", "10111000001000000001001011111011")]
        public void Crc32XferTest(string data, string hax, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc32Xfer);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hax);
            hashVal.GetBinString().ShouldBe(bin);
            hashVal.GetBinString(true).ShouldBe(binWithZero);
        }
    }
}