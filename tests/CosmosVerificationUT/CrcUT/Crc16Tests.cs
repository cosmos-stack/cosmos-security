using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace CrcUT
{
    [Trait("CrcUT", "Crc16Tests")]
    public class Crc16Tests
    { 
        [Theory(DisplayName = "CRC-16/Ccitt")]
        [InlineData("Nice", "305A", "11000001011010", "0011000001011010")]
        [InlineData("Nice Boat", "9D94", "1001110110010100", "1001110110010100")]
        public void Crc16CcittTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16Ccitt);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/CcittFalse")]
        [InlineData("Nice", "862F", "1000011000101111", "1000011000101111")]
        [InlineData("Nice Boat", "FEAD", "1111111010101101", "1111111010101101")]
        public void Crc16CcittFalseTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16CcittFalse);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/ARC")]
        [InlineData("Nice", "2FEF", "10111111101111", "0010111111101111")]
        [InlineData("Nice Boat", "6D07", "110110100000111", "0110110100000111")]
        public void Crc16ArcTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16Arc);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/AUG-CCITT")]
        [InlineData("Nice", "56A5", "101011010100101", "0101011010100101")]
        [InlineData("Nice Boat", "8361", "1000001101100001", "1000001101100001")]
        public void Crc16AugCcittTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16AugCcitt);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/Buypass")]
        [InlineData("Nice", "7114", "111000100010100", "0111000100010100")]
        [InlineData("Nice Boat", "1B35", "1101100110101", "0001101100110101")]
        public void Crc16BuypassTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16Buypass);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/CDMA2000")]
        [InlineData("Nice", "9A28", "1001101000101000", "1001101000101000")]
        [InlineData("Nice Boat", "F571", "1111010101110001", "1111010101110001")]
        public void Crc16Cdma2000Test(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16Cdma2000);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/DDS-110")]
        [InlineData("Nice", "A914", "1010100100010100", "1010100100010100")]
        [InlineData("Nice Boat", "3C55", "11110001010101", "0011110001010101")]
        public void Crc16Dds110Test(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16Dds110);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/DECT-R")]
        [InlineData("Nice", "D2E3", "1101001011100011", "1101001011100011")]
        [InlineData("Nice Boat", "3E35", "11111000110101", "0011111000110101")]
        public void Crc16DectRTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16DectR);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/DECT-X")]
        [InlineData("Nice", "D3E3", "1101001111100011", "1101001111100011")]
        [InlineData("Nice Boat", "3F35", "11111100110101", "0011111100110101")]
        public void Crc16DectXTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16DectX);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/DNP")]
        [InlineData("Nice", "DEDD", "1101111011011101", "1101111011011101")]
        [InlineData("Nice Boat", "02D6", "1011010110", "0000001011010110")]
        public void Crc16DnpTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16Dnp);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/En13757")]
        [InlineData("Nice", "A758", "1010011101011000", "1010011101011000")]
        [InlineData("Nice Boat", "F423", "1111010000100011", "1111010000100011")]
        public void Crc16En13757Test(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16En13757);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/Genibus")]
        [InlineData("Nice", "79D0", "111100111010000", "0111100111010000")]
        [InlineData("Nice Boat", "0152", "101010010", "0000000101010010")]
        public void Crc16GenibusTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16Genibus);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/MAXIM")]
        [InlineData("Nice", "D010", "1101000000010000", "1101000000010000")]
        [InlineData("Nice Boat", "92F8", "1001001011111000", "1001001011111000")]
        public void Crc16MaximTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16Maxim);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/MCRF4XX")]
        [InlineData("Nice", "1159", "1000101011001", "0001000101011001")]
        [InlineData("Nice Boat", "85DA", "1000010111011010", "1000010111011010")]
        public void Crc16Mcrf4XxTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16Mcrf4Xx);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/Riello")]
        [InlineData("Nice", "567D", "101011001111101", "0101011001111101")]
        [InlineData("Nice Boat", "C4D6", "1100010011010110", "1100010011010110")]
        public void Crc16RielloTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16Riello);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/T10Dif")]
        [InlineData("Nice", "7C40", "111110001000000", "0111110001000000")]
        [InlineData("Nice Boat", "A7A0", "1010011110100000", "1010011110100000")]
        public void Crc16T10DifTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16T10Dif);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/Teledisk")]
        [InlineData("Nice", "A6B4", "1010011010110100", "1010011010110100")]
        [InlineData("Nice Boat", "3DC2", "11110111000010", "0011110111000010")]
        public void Crc16TelediskTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16Teledisk);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/Tms37157")]
        [InlineData("Nice", "EFA2", "1110111110100010", "1110111110100010")]
        [InlineData("Nice Boat", "A593", "1010010110010011", "1010010110010011")]
        public void Crc16Tms37157Test(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16Tms37157);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/USB")]
        [InlineData("Nice", "D034", "1101000000110100", "1101000000110100")]
        [InlineData("Nice Boat", "9808", "1001100000001000", "1001100000001000")]
        public void Crc16UsbTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16Usb);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/A")]
        [InlineData("Nice", "300C", "11000000001100", "0011000000001100")]
        [InlineData("Nice Boat", "110A", "1000100001010", "0001000100001010")]
        public void Crc16ATest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.CrcA);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/Kermit")]
        [InlineData("Nice", "305A", "11000001011010", "0011000001011010")]
        [InlineData("Nice Boat", "9D94", "1001110110010100", "1001110110010100")]
        public void Crc16KermitTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16Kermit);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/Modbus")]
        [InlineData("Nice", "2FCB", "10111111001011", "0010111111001011")]
        [InlineData("Nice Boat", "67F7", "110011111110111", "0110011111110111")]
        public void Crc16ModbusTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16Modbus);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }

        [Theory(DisplayName = "CRC-16/X25")]
        [InlineData("Nice", "EEA6", "1110111010100110", "1110111010100110")]
        [InlineData("Nice Boat", "7A25", "111101000100101", "0111101000100101")]
        public void Crc16X25Test(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16X25);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/Xmodem")]
        [InlineData("Nice", "46AB", "100011010101011", "0100011010101011")]
        [InlineData("Nice Boat", "8CB5", "1000110010110101", "1000110010110101")]
        public void Crc16XmodemTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16Xmodem);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
        
        [Theory(DisplayName = "CRC-16/IBM")]
        [InlineData("Nice", "2FEF", "10111111101111", "0010111111101111")]
        [InlineData("Nice Boat", "6D07", "110110100000111", "0110110100000111")]
        public void Crc16IbmTest(string data, string hex, string bin, string binWithZero)
        {
            var function = CrcFactory.Create(CrcTypes.Crc16Ibm);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
            hashVal.AsBinString().ShouldBe(bin);
            hashVal.AsBinString(true).ShouldBe(binWithZero);
        }
    }
}