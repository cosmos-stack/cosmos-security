using Cosmos.Security.Verification.MessageDigest;
using Shouldly;
using Xunit;

namespace MdUT
{
    [Trait("MdUT", "Md6Tests")]
    public class Md6Tests
    {
        [Theory(DisplayName = "Md6")]
        [InlineData("image", "E913BFCA3B8F6D2DEB1A42AC8070AC568806203A74E35930B139ACEB0494E9A2")]
        [InlineData("Den boer and Bosselaers found pseudo-collisions in MD5", "A6B6548EAF94FF09254203E7C505F3BDA55FA871C8374B0022788C7D4845A37A")]
        public void Md6(string data, string hex)
        {
            var function = MdFactory.Create(MdTypes.Md6);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory(DisplayName = "Md6-bit128")]
        [InlineData("image", "C09B7A98DA44ECBD578A5B2B19A275E2")]
        [InlineData("Den boer and Bosselaers found pseudo-collisions in MD5", "C4C48FFC29D87656113E6741C7C5DAC4")]
        public void Md6Bit128(string data, string hex)
        {
            var function = MdFactory.Create(MdTypes.Md6Bit128);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory(DisplayName = "Md6-bit256")]
        [InlineData("image", "E913BFCA3B8F6D2DEB1A42AC8070AC568806203A74E35930B139ACEB0494E9A2")]
        [InlineData("Den boer and Bosselaers found pseudo-collisions in MD5", "A6B6548EAF94FF09254203E7C505F3BDA55FA871C8374B0022788C7D4845A37A")]
        public void Md6Bit256(string data, string hex)
        {
            var function = MdFactory.Create(MdTypes.Md6Bit256);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory(DisplayName = "Md6-bit512")]
        [InlineData("image", "32FA2838A6F538AF96DD6A57C5801F31A8A8365A3D87EF49A97B22BEA0AA6BA77C77F22355B5D843CFEC43A7A820DB2DA1F59CB687C728866D8E85A300F13533")]
        [InlineData("Den boer and Bosselaers found pseudo-collisions in MD5", "84A3B12F9C48F0B458D5D1BFECFD21C437AA7C54F0CD2F19E7576B4F83E450DD1BDDD7C6D800CE86EEC3761660E8C1349D97CEB834601022A6C5D8E6C86C66A4")]
        public void Md6Bit512(string data, string hex)
        {
            var function = MdFactory.Create(MdTypes.Md6Bit512);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }
    }
}