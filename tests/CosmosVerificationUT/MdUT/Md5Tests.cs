using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace MdUT
{
    [Trait("MdUT", "Md5Tests")]
    public class Md5Tests
    {
        [Theory(DisplayName = "Md5")]
        [InlineData("image", "78805A221A988E79EF3F42D7C5BFD418")]
        [InlineData("Den boer and Bosselaers found pseudo-collisions in MD5", "ADBCBF01745222BD0228352A0863AE3D")]
        public void Md5(string data, string hex)
        {
            var function = MdFactory.Create(MdTypes.Md5);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }

        [Theory(DisplayName = "Md5_bit16")]
        [InlineData("image", "1A988E79EF3F42D7")]
        [InlineData("Den boer and Bosselaers found pseudo-collisions in MD5", "745222BD0228352A")]
        public void Md5_bit16(string data, string hex)
        {
            var function = MdFactory.Create(MdTypes.Md5Bit16);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }

        [Theory(DisplayName = "Md5_bit32")]
        [InlineData("image", "78805A221A988E79EF3F42D7C5BFD418")]
        [InlineData("Den boer and Bosselaers found pseudo-collisions in MD5", "ADBCBF01745222BD0228352A0863AE3D")]
        public void Md5_bit32(string data, string hex)
        {
            var function = MdFactory.Create(MdTypes.Md5Bit32);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
        }

        [Theory(DisplayName = "Md5_bit64")]
        [InlineData("image", "65494261496871596A6E6E7650304C5878622F5547413D3D", "eIBaIhqYjnnvP0LXxb/UGA==")]
        [InlineData("kaka123", "58515576486A4B76546B72435645706677716D356B673D3D", "XQUvHjKvTkrCVEpfwqm5kg==")]
        [InlineData("Den boer and Bosselaers found pseudo-collisions in MD5", "7262792F41585253497230434B44557143474F7550513D3D", "rby/AXRSIr0CKDUqCGOuPQ==")]
        public void Md5_bit64(string data, string hex, string base64Val)
        {
            var function = MdFactory.Create(MdTypes.Md5Bit64);
            var hashVal = function.ComputeHash(data);
            hashVal.GetHexString(true).ShouldBe(hex);
            hashVal.GetString().ShouldBe(base64Val);
        }
    }
}