using Cosmos.Security.Verification;
using Shouldly;
using Xunit;

namespace HmacUT
{
    [Trait("HmacUT", "HmacTests")]
    public class HmacTests
    {
        [Theory(DisplayName = "HMAC/MD5")]
        [InlineData("image", "alexinea", "C970FEC14C50EF84E1480EA2746BBA58")]
        [InlineData("image0", "alexinea", "12DDFC8D78E938EC57856080DC31B325")]
        [InlineData("image1", "alexinea", "0DFD3A335B240A1B76D70FF5A7208D5B")]
        public void HmacMd5Test(string data, string key, string hex)
        {
            var function = HmacFactory.Create(HmacTypes.HmacMd5, key);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory(DisplayName = "HMAC/SHA1")]
        [InlineData("image", "alexinea", "0E5CF78AECFE44262169BB15003F97443E9DDFE3")]
        [InlineData("image0", "alexinea", "C2D38A4C602AF3ED2D1CFFAC24A692233CF31E33")]
        [InlineData("image1", "alexinea", "05D4B70FD5C54A9271F74B013E99E040815693C7")]
        public void HmacSha1Test(string data, string key, string hex)
        {
            var function = HmacFactory.Create(HmacTypes.HmacSha1, key);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory(DisplayName = "HMAC/Sha256")]
        [InlineData("image", "alexinea", "8A51972243A890448E2054424D09EC87F68DEE753CA4EF64A4907107F1EF7917")]
        [InlineData("image0", "alexinea", "6C9DF97C39913C720D62B02B8450CA2CBAE2BB91722BF04F4C5147992BCCABFF")]
        [InlineData("image1", "alexinea", "8EE22EE5F70E434998522DAE9FA26FB55C536F4304ABFF62059254D5CD0C807B")]
        public void HmacSha256Test(string data, string key, string hex)
        {
            var function = HmacFactory.Create(HmacTypes.HmacSha256, key);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory(DisplayName = "HMAC/Sha384")]
        [InlineData("image", "alexinea", "BBA2453672D08873C997F2CBDE45A0F5721D5D84CF36D491394873CF4F12823266BAED5513759BA8908786C7E97094AC")]
        [InlineData("image0", "alexinea", "5774657FCD42987C32870B9C8C628D02E33A53322B24D5CB9C1B98BB2026B287C0FA1202FD3137AB4B7D7B52264E6E22")]
        [InlineData("image1", "alexinea", "46AC8FA2649C412BBD748F4C2BC21F23699AC38A5E94FA6F571BDCBDD371DB7FA4E5570BECE4B2BE5D963E5112152B4E")]
        public void HmacSha384Test(string data, string key, string hex)
        {
            var function = HmacFactory.Create(HmacTypes.HmacSha384, key);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory(DisplayName = "HMAC/Sha512")]
        [InlineData("image", "alexinea", "5761F399848FD4E1C2A6DAA3C5EF03A8478B430667A1F706C39338925A93F14B782F64C831FF8F54C3CB7EF6A2BF6A29B091A9A20620E3B2AB7DCD7676CFFAAF")]
        [InlineData("image0", "alexinea", "C8EDA091335F3EE6DA95CCAE9129017414D93D0EBC37E76FEB98DFF005A218CD8E15D4BD16CAF5D0B9479BE03B909D95816CBB48252B72BD8C3EE5F742F2008D")]
        [InlineData("image1", "alexinea", "46B41E2E541BF70A0B00A8AF99A6869CAD5C91DA01217C726B9D08F2CC911AB326296347671F5A27FEC095ED08E27BEB93606CABF744C8F9A73DB0BC96051054")]
        public void HmacSha512Test(string data, string key, string hex)
        {
            var function = HmacFactory.Create(HmacTypes.HmacSha512, key);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }
    }
}