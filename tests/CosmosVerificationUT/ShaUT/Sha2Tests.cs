using Cosmos.Security.Verification.SHA;
using Shouldly;
using Xunit;

namespace ShaUT
{
    [Trait("ShaUT", "Sha2Tests")]
    public class Sha2Tests
    {
        [Theory(DisplayName = "Sha2/256")]
        [InlineData("image", "6105D6CC76AF400325E94D588CE511BE5BFDBB73B437DC51ECA43917D7A43E3D")]
        [InlineData("The quick brown fox jumps over the lazy dog", "D7A8FBB307D7809469CA9ABCB0082E4F8D5651E46D3CDB762D02D0BF37C9E592")]
        public void Sha256Test(string data, string hex)
        {
            var function = ShaFactory.Create(ShaTypes.Sha256);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory(DisplayName = "Sha2/224")]
        [InlineData("image", "CED695E9BB1B54396406CE33AA70E0FD7251F8A03118A682CD815C6D")]
        [InlineData("Hello World!", "4575BB4EC129DF6380CEDDE6D71217FE0536F8FFC4E18BCA530A7A1B")]
        [InlineData("The quick brown fox jumps over the lazy dog", "730E109BD7A8A32B1CB9D9A09AA2325D2430587DDBC0C38BAD911525")]
        public void Sha224Test(string data, string hex)
        {
            var function = ShaFactory.Create(ShaTypes.Sha224);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory(DisplayName = "Sha2/384")]
        [InlineData("image", "7158862BE7FF7D2AE0A585B872F415CF09B7FE8C6CE170EF944061E7788D73C1F5835652D8AFE9939B01905D5AA7C48C")]
        [InlineData("The quick brown fox jumps over the lazy dog", "CA737F1014A48F4C0B6DD43CB177B0AFD9E5169367544C494011E3317DBF9A509CB1E5DC1E85A941BBEE3D7F2AFBC9B1")]
        public void Sha384Test(string data, string hex)
        {
            var function = ShaFactory.Create(ShaTypes.Sha384);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }

        [Theory(DisplayName = "Sha2/512")]
        [InlineData("image", "EB31D04DA633DC9F49DFBD66CDB92FBB9B4F9C9BE67914C0209B5DD31CC65A136E1CDCE7D0DB88112E3A759131B9D970CFAAC7EE77CCD620C3DD49043F88958E")]
        [InlineData("The quick brown fox jumps over the lazy dog", "07E547D9586F6A73F73FBAC0435ED76951218FB7D0C8D788A309D785436BBB642E93A252A954F23912547D1E8A3B5ED6E1BFD7097821233FA0538F3DB854FEE6")]
        public void Sha512Test(string data, string hex)
        {
            var function = ShaFactory.Create(ShaTypes.Sha512);
            var hashVal = function.ComputeHash(data);
            hashVal.AsHexString(true).ShouldBe(hex);
        }
    }
}