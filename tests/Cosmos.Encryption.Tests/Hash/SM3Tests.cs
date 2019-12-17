//using System;
//using System.Collections.Generic;
//using System.Text;
//using Cosmos.Encryption.Hash;
using Xunit;

namespace Cosmos.Encryption.Tests.Hash
{
    public class SM3Tests
    {
        [Fact]
        public void HashTest()
        {
            var s = SM3HashingProvider.Signature("天下无敌");
            Assert.Equal("wbjZMU+Yd/zjZpAxoqA/YFsMzSWphatXnot8EHUlBY4=", s);
        }
    }
}
