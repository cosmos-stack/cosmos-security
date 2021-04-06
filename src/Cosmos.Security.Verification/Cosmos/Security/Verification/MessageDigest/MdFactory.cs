using System;

namespace Cosmos.Security.Verification.MessageDigest
{
    /// <summary>
    /// Message Digest Hash Function Factory
    /// </summary>
    public static class MdFactory
    {
        public static MdFunction Create(MdTypes type = MdTypes.Md5) => new(type);

        public static MdFunction Create(Md6Options options) => new(options);

        public static MdFunction Create(Action<Md6Options> optionsAct)
        {
            var options = Md6Options.Md6Bit256();
            optionsAct?.Invoke(options);
            return Create(options);
        }
    }
}