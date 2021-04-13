using System;
// ReSharper disable once CheckNamespace
namespace Cosmos.Security.Verification
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

        public static MdFunction Md2 => Create(MdTypes.Md2);
        public static MdFunction Md4 => Create(MdTypes.Md4);
        public static MdFunction Md5 => Create(MdTypes.Md5);
        public static MdFunction Md6 => Create(MdTypes.Md6);
    }
}