using System;
using Factory = Cosmos.Security.Verification.MdFactory;

namespace Cosmos.Security.Verification
{
    public static class MessageDigest
    {
        public static IMD Create(MdTypes type = MdTypes.Md5) => Factory.Create(type);
    }

    public static class MessageDigest2
    {
        public static IMD Create() => Factory.Create(MdTypes.Md2);
    }

    public static class MessageDigest4
    {
        public static IMD Create() => Factory.Create(MdTypes.Md4);
    }

    public static class MessageDigest5
    {
        public static IMD Create() => Factory.Create(MdTypes.Md5);
    }

    public static class MessageDigest6
    {
        public static IMD Create(Md6Options options) => Factory.Create(options);

        public static IMD Create(Action<Md6Options> optionsAct) => Factory.Create(optionsAct);
    }
}