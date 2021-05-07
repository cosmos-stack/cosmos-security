using Factory = Cosmos.Security.Verification.JenkinsFactory;

namespace Cosmos.Security.Verification
{
    public class Jenkins
    {
        public static IJenkins Create(JenkinsTypes type = JenkinsTypes.OneAtTime) => Factory.Create(type);

        public static IJenkins Create(JenkinsTypes type, JenkinsConfig config) => Factory.Create(type, config);

        public static IStreamableJenkins Lookup2(JenkinsConfig config = null) => Factory.Lookup2(config);

        public static IJenkins Lookup3Bit32(JenkinsConfig config = null) => Factory.Lookup3Bit32(config);

        public static IJenkins Lookup3Bit64(JenkinsConfig config = null) => Factory.Lookup3Bit64(config);

        public static IStreamableJenkins OneAtTime => new JenkinsOneAtTimeFunction();
    }
}