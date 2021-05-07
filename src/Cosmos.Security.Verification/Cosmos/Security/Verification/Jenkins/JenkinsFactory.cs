// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Verification
{
    /// <summary>
    /// Jenkins Hash Function Factory
    /// </summary>
    public class JenkinsFactory
    {
        public static IJenkins Create(JenkinsTypes type = JenkinsTypes.OneAtTime)
        {
            return Create(type, new JenkinsConfig());
        }

        public static IJenkins Create(JenkinsTypes type, JenkinsConfig config)
        {
            if (type is not JenkinsTypes.OneAtTime)
            {
                config.CheckNull(nameof(config));
                config = config.Clone();

                config.HashSizeInBits = type switch
                {
                    JenkinsTypes.Lookup2 => 32,
                    JenkinsTypes.Lookup3Bit32 => 32,
                    JenkinsTypes.Lookup3Bit64 => 64,
                    _ => 32
                };
            }

            return type switch
            {
                JenkinsTypes.Lookup2 => new JenkinsLookup2Function(config),
                JenkinsTypes.Lookup3Bit32 => new JenkinsLookup3Function(config),
                JenkinsTypes.Lookup3Bit64 => new JenkinsLookup3Function(config),
                JenkinsTypes.OneAtTime => new JenkinsOneAtTimeFunction(),
                _ => new JenkinsOneAtTimeFunction()
            };
        }

        public static IStreamableJenkins Lookup2() => Lookup2(new JenkinsConfig());

        public static IStreamableJenkins Lookup2(JenkinsConfig config)
        {
            config ??= new JenkinsConfig();
            config.HashSizeInBits = 32;
            return new JenkinsLookup2Function(config);
        }

        public static IJenkins Lookup3Bit32() => Lookup3Bit32(new JenkinsConfig());

        public static IJenkins Lookup3Bit32(JenkinsConfig config)
        {
            config ??= new JenkinsConfig();
            config.HashSizeInBits = 32;
            return new JenkinsLookup3Function(config);
        }

        public static IJenkins Lookup3Bit64() => Lookup3Bit64(new JenkinsConfig());

        public static IJenkins Lookup3Bit64(JenkinsConfig config)
        {
            config ??= new JenkinsConfig();
            config.HashSizeInBits = 64;
            return new JenkinsLookup3Function(config);
        }

        public static IStreamableJenkins OneAtTime()
        {
            return new JenkinsOneAtTimeFunction();
        }
    }
}