// ReSharper disable once CheckNamespace

namespace Cosmos.Security.Verification
{
    /// <summary>
    /// ELF-64 Hash Function Factory
    /// </summary>
    public static class Elf64Factory
    {
        public static IELF64 Create() => new Elf64Function();
    }
}