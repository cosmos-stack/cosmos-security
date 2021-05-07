using Factory = Cosmos.Security.Verification.Elf64Factory;

// ReSharper disable InconsistentNaming

namespace Cosmos.Security.Verification
{
    /// <summary>
    /// ELF-64 Hash Function Factory
    /// </summary>
    public static class ELF64
    {
        public static IELF64 Create() => Factory.Create();
    }
}