using Cosmos.Reflection;

namespace Cosmos.Security.Verification
{
    public static class HashValueExtensions
    {
        #region To HashCode-NN

        public static HashCode32 ToHashCode32(this IHashValue hashVal, bool strictMode = true)
        {
            if (hashVal is null)
                return HashCode32.Zero;
            var hex = hashVal.GetHexString();
            return strictMode ? HashCode32.Parse(hex) : HashCode32.ParseLoosely(hex);
        }

        public static HashCode64 ToHashCode64(this IHashValue hashVal, bool strictMode = true)
        {
            if (hashVal is null)
                return HashCode64.Zero;
            var hex = hashVal.GetHexString();
            return strictMode ? HashCode64.Parse(hex) : HashCode64.ParseLoosely(hex);
        }

        public static HashCode128 ToHashCode128(this IHashValue hashVal, bool strictMode = true)
        {
            if (hashVal is null)
                return HashCode128.Zero;
            var hex = hashVal.GetHexString();
            return strictMode ? HashCode128.Parse(hex) : HashCode128.ParseLoosely(hex);
        }

        public static HashCode256 ToHashCode256(this IHashValue hashVal, bool strictMode = true)
        {
            if (hashVal is null)
                return HashCode256.Zero;
            var hex = hashVal.GetHexString();
            return strictMode ? HashCode256.Parse(hex) : HashCode256.ParseLoosely(hex);
        }

        public static HashCode512 ToHashCode512(this IHashValue hashVal, bool strictMode = true)
        {
            if (hashVal is null)
                return HashCode512.Zero;
            var hex = hashVal.GetHexString();
            return strictMode ? HashCode512.Parse(hex) : HashCode512.ParseLoosely(hex);
        }

        public static HashCode1024 ToHashCode1024(this IHashValue hashVal, bool strictMode = true)
        {
            if (hashVal is null)
                return HashCode1024.Zero;
            var hex = hashVal.GetHexString();
            return strictMode ? HashCode1024.Parse(hex) : HashCode1024.ParseLoosely(hex);
        }

        #endregion

        #region Safe HashCode-NN

        public static HashCode32 SafeHashCode32(this IHashValue hashVal, bool strictMode = true)
        {
            if (hashVal is null)
                return HashCode32.Zero;
            
            var hex = hashVal.GetHexString();

            return strictMode
                ? HashCode32.TryParse(hex, out var hash)
                    ? hash
                    : HashCode32.Zero
                : HashCode32.TryParseLoosely(hex, out hash)
                    ? hash
                    : HashCode32.Zero;
        }

        public static HashCode64 SafeHashCode64(this IHashValue hashVal, bool strictMode = true)
        {
            if (hashVal is null)
                return HashCode64.Zero;
            
            var hex = hashVal.GetHexString();

            return strictMode
                ? HashCode64.TryParse(hex, out var hash)
                    ? hash
                    : HashCode64.Zero
                : HashCode64.TryParseLoosely(hex, out hash)
                    ? hash
                    : HashCode64.Zero;
        }

        public static HashCode128 SafeHashCode128(this IHashValue hashVal, bool strictMode = true)
        {
            if (hashVal is null)
                return HashCode128.Zero;
            
            var hex = hashVal.GetHexString();

            return strictMode
                ? HashCode128.TryParse(hex, out var hash)
                    ? hash
                    : HashCode128.Zero
                : HashCode128.TryParseLoosely(hex, out hash)
                    ? hash
                    : HashCode128.Zero;
        }

        public static HashCode256 SafeHashCode256(this IHashValue hashVal, bool strictMode = true)
        {
            if (hashVal is null)
                return HashCode256.Zero;
            
            var hex = hashVal.GetHexString();

            return strictMode
                ? HashCode256.TryParse(hex, out var hash)
                    ? hash
                    : HashCode256.Zero
                : HashCode256.TryParseLoosely(hex, out hash)
                    ? hash
                    : HashCode256.Zero;
        }

        public static HashCode512 SafeHashCode512(this IHashValue hashVal, bool strictMode = true)
        {
            if (hashVal is null)
                return HashCode512.Zero;
            
            var hex = hashVal.GetHexString();

            return strictMode
                ? HashCode512.TryParse(hex, out var hash)
                    ? hash
                    : HashCode512.Zero
                : HashCode512.TryParseLoosely(hex, out hash)
                    ? hash
                    : HashCode512.Zero;
        }

        public static HashCode1024 SafeHashCode1024(this IHashValue hashVal, bool strictMode = true)
        {
            if (hashVal is null)
                return HashCode1024.Zero;
            
            var hex = hashVal.GetHexString();

            return strictMode
                ? HashCode1024.TryParse(hex, out var hash)
                    ? hash
                    : HashCode1024.Zero
                : HashCode1024.TryParseLoosely(hex, out hash)
                    ? hash
                    : HashCode1024.Zero;
        }

        #endregion
    }
}