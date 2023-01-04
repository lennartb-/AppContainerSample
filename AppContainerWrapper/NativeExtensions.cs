using Vanara.PInvoke;

namespace AppContainerWrapper;

/// <summary>
///     Provides extension methods for PInvoke functions.
/// </summary>
internal static class NativeExtensions
{
    /// <summary>
    ///     Converts a <see cref="AdvApi32.SafeAllocatedSID" /> to a string.
    /// </summary>
    /// <param name="sid">The SID to convert to a string.</param>
    /// <returns>
    ///     <paramref name="sid" /> as string.
    /// </returns>
    public static string ToDisplayString(this AdvApi32.SafeAllocatedSID sid)
    {
        return AdvApi32.ConvertSidToStringSid(sid);
    }
}