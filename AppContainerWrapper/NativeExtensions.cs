using Vanara.PInvoke;

namespace AppContainerWrapper;

internal static class NativeExtensions
{
    public static string ToDisplayString(this AdvApi32.SafeAllocatedSID sid)
    {
        return AdvApi32.ConvertSidToStringSid(sid);
    }
}