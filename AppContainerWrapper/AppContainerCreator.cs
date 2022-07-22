using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Vanara.InteropServices;
using Vanara.PInvoke;

namespace AppContainerWrapper
{
    public class AppContainerCreator
    {
        private AdvApi32.SafeAllocatedSID CreateAppContainerProfile(string containerName)
        {
            try
            {
                UserEnv.CreateAppContainerProfile(
                    containerName,
                    "TestContainerDisplayName",
                    "TestContainerDescription",
                    null,
                    0,
                    out var sid
                ).ThrowIfFailed();

                return sid;
            }
            catch (Exception)
            {
                UserEnv.DeriveAppContainerSidFromAppContainerName(containerName, out var existingSid);
                return existingSid;
            }
        }

        public void SandboxProcess(string processName)
        {
            var startupinfo = Kernel32.STARTUPINFOEX.Default;
            var sid = CreateAppContainerProfile("TestContainer");
            SetProcessAttributes(ref startupinfo, sid);
            CreateSandboxedProcess(ref startupinfo, processName);
        }

        private void CreateSandboxedProcess(ref Kernel32.STARTUPINFOEX startupinfo, string processName)
        {
            using var currentIdentity = WindowsIdentity.GetCurrent();
            using var currentToken = new GenericSafeHandle(currentIdentity.Token, Kernel32.CloseHandle, false);

            var res = AdvApi32.CreateProcessAsUser(
                new HTOKEN(currentToken.DangerousGetHandle()),
                processName,
                null,
                null,
                null,
                false,
                Kernel32.CREATE_PROCESS.EXTENDED_STARTUPINFO_PRESENT,
                null,
                null,
                in startupinfo,
                out var processInfo);
            if (res)
            {
                var proc = Process.GetProcessById((int)processInfo.dwProcessId);

            }
            else
            {
                var err = Kernel32.GetLastError();
            }

            Console.ReadKey();
        }

        private void SetProcessAttributes(ref Kernel32.STARTUPINFOEX startupinfo, AdvApi32.SafeAllocatedSID sid)
        {

            var capabilities = new Kernel32.SECURITY_CAPABILITIES();

            SetSecurityCapabilities(ref capabilities, sid, new[] { AdvApi32.WELL_KNOWN_SID_TYPE.WinCapabilityInternetClientSid });

            var capabilitySize = Marshal.SizeOf(capabilities);

            var procThreadAttributeList = Kernel32.SafeProcThreadAttributeList.Create(Kernel32.PROC_THREAD_ATTRIBUTE.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, capabilities);

            var capabilityBuffer = new SafeHandleBuffer(capabilitySize);

            Marshal.StructureToPtr(capabilities, capabilityBuffer.DangerousGetHandle(), fDeleteOld: false);

            Kernel32.UpdateProcThreadAttribute(procThreadAttributeList.DangerousGetHandle(), 0, Kernel32.PROC_THREAD_ATTRIBUTE.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, capabilityBuffer.DangerousGetHandle(), capabilityBuffer.BufferSize);

            startupinfo.lpAttributeList = procThreadAttributeList.DangerousGetHandle();
        }

        private void SetSecurityCapabilities(ref Kernel32.SECURITY_CAPABILITIES securityCapabilities, AdvApi32.SafeAllocatedSID appContainerSid, AdvApi32.WELL_KNOWN_SID_TYPE[] appCapabilities)
        {
            securityCapabilities.AppContainerSid = appContainerSid.DangerousGetHandle();
            securityCapabilities.Capabilities = IntPtr.Zero;
            securityCapabilities.CapabilityCount = 0;

            if (appCapabilities is { Length: > 0 })
            {
                var capabilitiesBuffer = new SafeHandleBuffer(Marshal.SizeOf(typeof(AdvApi32.SID_AND_ATTRIBUTES)) * appCapabilities.Length);

                for (var i = 0; i < appCapabilities.Length; i++)
                {
                    var sidSize = (uint)AdvApi32.SECURITY_MAX_SID_SIZE;

                    var safePsid = new AdvApi32.SafePSID(sidSize);

                    if (!AdvApi32.CreateWellKnownSid(appCapabilities[i], IntPtr.Zero, safePsid, ref sidSize))
                    {
                        throw new Win32Exception();
                    }

                    var attributes = new AdvApi32.SID_AND_ATTRIBUTES
                    {
                        Attributes = (uint)AdvApi32.GroupAttributes.SE_GROUP_ENABLED,
                        Sid = safePsid.DangerousGetHandle()
                    };

                    Marshal.StructureToPtr(attributes, IntPtr.Add(capabilitiesBuffer.DangerousGetHandle(), i * Marshal.SizeOf(typeof(AdvApi32.SID_AND_ATTRIBUTES))), false);
                }

                securityCapabilities.Capabilities = capabilitiesBuffer.DangerousGetHandle();
                securityCapabilities.CapabilityCount = (uint)appCapabilities.Length;
            }
        }
    }
}