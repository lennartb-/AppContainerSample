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
            catch (Exception e)
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
            Create(ref startupinfo, processName);
        }

        private void Create(ref Kernel32.STARTUPINFOEX startupinfo, string processName)
        {
            using (var currentIdentity = WindowsIdentity.GetCurrent())
            using (var currentToken = new GenericSafeHandle(currentIdentity.Token, Kernel32.CloseHandle, false))
            {
                //using (SafeTokenHandle currentToken = new SafeTokenHandle(currentIdentity.Token, ownsHandle: false))

                var processInfo = new Kernel32.SafePROCESS_INFORMATION();
                var flag = Kernel32.CREATE_PROCESS.EXTENDED_STARTUPINFO_PRESENT;

                var res = AdvApi32.CreateProcessAsUser(
                    new HTOKEN(currentToken.DangerousGetHandle()),
                    processName,
                    null,
                    null,
                    null,
                    false,
                    flag,
                    null,
                    null,
                    in startupinfo,
                    out processInfo);
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
        }

        private void SetProcessAttributes(ref Kernel32.STARTUPINFOEX startupinfo, AdvApi32.SafeAllocatedSID sid)
        {

            var capabilities = new Kernel32.SECURITY_CAPABILITIES();

            SetSecurityCapabilities(ref capabilities, sid, new[] { AdvApi32.WELL_KNOWN_SID_TYPE.WinCapabilityInternetClientSid });

            var capabilitySize = Marshal.SizeOf(capabilities);

            var list = new SafeProcThreadAttributeList(1);

            var buffer = new SafeHGlobalBuffer(capabilitySize);

            Marshal.StructureToPtr(capabilities, buffer.DangerousGetHandle(), fDeleteOld: false);

            //var lpValue = Marshal.AllocHGlobal(IntPtr.Size);
            //Marshal.WriteIntPtr(lpValue, capabilities.Capabilities);

            Kernel32.UpdateProcThreadAttribute(list.DangerousGetHandle(), 0, Kernel32.PROC_THREAD_ATTRIBUTE.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, buffer.DangerousGetHandle(), buffer.Size);
            //Marshal.FreeHGlobal(lpValue);
            startupinfo.lpAttributeList = list.DangerousGetHandle();
        }

        private void SetSecurityCapabilities(
            ref Kernel32.SECURITY_CAPABILITIES securityCapabilities,
            AdvApi32.SafeAllocatedSID appContainerSid,
            AdvApi32.WELL_KNOWN_SID_TYPE[] appCapabilities)
        {
            securityCapabilities.AppContainerSid = appContainerSid.DangerousGetHandle();
            securityCapabilities.Capabilities = IntPtr.Zero;
            securityCapabilities.CapabilityCount = 0;
            securityCapabilities.Reserved = 0;

            if (appCapabilities is { Length: > 0 })
            {
                var attributesMemory = new SafeHGlobalBuffer(Marshal.SizeOf(typeof(AdvApi32.SID_AND_ATTRIBUTES)) * appCapabilities.Length);

                for (var i = 0; i < appCapabilities.Length; i++)
                {
                    var sidSize = (uint)AdvApi32.SECURITY_MAX_SID_SIZE;

                    var safeMemory = new AdvApi32.SafePSID(sidSize);

                    if (!AdvApi32.CreateWellKnownSid(appCapabilities[i], IntPtr.Zero, safeMemory, ref sidSize))
                    {
                        throw new Win32Exception();
                    }

                    uint flag = 0x00000004;

                    var attribute = new AdvApi32.SID_AND_ATTRIBUTES
                    {
                        Attributes = flag,
                        Sid = safeMemory.DangerousGetHandle()
                    };

                    Marshal.StructureToPtr(attribute, IntPtr.Add(attributesMemory.DangerousGetHandle(), i * Marshal.SizeOf(typeof(AdvApi32.SID_AND_ATTRIBUTES))), false);
                }

                securityCapabilities.Capabilities = attributesMemory.DangerousGetHandle();
                securityCapabilities.CapabilityCount = (uint)appCapabilities.Length;
            }
        }
    }

    public class SafeHGlobalBuffer : SafeBuffer
    {
        public SafeHGlobalBuffer(int size) : base(true)
        {
            handle = Marshal.AllocHGlobal(size);
            Size = size;
        }

        public int Size { get; }

        protected override bool ReleaseHandle()
        {
            if (!IsInvalid)
            {
                Marshal.FreeHGlobal(handle);
                handle = IntPtr.Zero;
            }

            return true;
        }
    }

    public class SafeProcThreadAttributeList : SafeBuffer
    {
        public SafeProcThreadAttributeList(uint attributeCount) : base(true)
        {
            var size = SizeT.Zero;
            Kernel32.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);

            handle = Marshal.AllocHGlobal(size);

            if (!Kernel32.InitializeProcThreadAttributeList(handle, attributeCount, 0, ref size))
            {
                Marshal.FreeHGlobal(handle);
                throw new Win32Exception();
            }
        }

        protected override bool ReleaseHandle()
        {
            if (!IsInvalid)
            {
                Kernel32.DeleteProcThreadAttributeList(handle);
                Marshal.FreeHGlobal(handle);
                handle = IntPtr.Zero;
            }

            return true;
        }
    }
}