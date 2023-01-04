using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Serilog;
using Serilog.Core;
using Vanara.InteropServices;
using Vanara.PInvoke;

namespace AppContainerWrapper;

/// <summary>
///     Encapsulates the necessary steps to create a sandboxed process with Windows AppContainers.
/// </summary>
public class AppContainerCreator
{
    private readonly ILogger logger;

    /// <summary>
    ///     Initializes a new instance of the <see cref="AppContainerCreator" /> class.
    /// </summary>
    /// <param name="logger">An implementation of <see cref="ILogger" />.</param>
    public AppContainerCreator(ILogger logger)
    {
        this.logger = logger;
    }

    /// <summary>
    ///     Initializes a new instance of the <see cref="AppContainerCreator" /> class.
    /// </summary>
    public AppContainerCreator()
        : this(Logger.None)
    {
    }

    /// <summary>
    ///     Creates an AppContainer for the specified process.
    /// </summary>
    /// <param name="processName">The full path to the process executable.</param>
    public void SandboxProcess(string processName)
    {
        var startupinfo = Kernel32.STARTUPINFOEX.Default;
        var sid = CreateOrGetAppContainerProfile("TestContainer", "TestContainerName", "TestContainerDescription");

        SetProcessAttributes(ref startupinfo, sid);
        if (!GrantFolderAccess(sid, @"D:\temp2"))
        {
            logger.Information("Error creating AppContainer, last error was: {Error}.", Kernel32.GetLastError());
            return;
        }

        // GrantFolderAccess(sid, @"D:\temp\test.txt");
        CreateSandboxedProcess(ref startupinfo, processName);
    }

    private AdvApi32.SafeAllocatedSID CreateOrGetAppContainerProfile(string containerName, string containerDisplayName, string containerDescription)
    {
        logger.Information("Trying to create new container profile");
        var result = UserEnv.CreateAppContainerProfile(containerName, containerDisplayName, containerDescription, null, 0, out var sid);

        if (result == HRESULT.S_OK)
        {
            logger.Information("New container profile created, SID is {Sid}", sid.ToDisplayString());
            return sid;
        }

        UserEnv.DeriveAppContainerSidFromAppContainerName(containerName, out var existingSid);

        logger.Information("Container profile seems to exist, using existing SID {Sid}", existingSid.ToDisplayString());

        return existingSid;
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
            var procId = (int)processInfo.dwProcessId;
            var proc = Process.GetProcessById(procId);
            logger.Information("Created sandboxed process with PID {Pid}", proc.Id);
        }
        else
        {
            var err = Kernel32.GetLastError();
            logger.Error("Created sandboxed process failed, last error is {Error} ", err);
        }
    }

    /// <remarks>
    ///     Path should be a directory. Granting access to entire volumes requires additional permissions.
    /// </remarks>
    private bool GrantFolderAccess(AdvApi32.SafeAllocatedSID appContainerSid, string path)
    {
        const AdvApi32.SE_OBJECT_TYPE type = AdvApi32.SE_OBJECT_TYPE.SE_FILE_OBJECT;

        var access = new AdvApi32.EXPLICIT_ACCESS
        {
            grfAccessMode = AdvApi32.ACCESS_MODE.GRANT_ACCESS,
            grfAccessPermissions = ACCESS_MASK.GENERIC_ALL,
            grfInheritance = AdvApi32.INHERIT_FLAGS.NO_INHERITANCE,
            Trustee = new AdvApi32.TRUSTEE
            {
                MultipleTrusteeOperation = AdvApi32.MULTIPLE_TRUSTEE_OPERATION.NO_MULTIPLE_TRUSTEE,
                ptstrName = appContainerSid.DangerousGetHandle(),
                TrusteeForm = AdvApi32.TRUSTEE_FORM.TRUSTEE_IS_SID,
                TrusteeType = AdvApi32.TRUSTEE_TYPE.TRUSTEE_IS_WELL_KNOWN_GROUP,
            },
        };
        var info = AdvApi32.GetNamedSecurityInfo(path, type, SECURITY_INFORMATION.DACL_SECURITY_INFORMATION, out var ppsidOwner, out var ppsidGroup, out var ppDacl, out var ppSacl, out _);

        if (info.Failed)
        {
            logger.Error("Getting security info for path {Path} failed with {Error}.", path, info);
            return false;
        }

        var entr = AdvApi32.SetEntriesInAcl(1, new[] { access }, ppDacl.DangerousGetHandle(), out var newAcl);

        if (entr.Failed)
        {
            logger.Error("Creation of new ACL failed with {Error}.", entr);
            return false;
        }

        // ReSharper disable once RedundantArgumentDefaultValue
        var setInfo = AdvApi32.SetNamedSecurityInfo(path, type, SECURITY_INFORMATION.DACL_SECURITY_INFORMATION, ppsidOwner);

        if (setInfo.Failed)
        {
            logger.Error("Setting new ACL for {Path} failed with {Error}.", path, setInfo);
            return false;
        }

        logger.Information("Granting folder access for container {SID} to path {Path} ", appContainerSid.ToDisplayString(), path);
        return true;
    }

    private void SetProcessAttributes(ref Kernel32.STARTUPINFOEX startupinfo, AdvApi32.SafeAllocatedSID sid)
    {
        logger.Information("Setting process attributes");

        var capabilities = default(Kernel32.SECURITY_CAPABILITIES);

        SetSecurityCapabilities(ref capabilities, sid, new[] { AdvApi32.WELL_KNOWN_SID_TYPE.WinCapabilityInternetClientServerSid });

        var capabilitySize = Marshal.SizeOf(capabilities);

        var procThreadAttributeList = Kernel32.SafeProcThreadAttributeList.Create(Kernel32.PROC_THREAD_ATTRIBUTE.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, capabilities);

        var capabilityBuffer = new SafeHandleBuffer(capabilitySize);

        Marshal.StructureToPtr(capabilities, capabilityBuffer.DangerousGetHandle(), false);

        Kernel32.UpdateProcThreadAttribute(
            procThreadAttributeList.DangerousGetHandle(),
            0,
            Kernel32.PROC_THREAD_ATTRIBUTE.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            capabilityBuffer.DangerousGetHandle(),
            capabilityBuffer.BufferSize);

        startupinfo.lpAttributeList = procThreadAttributeList.DangerousGetHandle();
    }

    private void SetSecurityCapabilities(ref Kernel32.SECURITY_CAPABILITIES securityCapabilities, AdvApi32.SafeAllocatedSID appContainerSid, AdvApi32.WELL_KNOWN_SID_TYPE[] appCapabilities)
    {
        logger.Information("Setting security capabilities");

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

                var capability = appCapabilities[i];
                if (AdvApi32.CreateWellKnownSid(capability, IntPtr.Zero, safePsid, ref sidSize))
                {
                    logger.Information("Added capability {Capability} to container ", capability);
                }
                else
                {
                    var err = Kernel32.GetLastError();
                    logger.Error("Creating well known SID failed, last error is {Error} ", err);
                    return;
                }

                var attributes = new AdvApi32.SID_AND_ATTRIBUTES { Attributes = (uint)AdvApi32.GroupAttributes.SE_GROUP_ENABLED, Sid = safePsid.DangerousGetHandle() };

                Marshal.StructureToPtr(attributes, IntPtr.Add(capabilitiesBuffer.DangerousGetHandle(), i * Marshal.SizeOf(typeof(AdvApi32.SID_AND_ATTRIBUTES))), false);
            }

            securityCapabilities.Capabilities = capabilitiesBuffer.DangerousGetHandle();
            securityCapabilities.CapabilityCount = (uint)appCapabilities.Length;
        }
    }
}