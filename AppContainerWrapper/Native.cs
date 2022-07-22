using System.ComponentModel;
using System.Runtime.InteropServices;
using Vanara.PInvoke;

namespace AppContainerWrapper
{
    public class Native
    {
        private const CharSet DefaultCharSet = CharSet.Auto;

        internal enum ACCESS_MODE : uint
        {
            NOT_USED_ACCESS = 0,
            GRANT_ACCESS,
            SET_ACCESS,
            REVOKE_ACCESS,
            SET_AUDIT_SUCCESS,
            SET_AUDIT_FAILURE
        }

        internal enum ACCESS_MASK : uint
        {
            GENERIC_ALL = 0x10000000, //268435456,
            GENERIC_READ = 0x80000000, //2147483648L,
            GENERIC_WRITE = 0x40000000, //1073741824,
            GENERIC_EXECUTE = 0x20000000, //536870912,
            STANDARD_RIGHTS_READ = 0x00020000, //131072
            STANDARD_RIGHTS_WRITE = 0x00020000,
            SHARE_ACCESS_READ = 0x1200A9, // 1179817
            SHARE_ACCESS_WRITE = 0x1301BF, // 1245631
            SHARE_ACCESS_FULL = 0x1f01ff // 2032127
        }

        internal enum ACCESS_INHERITANCE : uint
        {
            NO_INHERITANCE = 0,
            OBJECT_INHERIT_ACE = 0x1,
            CONTAINER_INHERIT_ACE = 0x2,
            NO_PROPAGATE_INHERIT_ACE = 0x4,
            INHERIT_ONLY_ACE = 0x8,
            INHERITED_ACE = 0x10,
            SUB_OBJECTS_ONLY_INHERIT = ACCESS_INHERITANCE.OBJECT_INHERIT_ACE | ACCESS_INHERITANCE.INHERIT_ONLY_ACE,
            SUB_CONTAINERS_ONLY_INHERIT = ACCESS_INHERITANCE.CONTAINER_INHERIT_ACE | ACCESS_INHERITANCE.INHERIT_ONLY_ACE,
            SUB_CONTAINERS_AND_OBJECTS_INHERIT = ACCESS_INHERITANCE.CONTAINER_INHERIT_ACE | ACCESS_INHERITANCE.OBJECT_INHERIT_ACE,
        }

        internal enum MULTIPLE_TRUSTEE_OPERATION
        {
            NO_MULTIPLE_TRUSTEE,
            TRUSTEE_IS_IMPERSONATE
        }

        internal enum SE_OBJECT_TYPE
        {
            SE_UNKNOWN_OBJECT_TYPE = 0,
            SE_FILE_OBJECT,
            SE_SERVICE,
            SE_PRINTER,
            SE_REGISTRY_KEY,
            SE_LMSHARE,
            SE_KERNEL_OBJECT,
            SE_WINDOW_OBJECT,
            SE_DS_OBJECT,
            SE_DS_OBJECT_ALL,
            SE_PROVIDER_DEFINED_OBJECT,
            SE_WMIGUID_OBJECT,
            SE_REGISTRY_WOW64_32KEY
        }

        [Flags]
        internal enum SECURITY_INFORMATION : uint
        {
            OWNER_SECURITY_INFORMATION = 0x00000001,
            GROUP_SECURITY_INFORMATION = 0x00000002,
            DACL_SECURITY_INFORMATION = 0x00000004,
            SACL_SECURITY_INFORMATION = 0x00000008,
            UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000,
            UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
            PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000,
            PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
        }

        internal enum SHARE_TYPE : uint
        {
            STYPE_DISKTREE = 0,
            STYPE_PRINTQ = 1,
            STYPE_DEVICE = 2,
            STYPE_IPC = 3,
            STYPE_TEMPORARY = 0x40000000,
            STYPE_SPECIAL = 0x80000000,
        }

        internal enum TRUSTEE_FORM
        {
            TRUSTEE_IS_SID = 0,
            TRUSTEE_IS_NAME,
            TRUSTEE_BAD_FORM,
            TRUSTEE_IS_OBJECTS_AND_SID,
            TRUSTEE_IS_OBJECTS_AND_NAME
        }

        internal enum TRUSTEE_TYPE
        {
            TRUSTEE_IS_UNKNOWN = 0,
            TRUSTEE_IS_USER,
            TRUSTEE_IS_GROUP,
            TRUSTEE_IS_DOMAIN,
            TRUSTEE_IS_ALIAS,
            TRUSTEE_IS_WELL_KNOWN_GROUP,
            TRUSTEE_IS_DELETED,
            TRUSTEE_IS_INVALID,
            TRUSTEE_IS_COMPUTER
        }

        [StructLayout(LayoutKind.Sequential, CharSet = DefaultCharSet)]
        internal struct SHARE_INFO_502
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string shi502_netname;
            public SHARE_TYPE shi502_type;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string shi502_remark;
            public int shi502_permissions;
            public int shi502_max_uses;
            public int shi502_current_uses;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string shi502_path;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string shi502_passwd;
            public int shi502_reserved;
            public IntPtr shi502_security_descriptor;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = DefaultCharSet)]
        internal struct EXPLICIT_ACCESS
        {
            public uint AccessPermissions;
            public uint AccessMode;
            public uint Inheritance;
            public TRUSTEE trustee;
        }

        //Platform independent (32 & 64 bit) - use Pack = 0 for both platforms. IntPtr works as well.
        [StructLayout(LayoutKind.Sequential, CharSet = DefaultCharSet, Pack = 4)]
        internal struct TRUSTEE
        {
            public IntPtr MultipleTrustee;
            public MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation;
            public TRUSTEE_FORM TrusteeForm;
            public TRUSTEE_TYPE TrusteeType;
            //[MarshalAs(UnmanagedType.LPWStr)]
            //public string Name;
            public IntPtr ptstrName;
        }

        [DllImport("advapi32.dll", CharSet = DefaultCharSet, SetLastError = true)]
        internal static extern uint GetNamedSecurityInfo(
           [MarshalAs(UnmanagedType.LPWStr)] string pObjectName,
           SE_OBJECT_TYPE ObjectType,
           SECURITY_INFORMATION SecurityInfo,
           out IntPtr pSidOwner,
           out IntPtr pSidGroup,
           out IntPtr pDacl,
           out IntPtr pSacl,
           out IntPtr pSecurityDescriptor);

        [DllImport("advapi32.dll", CharSet = DefaultCharSet, SetLastError = true)]
        internal static extern uint SetNamedSecurityInfo(
             [MarshalAs(UnmanagedType.LPWStr)] string pObjectName,
             SE_OBJECT_TYPE ObjectType,
             SECURITY_INFORMATION SecurityInfo,
             IntPtr psidOwner,
             IntPtr psidGroup,
             IntPtr pDacl,
             IntPtr pSacl);

        [DllImport("advapi32.dll", CharSet = DefaultCharSet, SetLastError = true)]
        internal static extern int SetEntriesInAcl(
             int cCountOfExplicitEntries,
             ref EXPLICIT_ACCESS pListOfExplicitEntries,
             IntPtr OldAcl,
             out IntPtr NewAcl);

        //public static void SetReadOnlySharePermissions(AdvApi32.SafeAllocatedSID safeAllocatedSid)
        //{
        //    IntPtr sidOwnerPtr = IntPtr.Zero;
        //    IntPtr groupOwnerPtr = IntPtr.Zero;
        //    IntPtr saclPtr = IntPtr.Zero;
        //    IntPtr oldDacl = IntPtr.Zero;
        //    IntPtr oldSecurityDescriptor = IntPtr.Zero;
        //    string file = @"C:\Users\lbrue\Desktop\test.txt";

        //    uint securityObjectQueryResult = GetNamedSecurityInfo(
        //        file,
        //        SE_OBJECT_TYPE.SE_FILE_OBJECT,
        //        SECURITY_INFORMATION.DACL_SECURITY_INFORMATION,
        //        out sidOwnerPtr,
        //        out groupOwnerPtr,
        //        out oldDacl,
        //        out saclPtr,
        //        out oldSecurityDescriptor);

        //    if (securityObjectQueryResult != 0)
        //    {
        //        throw new Win32Exception((int)securityObjectQueryResult);
        //    }

        //    // Default permissions = ReadOnly
        //    uint shareAccessPermissions = (uint)ACCESS_MASK.SHARE_ACCESS_FULL;

        //    EXPLICIT_ACCESS access = new EXPLICIT_ACCESS()
        //    {
        //        AccessMode = (uint)ACCESS_MODE.SET_ACCESS,
        //        AccessPermissions = shareAccessPermissions,
        //        Inheritance = (uint)ACCESS_INHERITANCE.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
        //        trustee = new TRUSTEE()
        //        {
        //            //Name = "Administrators",
        //            //TrusteeForm = TRUSTEE_FORM.TRUSTEE_IS_NAME,
        //            //TrusteeType = TRUSTEE_TYPE.TRUSTEE_IS_WELL_KNOWN_GROUP
        //            MultipleTrusteeOperation = MULTIPLE_TRUSTEE_OPERATION.NO_MULTIPLE_TRUSTEE,
        //            ptstrName = safeAllocatedSid.DangerousGetHandle(),
        //            TrusteeForm = TRUSTEE_FORM.TRUSTEE_IS_SID,
        //            TrusteeType = TRUSTEE_TYPE.TRUSTEE_IS_WELL_KNOWN_GROUP
        //        }
        //    };

        //    IntPtr newDacl;
        //    int initializeAclEntriesResult = SetEntriesInAcl(1, ref access, oldDacl, out newDacl);
        //    if (initializeAclEntriesResult != 0)
        //    {
        //        throw new Win32Exception(initializeAclEntriesResult);
        //    }

        //    uint setSecurityResult = SetNamedSecurityInfo(
        //        file,
        //        SE_OBJECT_TYPE.SE_FILE_OBJECT,
        //        SECURITY_INFORMATION.DACL_SECURITY_INFORMATION,
        //        IntPtr.Zero,
        //        IntPtr.Zero,
        //        newDacl,
        //        IntPtr.Zero);

        //    if (setSecurityResult != 0)
        //    {
        //        throw new Win32Exception((int)setSecurityResult);
        //    }
        //}

    }
}