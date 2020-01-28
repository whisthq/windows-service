using System;
using System.ServiceProcess;
using System.Security;
using System.Runtime.InteropServices;
using System.Threading;
using System.Diagnostics;

// Fractal Service namespace
namespace FractalService
{
    // Fractal Service class
    public partial class FractalService : ServiceBase
    {
        // Imports from Windows APIs
        #region Constants Imports
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int MAXIMUM_ALLOWED = 0x2000000;
        internal const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        internal const int NORMAL_PRIORITY_CLASS = 0x20;
        internal const int CREATE_NEW_CONSOLE = 0x00000010;

        // Generic access flags
        internal const int GENERIC_WRITE = 0x40000000;
        internal const int GENERIC_EXECUTE = 0x20000000;
        internal const int GENERIC_ALL_ACCESS = 0x10000000;

        // Desktop-specific access flags
        internal const int DESKTOP_READOBJECTS = 0x0001;
        internal const int DESKTOP_CREATEWINDOW = 0x0002;
        internal const int DESKTOP_CREATEMENU = 0x0004;
        internal const int DESKTOP_HOOKCONTROL = 0x0008;
        internal const int DESKTOP_JOURNALRECORD = 0x0010;
        internal const int DESKTOP_JOURNALPLAYBACK = 0x0020;
        internal const int DESKTOP_ENUMERATE = 0x0040;
        internal const int DESKTOP_WRITEOBJECTS = 0x0080;
        internal const int DESKTOP_SWITCHDESKTOP = 0x0100;

        public const uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const uint STANDARD_RIGHTS_READ = 0x00020000;
        public const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const uint TOKEN_DUPLICATE = 0x0002;
        public const uint TOKEN_IMPERSONATE = 0x0004;
        public const uint TOKEN_QUERY = 0x0008;
        public const uint TOKEN_QUERY_SOURCE = 0x0010;
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const uint TOKEN_ADJUST_GROUPS = 0x0040;
        public const uint TOKEN_ADJUST_DEFAULT = 0x0080;
        public const uint TOKEN_ADJUST_SESSIONID = 0x0100;
        public const uint TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const uint TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
                                              TOKEN_DUPLICATE | TOKEN_IMPERSONATE |
                                              TOKEN_QUERY | TOKEN_QUERY_SOURCE |
                                              TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS |
                                              TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID);

        internal const uint INFINITE = 0xFFFFFFFF;
        internal const uint WAIT_ABANDONED = 0x00000080;
        internal const uint WAIT_OBJECT_0 = 0x00000000;
        internal const uint WAIT_TIMEOUT = 0x00000102;

        internal const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
        internal const string SE_TCB_NAME = "SeTcbPrivilege";
        internal const string SE_RESTORE_NAME = "SeRestorePrivilege";
        internal const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
        internal const string SE_DEBUG_NAME = "SeDebugPrivilege";
        #endregion

        #region Structs & Enums
        public enum ServiceState
        {
            SERVICE_STOPPED = 0x00000001,
            SERVICE_START_PENDING = 0x00000002,
            SERVICE_STOP_PENDING = 0x00000003,
            SERVICE_RUNNING = 0x00000004,
            SERVICE_CONTINUE_PENDING = 0x00000005,
            SERVICE_PAUSE_PENDING = 0x00000006,
            SERVICE_PAUSED = 0x00000007,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ServiceStatus
        {
            public int dwServiceType;
            public ServiceState dwCurrentState;
            public int dwControlsAccepted;
            public int dwWin32ExitCode;
            public int dwServiceSpecificExitCode;
            public int dwCheckPoint;
            public int dwWaitHint;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }
        struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
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
        struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        public enum ShowCommands : int
        {
            SW_HIDE = 0,
            SW_SHOWNORMAL = 1,
            SW_NORMAL = 1,
            SW_SHOWMINIMIZED = 2,
            SW_SHOWMAXIMIZED = 3,
            SW_MAXIMIZE = 3,
            SW_SHOWNOACTIVATE = 4,
            SW_SHOW = 5,
            SW_MINIMIZE = 6,
            SW_SHOWMINNOACTIVE = 7,
            SW_SHOWNA = 8,
            SW_RESTORE = 9,
            SW_SHOWDEFAULT = 10,
            SW_FORCEMINIMIZE = 11,
            SW_MAX = 11
        }

        enum TOKEN_INFORMATION_CLASS
        {
            /// <summary>
            /// The buffer receives a TOKEN_USER structure that contains the user account of the token.
            /// </summary>
            TokenUser = 1,
            /// <summary>
            /// The buffer receives a TOKEN_GROUPS structure that contains the group accounts associated with the token.
            /// </summary>
            TokenGroups,
            /// <summary>
            /// The buffer receives a TOKEN_PRIVILEGES structure that contains the privileges of the token.
            /// </summary>
            TokenPrivileges,
            /// <summary>
            /// The buffer receives a TOKEN_OWNER structure that contains the default owner security identifier (SID) for newly created objects.
            /// </summary>
            TokenOwner,
            /// <summary>
            /// The buffer receives a TOKEN_PRIMARY_GROUP structure that contains the default primary group SID for newly created objects.
            /// </summary>
            TokenPrimaryGroup,
            /// <summary>
            /// The buffer receives a TOKEN_DEFAULT_DACL structure that contains the default DACL for newly created objects.
            /// </summary>
            TokenDefaultDacl,
            /// <summary>
            /// The buffer receives a TOKEN_SOURCE structure that contains the source of the token. TOKEN_QUERY_SOURCE access is needed to retrieve this information.
            /// </summary>
            TokenSource,
            /// <summary>
            /// The buffer receives a TOKEN_TYPE value that indicates whether the token is a primary or impersonation token.
            /// </summary>
            TokenType,
            /// <summary>
            /// The buffer receives a SECURITY_IMPERSONATION_LEVEL value that indicates the impersonation level of the token. If the access token is not an impersonation token, the function fails.
            /// </summary>
            TokenImpersonationLevel,
            /// <summary>
            /// The buffer receives a TOKEN_STATISTICS structure that contains various token statistics.
            /// </summary>
            TokenStatistics,
            /// <summary>
            /// The buffer receives a TOKEN_GROUPS structure that contains the list of restricting SIDs in a restricted token.
            /// </summary>
            TokenRestrictedSids,
            /// <summary>
            /// The buffer receives a DWORD value that indicates the Terminal Services session identifier that is associated with the token.
            /// </summary>
            TokenSessionId,
            /// <summary>
            /// The buffer receives a TOKEN_GROUPS_AND_PRIVILEGES structure that contains the user SID, the group accounts, the restricted SIDs, and the authentication ID associated with the token.
            /// </summary>
            TokenGroupsAndPrivileges,
            /// <summary>
            /// Reserved.
            /// </summary>
            TokenSessionReference,
            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if the token includes the SANDBOX_INERT flag.
            /// </summary>
            TokenSandBoxInert,
            /// <summary>
            /// Reserved.
            /// </summary>
            TokenAuditPolicy,
            /// <summary>
            /// The buffer receives a TOKEN_ORIGIN value.
            /// </summary>
            TokenOrigin,
            /// <summary>
            /// The buffer receives a TOKEN_ELEVATION_TYPE value that specifies the elevation level of the token.
            /// </summary>
            TokenElevationType,
            /// <summary>
            /// The buffer receives a TOKEN_LINKED_TOKEN structure that contains a handle to another token that is linked to this token.
            /// </summary>
            TokenLinkedToken,
            /// <summary>
            /// The buffer receives a TOKEN_ELEVATION structure that specifies whether the token is elevated.
            /// </summary>
            TokenElevation,
            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if the token has ever been filtered.
            /// </summary>
            TokenHasRestrictions,
            /// <summary>
            /// The buffer receives a TOKEN_ACCESS_INFORMATION structure that specifies security information contained in the token.
            /// </summary>
            TokenAccessInformation,
            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if virtualization is allowed for the token.
            /// </summary>
            TokenVirtualizationAllowed,
            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if virtualization is enabled for the token.
            /// </summary>
            TokenVirtualizationEnabled,
            /// <summary>
            /// The buffer receives a TOKEN_MANDATORY_LABEL structure that specifies the token's integrity level.
            /// </summary>
            TokenIntegrityLevel,
            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if the token has the UIAccess flag set.
            /// </summary>
            TokenUIAccess,
            /// <summary>
            /// The buffer receives a TOKEN_MANDATORY_POLICY structure that specifies the token's mandatory integrity policy.
            /// </summary>
            TokenMandatoryPolicy,
            /// <summary>
            /// The buffer receives the token's logon security identifier (SID).
            /// </summary>
            TokenLogonSid,
            /// <summary>
            /// The maximum value for this enumeration
            /// </summary>
            MaxTokenInfoClass
        }

        enum ShowWindowCommands
        {
            /// <summary>
            /// Hides the window and activates another window.
            /// </summary>
            Hide = 0,
            /// <summary>
            /// Activates and displays a window. If the window is minimized or
            /// maximized, the system restores it to its original size and position.
            /// An application should specify this flag when displaying the window
            /// for the first time.
            /// </summary>
            Normal = 1,
            /// <summary>
            /// Activates the window and displays it as a minimized window.
            /// </summary>
            ShowMinimized = 2,
            /// <summary>
            /// Maximizes the specified window.
            /// </summary>
            Maximize = 3, // is this the right value?
            /// <summary>
            /// Activates the window and displays it as a maximized window.
            /// </summary>      
            ShowMaximized = 3,
            /// <summary>
            /// Displays a window in its most recent size and position. This value
            /// is similar to <see //cref="Win32.ShowWindowCommand.Normal"/>, except
            /// the window is not activated.
            /// </summary>
            ShowNoActivate = 4,
            /// <summary>
            /// Activates the window and displays it in its current size and position.
            /// </summary>
            Show = 5,
            /// <summary>
            /// Minimizes the specified window and activates the next top-level
            /// window in the Z order.
            /// </summary>
            Minimize = 6,
            /// <summary>
            /// Displays the window as a minimized window. This value is similar to
            /// <see //cref="Win32.ShowWindowCommand.ShowMinimized"/>, except the
            /// window is not activated.
            /// </summary>
            ShowMinNoActive = 7,
            /// <summary>
            /// Displays the window in its current size and position. This value is
            /// similar to <see //cref="Win32.ShowWindowCommand.Show"/>, except the
            /// window is not activated.
            /// </summary>
            ShowNA = 8,
            /// <summary>
            /// Activates and displays the window. If the window is minimized or
            /// maximized, the system restores it to its original size and position.
            /// An application should specify this flag when restoring a minimized window.
            /// </summary>
            Restore = 9,
            /// <summary>
            /// Sets the show state based on the SW_* value specified in the
            /// STARTUPINFO structure passed to the CreateProcess function by the
            /// program that started the application.
            /// </summary>
            ShowDefault = 10,
            /// <summary>
            ///  <b>Windows 2000/XP:</b> Minimizes a window, even if the thread
            /// that owns the window is not responding. This flag should only be
            /// used when minimizing windows from a different thread.
            /// </summary>
            ForceMinimize = 11
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
        };

        public enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            All = (HeapList | Process | Thread | Module),
            Inherit = 0x80000000,
            NoHeaps = 0x40000000
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)] // valid for 1 privilege
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        enum CreateProcessFlags
        {
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_SUSPENDED = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            DEBUG_PROCESS = 0x00000001,
            DETACHED_PROCESS = 0x00000008,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            INHERIT_PARENT_AFFINITY = 0x00010000,
            INHERIT_CALLER_PRIORITY = 0x10000000
        }

        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }
        #endregion

        #region DLL Imports
        [DllImport("shell32.dll")]
        static extern IntPtr ShellExecute(IntPtr hwnd,
                                          string lpOperation,
                                          string lpFile,
                                          string lpParameters,
                                          string lpDirectory,
                                          ShowCommands nShowCmd);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetServiceStatus(IntPtr handle, ref ServiceStatus serviceStatus);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern int ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
                                                 bool DisableAllPrivileges,
                                                 ref TOKEN_PRIVILEGES NewState,
                                                 uint Zero,
                                                 IntPtr Null1,
                                                 IntPtr Null2);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SetTokenInformation(IntPtr TokenHandle,
                                               TOKEN_INFORMATION_CLASS TokenInformationClass,
                                               ref uint TokenInformation,
                                               uint TokenInformationLength);

        [DllImport("kernel32.dll", SetLastError = true), SuppressUnmanagedCodeSecurity]
        static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll", SetLastError = true)]
        static extern bool WTSQueryUserToken(uint sessionID, out IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle,
                                            uint DesiredAccess,
                                            out IntPtr TokenHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess,
                                                bool bInheritHandle,
                                                uint processId);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateToken(IntPtr ExistingTokenHandle,
                                                 int SECURITY_IMPERSONATION_LEVEL,
                                                 ref IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private extern static bool DuplicateTokenEx(IntPtr hExistingToken,
                                                    uint dwDesiredAccess,
                                                    ref SECURITY_ATTRIBUTES lpTokenAttributes,
                                                    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
                                                    TOKEN_TYPE TokenType,
                                                    out IntPtr phNewToken);

        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessAsUser(IntPtr hToken,
                                               string lpApplicationName,
                                               string lpCommandLine,
                                               ref SECURITY_ATTRIBUTES lpProcessAttributes,
                                               ref SECURITY_ATTRIBUTES lpThreadAttributes,
                                               bool bInheritHandles,
                                               uint dwCreationFlags,
                                               IntPtr lpEnvironment,
                                               string lpCurrentDirectory,
                                               ref STARTUPINFO lpStartupInfo,
                                               out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool RevertToSelf();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll")]
        static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll")]
        static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll")]
        static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

        [DllImport("user32.dll", SetLastError = true)]
        static extern IntPtr OpenInputDesktop(uint dwFlags, bool fInherit, uint dwDesiredAccess);

        [DllImport("user32.dll", SetLastError = true)]
        static extern bool SetThreadDesktop(IntPtr hDesktop);

        [DllImport("user32.dll", SetLastError = true)]
        static extern bool CloseDesktop(IntPtr hDesktop);
        #endregion

        // Service global variables
        bool service_is_running = true; // to know whether to monitor the service
        PROCESS_INFORMATION pi; // variable holding the created process handles

        // Fractal Service initialization
        public FractalService()
        {
            InitializeComponent();
            eventLog1 = new System.Diagnostics.EventLog();
            if (!System.Diagnostics.EventLog.SourceExists("FractalSource"))
            {
                System.Diagnostics.EventLog.CreateEventSource("FractalSource", "FractalLog");
            }
            eventLog1.Source = "FractalSource";
            eventLog1.Log = "FractalLog";
        }

        // Runs when the service starts
        protected override void OnStart(string[] args)
        {
            // Write to log for debugging
            eventLog1.WriteEntry("In OnStart - Starting the service.");

            // Update the service state to Start Pending.
            ServiceStatus serviceStatus = new ServiceStatus
            {
                dwCurrentState = ServiceState.SERVICE_START_PENDING,
                dwWaitHint = 100000
            };
            SetServiceStatus(this.ServiceHandle, ref serviceStatus);

            // Update the service state to Running.
            serviceStatus.dwCurrentState = ServiceState.SERVICE_RUNNING;
            SetServiceStatus(this.ServiceHandle, ref serviceStatus);

            // Launch the Fractal Protocol server as a console process to run on headless VM
            if (!LaunchConsoleProcess())
            {
                eventLog1.WriteEntry("Failed to launch Fractal Protocol as console process w/ error code: " + GetLastError().ToString());
                return;
            }
            // eventLog1.WriteEntry("Successfully launched Fractal Protocol as console process.");

            // Create new thread to monitor the Fractal Protocol server process, and restart it if it crashed
            Thread processMonitor = new Thread(MonitorProcess);
            processMonitor.Start();

            // For debugging
            eventLog1.WriteEntry("Process monitoring thread launched - End of OnStart().");
        }

        // Runs when the program stops
        protected override void OnStop()
        {
            // Write to log for debugging
            eventLog1.WriteEntry("In OnStop - Stopping the service.");

            // Set service is running to false to stop monitoring process
            service_is_running = false;

            // Close the process handles
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);

            // Update the service state to Stop Pending.
            ServiceStatus serviceStatus = new ServiceStatus
            {
                dwCurrentState = ServiceState.SERVICE_STOP_PENDING,
                dwWaitHint = 100000
            };
            SetServiceStatus(this.ServiceHandle, ref serviceStatus);

            // Update the service state to Stopped.
            serviceStatus.dwCurrentState = ServiceState.SERVICE_STOPPED;
            SetServiceStatus(this.ServiceHandle, ref serviceStatus);

            // Write to log for debugging
            eventLog1.WriteEntry("In OnStop - Service stopped.");
        }

        // Launches the Fractal Protocol server as a console process to run on headless VM
        public bool LaunchConsoleProcess()
        {
            // For debugging
            eventLog1.WriteEntry("In LaunchConsoleProcess - Starting the Process.");

            // Grab the winlogon process
            Process winLogon = null;
            foreach (Process p in Process.GetProcesses())
            {
                if (p.ProcessName.Contains("winlogon"))
                {
                    // Winlogon found, save the process
                    // eventLog1.WriteEntry("Found Winlogon in console session.");
                    winLogon = p;
                    break;
                }
            }

            // Ensure we found winlogon
            if (winLogon == null)
            {
                eventLog1.WriteEntry("Could not find Winlogon in console session.");
                return false;
            }

            // Grab the winlogon's token
            if (!OpenProcessToken(winLogon.Handle, TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, out IntPtr userToken))
            {
                eventLog1.WriteEntry("OpenProcessToken failed w/ error code: " + GetLastError().ToString());
                return false;
            }
            // eventLog1.WriteEntry("OpenProcessToken succeeded, opened token is: " + userToken.ToString());

            // Set token security attributes
            SECURITY_ATTRIBUTES tokenAttributes = new SECURITY_ATTRIBUTES();
            tokenAttributes.nLength = Marshal.SizeOf(tokenAttributes);

            // Set token thread attributes
            SECURITY_ATTRIBUTES threadAttributes = new SECURITY_ATTRIBUTES();
            threadAttributes.nLength = Marshal.SizeOf(threadAttributes);

            // Duplicate the winlogon token to the new token
            if (!DuplicateTokenEx(userToken,                                           // token to duplicate
                                  GENERIC_ALL_ACCESS,                                  // access rights
                                  ref tokenAttributes,                                 // token security attributes
                                  SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, // security impersonation level
                                  TOKEN_TYPE.TokenPrimary,                             // duplicated token type
                                  out IntPtr newToken))                                // handle to receive the duplicated token
            {
                eventLog1.WriteEntry("DuplicateTokenEx failed w/ error code: " + GetLastError().ToString());
                CloseHandle(userToken);
                return false;
            }
            // eventLog1.WriteEntry("DuplicateTokenEx succeeded, duplicated token is: " + newToken.ToString());

            // Create token privileges structure
            TOKEN_PRIVILEGES tokPrivs = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1
            };
            LUID seDebugNameValue = new LUID();

            // Lookup the existing token privileges so we can adjust them after
            if (!LookupPrivilegeValue(null, SE_DEBUG_NAME, ref seDebugNameValue)) // null attempts to find privileges on LOCAL_SYSTEM
            {
                eventLog1.WriteEntry("LookupPrivilegeValue failed w/ error code: " + GetLastError().ToString());
                CloseHandle(newToken);
                CloseHandle(userToken);
                return false;
            }
            // eventLog1.WriteEntry("LookupPrivilegeValue succeeded.");

            // Fill token privileges structure with the existing privileges + SE_ENABLED
            tokPrivs.Privileges = new LUID_AND_ATTRIBUTES[1];
            tokPrivs.Privileges[0].Luid = seDebugNameValue;
            tokPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            // Escalate the new token's privileges
            if (!AdjustTokenPrivileges(newToken, false, ref tokPrivs, 0, IntPtr.Zero, IntPtr.Zero))
            {
                eventLog1.WriteEntry("AdjustTokenPrivileges failed w/ error code: " + GetLastError().ToString());
                CloseHandle(newToken);
                CloseHandle(userToken);
                return false;
            }
            eventLog1.WriteEntry("AdjustTokenPrivilege succeeded.");

            // Path of the Fractal Protocol executable
            string AppName = "C:\\Program Files\\Fractal\\fractal-protocol\\server\\server.exe";

            // Initialize the process structure
            pi = new PROCESS_INFORMATION();

            // Initialize the process startup info and set it to Winlogon to run on the lock screen
            STARTUPINFO si = new STARTUPINFO();
            si.cb = (uint) Marshal.SizeOf(si);
            si.lpDesktop = null;

            //si.lpDesktop = "Winsta0\\default";
            //si.lpDesktop = "Winsta0\\Winlogon";
            //si.dwFlags = STARTF_USESHOWWINDOW;
            //si.wShowWindow = (short) ShowWindowCommands.Show;

            // CreateProcess flags
            uint dwCreationFlags = (uint) CreateProcessFlags.CREATE_NEW_CONSOLE | (uint) CreateProcessFlags.INHERIT_CALLER_PRIORITY;

            // Launch the process in the client's logon session using the new token
            if (!CreateProcessAsUser(newToken,                // client's access token
                                     AppName,                 // file to execute
                                     null,                    // command line
                                     ref tokenAttributes,     // pointer to process SECURITY_ATTRIBUTES
                                     ref threadAttributes,    // pointer to thread SECURITY_ATTRIBUTES
                                     false,                    // handles are not inheritable
                                     dwCreationFlags,         // creation flags
                                     IntPtr.Zero,             // pointer to new environment block 
                                     null,                    // name of current directory 
                                     ref si,                  // pointer to STARTUPINFO structure
                                     out pi))                 // receives information about new process
            {
                eventLog1.WriteEntry("CreateProcessAsUser failed w/ error code: " + GetLastError().ToString());
                CloseHandle(newToken);
                CloseHandle(userToken);
                return false;
            }
            eventLog1.WriteEntry("CreateProcessAsUser succeeded.");

            // Confirm the process is running
            Process _p = Process.GetProcessById((int) pi.dwProcessId);
            if (_p != null)
            {
                eventLog1.WriteEntry("Found our process with ID: " + _p.Id + " and name: " + _p.ProcessName);
            }
            else
            {
                EventLog.WriteEntry("Process not found.");
            }
            
            // Close handles task now that the process is launched, process information is in PROCESS_INFORMATION pi
            CloseHandle(newToken);
            CloseHandle(userToken);

            // Done launching the console process
            eventLog1.WriteEntry("Console Process launched - End of LaunchConsoleProcess.");
            return true;
        }

        // Monitors the launched process and restart it if it crashes
        public void MonitorProcess()
        {
            // For debugging
            eventLog1.WriteEntry("In MonitorProcess. Process monitoring started.");

            // Monitor the process until the service gets manually stopped in Windows Services
            while (service_is_running)
            {
                // Wait for the process to terminate, if it does we reset all the variables and restart it
                if (WaitForSingleObject(pi.hProcess, INFINITE) == WAIT_OBJECT_0)
                {
                    // For debugging
                    eventLog1.WriteEntry("Application crashed, restarting a new process.");

                    // Reset the PROCESS_INFORMATION handles
                    pi.hProcess = IntPtr.Zero;
                    pi.hThread = IntPtr.Zero;

                    // Restart the process!
                    if (!LaunchConsoleProcess())
                    {
                        eventLog1.WriteEntry("Failed to restart Fractal Protocol as console process w/ error code: " + GetLastError().ToString());
                        return;
                    }
                    eventLog1.WriteEntry("Successfully restarted Fractal Protocol as console process.");
                }
            }
            // Exited the forever loop, service is getting stopped manually
        }
    }
}