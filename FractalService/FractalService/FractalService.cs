using System;
using System.ServiceProcess;
using System.Security;
using System.Runtime.InteropServices;
using System.Threading;

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
        public const uint TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE |
                                              TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
                                              TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
                                              TOKEN_ADJUST_SESSIONID);

        internal const uint INFINITE = 0xFFFFFFFF;
        internal const uint WAIT_ABANDONED = 0x00000080;
        internal const uint WAIT_OBJECT_0 = 0x00000000;
        internal const uint WAIT_TIMEOUT = 0x00000102;
        internal const uint STILL_ACTIVE = 259; // for GetExitCode

        internal const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
        internal const string SE_TCB_NAME = "SeTcbPrivilege";
        internal const string SE_RESTORE_NAME = "SeRestorePrivilege";
        internal const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";

        IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
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
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)] // arbitrary size
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
        #endregion

        #region DLL Imports
        [DllImport("shell32.dll")]
        static extern IntPtr ShellExecute(IntPtr hwnd, string lpOperation, string lpFile, string lpParameters, string lpDirectory, ShowCommands nShowCmd);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetServiceStatus(IntPtr handle, ref ServiceStatus serviceStatus);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern int ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, ref uint TokenInformation, uint TokenInformationLength);

        [DllImport("kernel32.dll", SetLastError = true), SuppressUnmanagedCodeSecurity]
        static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll", SetLastError = true)]
        static extern bool WTSQueryUserToken(uint sessionID, out IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, uint processId);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, ref IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        static extern bool DuplicateTokenEx(IntPtr hExistingToken, int dwDesiredAccess, ref SECURITY_ATTRIBUTES lpThreadAttributes, int ImpersonationLevel, int dwTokenType, ref IntPtr phNewToken);

        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        
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
        #endregion

        // Service global variables
        bool service_is_running = true; // to know whether to monitor the service
        bool bElevate = true; // to know whether to elevate privileges
        IntPtr ConsoleEnvironment = IntPtr.Zero; // environment block handle
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
            ServiceStatus serviceStatus = new ServiceStatus();
            serviceStatus.dwCurrentState = ServiceState.SERVICE_START_PENDING;
            serviceStatus.dwWaitHint = 100000;
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
            eventLog1.WriteEntry("Successfully launched Fractal Protocol as console process.");

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

            // Revert the impersonation
            RevertToSelf();

            // Destroy the environment block and close the process handles
            DestroyEnvironmentBlock(ConsoleEnvironment);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);

            // Update the service state to Stop Pending.
            ServiceStatus serviceStatus = new ServiceStatus();
            serviceStatus.dwCurrentState = ServiceState.SERVICE_STOP_PENDING;
            serviceStatus.dwWaitHint = 100000;
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

            // Function variables
            bool bResult = false;
            uint consoleSessionId;
            uint winlogonPid = 0; // dummy init value
            IntPtr hUserToken = IntPtr.Zero;
            IntPtr hUserTokenDup = IntPtr.Zero;
            IntPtr hPToken = IntPtr.Zero;
            IntPtr hProcess = IntPtr.Zero;

            // Obtain the console ID, should be 1             
            consoleSessionId = WTSGetActiveConsoleSessionId();
            eventLog1.WriteEntry("Console session ID is: " + consoleSessionId.ToString()); // for debugging

            // Find the winlogon process
            PROCESSENTRY32 procEntry = new PROCESSENTRY32();

            // Create the snapshot tool
            IntPtr handleToSnapshot = CreateToolhelp32Snapshot((uint) SnapshotFlags.Process, 0);
            if (handleToSnapshot == INVALID_HANDLE_VALUE)
            {
                eventLog1.WriteEntry("CreateToolhelp32Snapshot failed w/ error code: " + GetLastError().ToString());
                return false;
            }
            eventLog1.WriteEntry("CreateToolhelp32Snapshot succeeded.");

            // Get the size of the process
            procEntry.dwSize = (uint) Marshal.SizeOf(procEntry); // sizeof(PROCESSENTRY32);

            // gGt the first process from that snapshot, should contain winlogon
            if (!Process32First(handleToSnapshot, ref procEntry))
            {
                eventLog1.WriteEntry("Process32First failed w/ error code: " + GetLastError().ToString());
                return false;
            }
            eventLog1.WriteEntry("Process32First succeeded.");

            // Loop over the indices of that first process and check if it is winlogon
            string strCmp = "winlogon.exe";
            do
            {
                if (strCmp.IndexOf(procEntry.szExeFile) == 0)
                {
                    // We found a Winlogon process... make sure it's running in the console session
                    if (ProcessIdToSessionId(procEntry.th32ProcessID, out uint winlogonSessId) && winlogonSessId == consoleSessionId)
                    {
                        // It is, save the process ID and exit
                        winlogonPid = procEntry.th32ProcessID;
                        eventLog1.WriteEntry("Found Winlogon in console session, PID is: " + winlogonPid.ToString());
                        break;
                    }
                }
            } while (Process32Next(handleToSnapshot, ref procEntry));

            // Ensure we found a Winlogon PID by comparing to dummy init value
            if (winlogonPid == 0)
            {
                eventLog1.WriteEntry("Could not find Winlogon in console session.");
                CloseHandle(handleToSnapshot);
                return false;
            }

            // Get the user token used by DuplicateTokenEx in the console session
            if (!WTSQueryUserToken(consoleSessionId, out hUserToken))
            {
                eventLog1.WriteEntry("WTSQueryUserToken failed w/ error code: " + GetLastError().ToString());
                CloseHandle(handleToSnapshot);
                return false;
            }
            eventLog1.WriteEntry("WTSQueryUserToken succeeded, user token is: " + hUserToken.ToString());

            // Set variables for defining the new process
            STARTUPINFO si = new STARTUPINFO();
            si.cb = (uint) Marshal.SizeOf(si);
            si.lpDesktop = "winsta0\\default"; // crucial to run the process in console with interactive desktop
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            LUID luid = new LUID();

            // Open the winlogon process
            hProcess = OpenProcess(ProcessAccessFlags.All, false, winlogonPid);
            if (hProcess == IntPtr.Zero)
            {
                eventLog1.WriteEntry("OpenProcess failed w/ error code: " + GetLastError().ToString());
                CloseHandle(hUserToken);
                CloseHandle(handleToSnapshot);
                return false;
            }
            eventLog1.WriteEntry("OpenProcess succeeded.");

            // Open the token of the winlogon process
            if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, out hPToken))
            {
                eventLog1.WriteEntry("OpenProcessToken failed w/ error code: " + GetLastError().ToString());
                CloseHandle(hProcess);
                CloseHandle(hUserToken);
                CloseHandle(handleToSnapshot);
                return false;
            }
            eventLog1.WriteEntry("OpenProcessToken succeeded.");









            // IntPtr LoggedInUserToken = IntPtr.Zero; == hUserToken
            IntPtr DuplicatedToken = IntPtr.Zero;


  
            // eventLog1.WriteEntry("WTSQueryUserToken worked, Console user token is: " + LoggedInUserToken.ToString());
            // Create new security attribute struct that will be filled when we duplicate the token to a primary token
            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
            // Duplicate the console token to a primary token so we can use it to create a new process
            // 2 = SECURITY_IMPERSONATION
            // 1 = TOKEN_PRIMARY
            if (!DuplicateTokenEx(hUserToken, MAXIMUM_ALLOWED, ref sa, 2, 1, ref DuplicatedToken))
            {
                // FALSE returned, failed to duplicate the console user token
                eventLog1.WriteEntry("DuplicateTokenEx returned false, could not duplicate console user token w/ error code: " + GetLastError().ToString());
                CloseHandle(DuplicatedToken);
                CloseHandle(hUserToken);
                return false;
            }
            // eventLog1.WriteEntry("DuplicateTokenEx worked, Duplicated token is: " + DuplicatedToken.ToString());
            // Impersonate the console user on our duplicated token to have console privileges
            if (ImpersonateLoggedOnUser(DuplicatedToken) == 0)
            {
                // 0 returned, failed to impersonate console user token
                eventLog1.WriteEntry("ImpersonateLoggedOnUser returned 0, could not impersonate console user token w/ error code: " + GetLastError().ToString());
                CloseHandle(hUserToken);
                CloseHandle(DuplicatedToken);
                return false;
            }
            // eventLog1.WriteEntry("ImpersonateLoggedOnUser worked, console user impersonated on DuplicatedToken.");
            // Create the environment block from the console process that the new process will spawn into
            uint dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
            if (!CreateEnvironmentBlock(out ConsoleEnvironment, DuplicatedToken, true))
            {
                eventLog1.WriteEntry("CreateEnvironmentBlock returned false, could not create environment block from DuplicatedToken w/ error code: " + GetLastError().ToString());
            }
            else
            {
                // if it suceeded, we don't create a new console
                dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
                // eventLog1.WriteEntry("CreateEnvironmentBlock worked, environment block created from DuplicatedToken");
            }
            // Prepare the parameters for creating a process in the console that launches the Fractal Protocol server
            string AppName = "C:\\Windows\\System32\\notepad.exe"; // TODO: replace with protocol executable
            SECURITY_ATTRIBUTES processAttributes = new SECURITY_ATTRIBUTES();
            SECURITY_ATTRIBUTES threadAttributes = new SECURITY_ATTRIBUTES();
            //PROCESS_INFORMATION pi; // process
            STARTUPINFO si2 = new STARTUPINFO(); // startup info
            // Create a process as a console user for Fractal Protocol server
            if (!CreateProcessAsUser(DuplicatedToken, AppName, string.Empty, ref processAttributes, ref threadAttributes, true, dwCreationFlags, ConsoleEnvironment, AppName.Substring(0, AppName.LastIndexOf('\\')), ref si2, out pi))
            {
                eventLog1.WriteEntry("CreateProcessAsUser returned false, could not create Fractal Protocol process as console user.");
                RevertToSelf(); // revert impersonation
                DestroyEnvironmentBlock(ConsoleEnvironment);
                CloseHandle(hUserToken);
                CloseHandle(DuplicatedToken);
                return false;
            }
            eventLog1.WriteEntry("CreateProcessAsUser worked, Fractal Protocol server process created as console - End of LaunchConsoleProcess.");
            // eventLog1.WriteEntry("CreateProcessAsUser worked, Fractal Protocol server process created as console - End of LaunchConsoleProcess.");

            // Store the process handle in a global var
            //ProcessHandle = pi.hProcess;
            // Done with initiating the service, now we monitor the process to restart it if it crashes
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

                    // Revert impersonation
                    RevertToSelf();

                    // Destroy the environment
                    DestroyEnvironmentBlock(ConsoleEnvironment);
                    ConsoleEnvironment = IntPtr.Zero;

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