using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Timers;
using System.Security;
using System.Runtime.InteropServices;
using System.Security.Principal;

// Enums
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


// Service namespace
namespace FractalService
{
    public partial class FractalService : ServiceBase
    {
        // DLL imports for Windows API functions
        #region DLL Imports
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        internal const int TOKEN_ASSIGN_PRIMARY = 0x0001;
        internal const int TOKEN_DUPLICATE = 0x0002;
        internal const int TOKEN_IMPERSONATE = 0X00000004;
        internal const int TOKEN_ADJUST_DEFAULT = 0x0080;
        internal const int TOKEN_ADJUST_SESSIONID = 0x0100;
        internal const int MAXIMUM_ALLOWED = 0x2000000;
        internal const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        internal const int NORMAL_PRIORITY_CLASS = 0x20;
        internal const int CREATE_NEW_CONSOLE = 0x00000010;

        internal const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
        internal const string SE_TCB_NAME = "SeTcbPrivilege";
        internal const string SE_RESTORE_NAME = "SeRestorePrivilege";

        private static WindowsImpersonationContext impersonatedUser;
        public static IntPtr hToken = IntPtr.Zero;
        public static IntPtr dupeTokenHandle = IntPtr.Zero;
        const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";

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

        [DllImport("shell32.dll")]
        static extern IntPtr ShellExecute(
         IntPtr hwnd,
         string lpOperation,
         string lpFile,
         string lpParameters,
         string lpDirectory,
         ShowCommands nShowCmd);

        // dlls
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetServiceStatus(System.IntPtr handle, ref ServiceStatus serviceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern int ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

        [DllImport("kernel32", SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32", SetLastError = true)]
        static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll", SetLastError = true)]
        static extern bool WTSQueryUserToken(UInt32 sessionID, out IntPtr hToken);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, ref IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        static extern bool DuplicateTokenEx(IntPtr hExistingToken, Int32 dwDesiredAccess,
                            ref SECURITY_ATTRIBUTES lpThreadAttributes,
                            Int32 ImpersonationLevel, Int32 dwTokenType,
                            ref IntPtr phNewToken);

        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessAsUser(
            IntPtr hToken,
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
        #endregion

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

        // Function that runs when the program starts.
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

            //****** Beginning of Console Impersonation to run on headless VM ******\\
            // Obtain the console ID, should be 1 (may vary?)
            uint consoleID;
            consoleID = WTSGetActiveConsoleSessionId();
            eventLog1.WriteEntry("Console session ID is: " + consoleID.ToString()); // for debugging

            // Define Tokens for impersonating the user
            IntPtr LoggedInUserToken = IntPtr.Zero;
            IntPtr DuplicatedToken = IntPtr.Zero;

            // Obtain the console user token, we will duplicate it to "fake" being in the console
            if (!WTSQueryUserToken(consoleID, out LoggedInUserToken))
            {
                // FALSE returned, failed to query the console user token
                eventLog1.WriteEntry("WTSQueryUserToken returned false, could not query console user token.");
                return;                    
            }
            eventLog1.WriteEntry("WTSQueryUserToken worked, Console user token is: " + LoggedInUserToken.ToString());

            // Create new security attribute struct that will be filled when we duplicate the token to a primary token
            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();

            // Duplicate the console token to a primary token so we can use it to create a new process
            // 2 = SECURITY_IMPERSONATION
            // 1 = TOKEN_PRIMARY
            if (!DuplicateTokenEx(LoggedInUserToken, MAXIMUM_ALLOWED, ref sa, 2, 1, ref DuplicatedToken)) {
                // FALSE returned, failed to duplicate the console user token
                eventLog1.WriteEntry("DuplicateTokenEx returned false, could not duplicate console user token.");
                return;
            }
            eventLog1.WriteEntry("DuplicateTokenEx worked, Duplicated token is: " + DuplicatedToken.ToString());

            // Impersonate the console user on our duplicated token to have console privileges
            if (ImpersonateLoggedOnUser(DuplicatedToken) == 0)
            {
                // 0 returned, failed to impersonate console user token
                eventLog1.WriteEntry("ImpersonateLoggedOnUser returned 0, could not impersonate console user token.");                 
            }
            eventLog1.WriteEntry("ImpersonateLoggedOnUser worked, console user impersonated on DuplicatedToken)");







            // here







        }

        // Function that runs when the program stops.
        protected override void OnStop()
        {
            // Write to log for debugging
            eventLog1.WriteEntry("In OnStop - Stopping the service.");

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
    }
}
