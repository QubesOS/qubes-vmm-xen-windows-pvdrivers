using System;
using System.Collections;
using System.Configuration.Install;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Reflection;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;


namespace ShutdownMon
{
    class Program : ServiceBase
    {
        const UInt32 READ_CONTROL = 0x00020000;
        const UInt32 STANDARD_RIGHTS_READ = READ_CONTROL;
        const UInt32 FILE_READ_DATA = 0x0001;
        const UInt32 FILE_READ_ATTRIBUTES = 0x0080;
        const UInt32 FILE_READ_EA = 0x0008;
        const UInt32 SYNCHRONIZE = 0x00100000;
        const UInt32 OPEN_EXISTING = 3;
        const UInt32 FILE_GENERIC_READ = (STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE);
        const UInt32 FILE_ATTRIBUTE_NORMAL = 0x0080;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern SafeFileHandle CreateFile(
            String Filename,
            UInt32 DesiredAccess,
            UInt32 ShareMode,
            IntPtr Attributes,
            UInt32 CreationDisposition,
            UInt32 FlagsAndAttributes,
            IntPtr TemplateFile);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern bool ExitWindowsEx(int flg, int rea);

        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        internal const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
        internal const int EWX_LOGOFF = 0x00000000;
        internal const int EWX_SHUTDOWN = 0x00000001;
        internal const int EWX_REBOOT = 0x00000002;
        internal const int EWX_FORCE = 0x00000004;
        internal const int EWX_POWEROFF = 0x00000008;
        internal const int EWX_FORCEIFHUNG = 0x00000010;

        private static void DoExitWin(int flg)
        {
            bool ok;
            TokPriv1Luid tp;
            IntPtr hproc = GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            ok = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            ok = LookupPrivilegeValue(null, SE_SHUTDOWN_NAME, ref tp.Luid);
            ok = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero,
            IntPtr.Zero);
            ok = ExitWindowsEx(flg, 0);
        }

        const string MyServiceName = "XenShutdownMon";
        const string MyDisplayName = "Xen Shutdown Monitor Service";
        const string MyServiceDescription = "Monitors the kernel driver and shuts down Windows when directed";

        static void Main(string[] args)
        {
            int argNo = 0;

            while (argNo < args.Length)
            {
                string arg = args[argNo++];
                switch (arg)
                {
                    case "-i":
                        {
                            IDictionary mySavedState = new Hashtable();

                            Installer i = new Installer();
                            i.Context = new InstallContext();
                            i.Context.Parameters.Add("AssemblyPath", Assembly.GetExecutingAssembly().Location);
                            i.Context.Parameters.Add("LogToConsole", "false");
                            i.Context.Parameters.Add("Silent", "true");

                            ServiceProcessInstaller spi = new ServiceProcessInstaller();
                            spi.Account = ServiceAccount.LocalSystem;
                            spi.Username = "";
                            spi.Password = "";
                            i.Installers.Add(spi);

                            ServiceInstaller si = new ServiceInstaller();
                            si.ServiceName = MyServiceName;
                            si.DisplayName = MyDisplayName;
                            si.Description = MyServiceDescription;
                            si.StartType = ServiceStartMode.Manual;
                            i.Installers.Add(si);

                            try
                            {
                                i.Install(mySavedState);

                                Microsoft.Win32.RegistryKey config;
                                config = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("System").OpenSubKey("CurrentControlSet").OpenSubKey("Services").OpenSubKey(si.ServiceName, true);
                                if (args.Length > 1)
                                {
                                    config.SetValue("ImagePath", config.GetValue("ImagePath") + " -s " + string.Join(" ", args, argNo, args.Length - argNo - 1));
                                }
                                else
                                {
                                    config.SetValue("ImagePath", config.GetValue("ImagePath") + " -s");
                                }

                                Console.WriteLine("Service installed successfully.");
                            }
                            catch (Win32Exception exWin32Exception)
                            {
                                if (exWin32Exception.NativeErrorCode == 1073)
                                {
                                    Console.WriteLine("Service already exists.");
                                    return;
                                }
                                else
                                    throw exWin32Exception;
                            }
                            return;
                        }
                    case "-u":
                        {
                            IDictionary mySavedState = new Hashtable();
                            Installer i = new Installer();
                            i.Context = new InstallContext(null, new string[] { "assemblypath=\"" + Assembly.GetExecutingAssembly().Location + "\" -s", "LogToConsole=false", "Silent=true" });

                            ServiceProcessInstaller spi = new ServiceProcessInstaller();
                            spi.Account = ServiceAccount.LocalSystem;
                            spi.Username = "";
                            spi.Password = "";
                            i.Installers.Add(spi);

                            ServiceInstaller si = new ServiceInstaller();
                            si.ServiceName = MyServiceName;
                            si.DisplayName = MyDisplayName;
                            si.Description = MyServiceDescription;
                            si.StartType = ServiceStartMode.Manual;
                            i.Installers.Add(si);

                            try
                            {
                                i.Uninstall(null);
                                Console.WriteLine("Service uninstalled successfully.");
                            }
                            catch (InstallException exInstallException)
                            {
                                if (exInstallException.InnerException is Win32Exception)
                                {
                                    Win32Exception exWin32Exception = (Win32Exception)exInstallException.InnerException;
                                    if (exWin32Exception.NativeErrorCode == 1060)
                                    {
                                        Console.WriteLine("Service does not exist.");
                                        return;
                                    }
                                }
                                throw exInstallException;
                            }
                            return;
                        }
                    case "-s": // run as service
                        ServiceBase.Run(new Program());
                        return;
                }
            }
            Console.WriteLine("Connecting to kernel driver...");
            new Program().Run();
        }

        public Program()
        {
            this.ServiceName = MyServiceName;
            this.CanHandlePowerEvent = false;
            this.CanHandleSessionChangeEvent = false;
            this.CanPauseAndContinue = false;
            this.CanShutdown = false;
            this.CanStop = true;
        }

        private Thread workerThread = null;

        protected override void OnStart(string[] args)
        {
            workerThread = new Thread(new ThreadStart(Run));
            workerThread.Start();
        }

        protected override void OnStop()
        {
            workerThread.Abort();
        }

        protected void Run()
        {
            SafeFileHandle handle;
            byte[] buf = new byte[128];

            handle = CreateFile(@"\\.\XenShutdown", FILE_GENERIC_READ, 0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
            FileStream fs = new FileStream(handle, FileAccess.Read);
            StreamReader sr = new StreamReader(fs);

            while (true)
            {
                string command = sr.ReadLine();

                Console.WriteLine("Command = " + command);

                switch (command)
                {
                    case "":
                        break;
                    case "reboot":
                        DoExitWin(EWX_REBOOT | EWX_FORCE);
                        break;
                    case "poweroff":
                    case "halt":
                    default:
                        DoExitWin(EWX_POWEROFF | EWX_FORCE);
                        break;
                }
            }
        }
    }
}
