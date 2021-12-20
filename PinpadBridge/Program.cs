using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using MilliwaysServiceManager;

namespace PinpadBridge
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool AllocConsole();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern void SetStdHandle(UInt32 nStdHandle, IntPtr handle);
        const UInt32 STD_OUTPUT_HANDLE = 0xFFFFFFF5;

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                ServiceBase[] ServicesToRun;
                ServicesToRun = new ServiceBase[]
                {
                    new PinpadBridgeService()
                };
                ServiceBase.Run(ServicesToRun);
            }
            else if ((args.Length == 1) && (args[0] == "/d"))
            {
                AllocConsole();

                PinpadBridgeService pinpad = new PinpadBridgeService();
                Console.WriteLine("Starting service...");
                pinpad.DoStart();
                Console.WriteLine("Press any key to stop...");
                Console.ReadKey();
                pinpad.DoStop();
            }
            else if ((args.Length == 1) && (args[0] == "/i"))
            {
                using (ServiceManager sm = new MilliwaysServiceManager.ServiceManager())
                {
                    sm.Install
                    (
                        "PinpadBridge", "PinpadBridge", System.Reflection.Assembly.GetEntryAssembly().Location,
                        ServiceManager.SERVICE_TYPE.WIN32_OWN_PROCESS, ServiceManager.SERVICE_START_TYPE.AUTO, ServiceManager.SERVICE_ERROR_TYPE.NORMAL, null
                    );
                }
            }
            else if ((args.Length == 1) && (args[0] == "/u"))
            {
                using (ServiceManager sm = new MilliwaysServiceManager.ServiceManager())
                {
                    sm.Uninstall("PinpadBridge");
                }
            }
        }
    }
}
