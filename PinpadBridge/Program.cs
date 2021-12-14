using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;

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
        }
    }
}
