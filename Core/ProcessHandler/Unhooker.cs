using System.Runtime.InteropServices;
using Microsoft.Win32;
using System;
using System.Text;
using System.Diagnostics;
using Core.WindowsInternals;

namespace Core.ProcessHandler
{
    internal class Hook
    {
        internal static string GetWinVer()
        {
            var installPath = (string) Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ReleaseId", null);
            if (installPath != null)
            {
                return installPath;
            }

            return "";
        }

        internal static string GetCurrentVer()
        {
            var installPath = (string) Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentVersion", null);
            if (installPath != null)
            {
                return installPath;
            }

            return "";
        }

        internal static string GetProductName()
        {
            var installPath = (string) Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", null);
            if (installPath != null)
            {
                return installPath;
            }

            return "";
        }

        internal static string FreeMemory(string location)
        {
            bool vFree;

            if (IntPtr.Size == 8)
            {
                vFree = Internals.VirtualFree(new IntPtr(Convert.ToInt64(location.Replace("0x", ""), 16)), IntPtr.Zero, Internals.AllocationType.Release);
            }
            else
            {
                vFree = Internals.VirtualFree(new IntPtr(Convert.ToInt32(location.Replace("0x", ""), 16)), IntPtr.Zero, Internals.AllocationType.Release);
            }

            if (!vFree)
            {
                return "\n[-] VirtualFree DLL in Memory after Injection: Failed";
            }

            return "\n[+] VirtualFree DLL in Memory after Injection: True";
        }

        internal static string UHookVMemory(byte sysCallId = 0x18)
        {
            var targetDLL = Internals.LoadLibrary("ntdll.dll");
            if (targetDLL == IntPtr.Zero)
            {
                return "[-] Error cannot find ntdll.dll";
            }

            var funcAddress = Internals.GetProcAddress(targetDLL, "ZwAllocateVirtualMemory");
            if (funcAddress == IntPtr.Zero)
            {
                return "[-] Error cannot find ZwAllocateVirtualMemory";
            }

            const int dwSize = 5;
            if (!Internals.VirtualProtect(funcAddress, dwSize, 0x40, out var zero))
            {
                return "[-] Error cannot change memory protection";
            }

            byte[] patch = {0x4c, 0x8b, 0xd1, 0xb8, sysCallId, 0x00, 0x00, 0x00};
            var unmanagedPointer = Marshal.AllocHGlobal(8);
            Marshal.Copy(patch, 0, unmanagedPointer, 8);
            Internals.RtlMoveMemory(funcAddress, unmanagedPointer, 8);
            Internals.VirtualProtect(funcAddress, dwSize, zero, out zero);
            return "\n[>] Memory location of ZwAllocateVirtualMemory: " + funcAddress.ToString("X8") + "\n[+] ZwAllocateVirtualMemory Patched\n";
        }

        internal static string UHookOProcess(byte sysCallId = 0x26)
        {
            var targetDLL = Internals.LoadLibrary("ntdll.dll");
            if (targetDLL == IntPtr.Zero)
            {
                return "[-] Error cannot find ntdll.dll";
            }

            var procAddress = Internals.GetProcAddress(targetDLL, "ZwOpenProcess");
            if (procAddress == IntPtr.Zero)
            {
                return "[-] Error cannot find ZwOpenProcess";
            }

            const int dwSize = 5;
            if (!Internals.VirtualProtect(procAddress, dwSize, 0x40, out var zero))
            {
                return "[-] Error cannot change memory protection";
            }

            byte[] patch = {0x4c, 0x8b, 0xd1, 0xb8, sysCallId, 0x00, 0x00, 0x00};
            var unmanagedPointer = Marshal.AllocHGlobal(8);
            Marshal.Copy(patch, 0, unmanagedPointer, 8);
            Internals.RtlMoveMemory(procAddress, unmanagedPointer, 8);
            Internals.VirtualProtect(procAddress, dwSize, zero, out zero);
            return "\n[>] Memory location of ZwOpenProcess: " + procAddress.ToString("X8") + "\n[+] ZwOpenProcess Patched\n";
        }

        internal static string UHookRMemory(byte sysCallId = 0x3f)
        {
            var targetDLL = Internals.LoadLibrary("ntdll.dll");
            if (targetDLL == IntPtr.Zero)
            {
                return "[-] Error cannot find ntdll.dll";
            }

            var procAddress = Internals.GetProcAddress(targetDLL, "NtReadVirtualMemory");
            if (procAddress == IntPtr.Zero)
            {
                return "[-] Error cannot find NtReadVirtualMemory";
            }

            const int dwSize = 5;
            if (!Internals.VirtualProtect(procAddress, dwSize, 0x40, out var zero))
            {
                return "[-] Error cannot change memory protection";
            }

            byte[] patch = {0x4c, 0x8b, 0xd1, 0xb8, sysCallId, 0x00, 0x00, 0x00};
            var unmanagedPointer = Marshal.AllocHGlobal(8);
            Marshal.Copy(patch, 0, unmanagedPointer, 8);
            Internals.RtlMoveMemory(procAddress, unmanagedPointer, 8);
            Internals.VirtualProtect(procAddress, dwSize, zero, out zero);
            return "\n[>] Memory location of NtReadVirtualMemory: " + procAddress.ToString("X8") + "\n[+] NtReadVirtualMemory Patched\n";
        }

        internal static string UHookWMemory(byte sysCallId = 0x3a)
        {
            var targetDLL = Internals.LoadLibrary("ntdll.dll");
            if (targetDLL == IntPtr.Zero)
            {
                return "[-] Error cannot find ntdll.dll";
            }

            var loadLibrary = Internals.GetProcAddress(targetDLL, "NtWriteVirtualMemory");
            if (loadLibrary == IntPtr.Zero)
            {
                return "[-] Error cannot find NtWriteVirtualMemory";
            }

            const int dwSize = 5;
            if (!Internals.VirtualProtect(loadLibrary, dwSize, 0x40, out var zero))
            {
                return "[-] Error cannot change memory protection";
            }

            byte[] patch = {0x4c, 0x8b, 0xd1, 0xb8, sysCallId, 0x00, 0x00, 0x00};
            var unmanagedPointer = Marshal.AllocHGlobal(8);
            Marshal.Copy(patch, 0, unmanagedPointer, 8);
            Internals.RtlMoveMemory(loadLibrary, unmanagedPointer, 8);
            Internals.VirtualProtect(loadLibrary, dwSize, zero, out zero);
            return "\n[>] Memory location of NtWriteVirtualMemory: " + loadLibrary.ToString("X8") + "\n[+] NtWriteVirtualMemory Patched\n";
        }

        internal static string UHookMvSection(byte sysCallId = 0x28)
        {
            var targetDLL = Internals.LoadLibrary("ntdll.dll");
            if (targetDLL == IntPtr.Zero)
            {
                return "[-] Error cannot find ntdll.dll";
            }

            var procAddress = Internals.GetProcAddress(targetDLL, "NtMapViewOfSection");
            if (procAddress == IntPtr.Zero)
            {
                return "[-] Error cannot find NtMapViewOfSection";
            }

            const int dwSize = 5;
            if (!Internals.VirtualProtect(procAddress, dwSize, 0x40, out var zero))
            {
                return "[-] Error cannot change memory protection";
            }

            byte[] patch = {0x4c, 0x8b, 0xd1, 0xb8, sysCallId, 0x00, 0x00, 0x00};
            var unmanagedPointer = Marshal.AllocHGlobal(8);
            Marshal.Copy(patch, 0, unmanagedPointer, 8);
            Internals.RtlMoveMemory(procAddress, unmanagedPointer, 8);
            Internals.VirtualProtect(procAddress, dwSize, zero, out zero);
            return "\n[>] Memory location of NtMapViewOfSection: " + procAddress.ToString("X8") + "\n[+] NtMapViewOfSection Patched\n";
        }

        internal static string UHook(byte sysCallId)
        {
            var targetDLL = Internals.LoadLibrary("ntdll.dll");
            if (targetDLL == IntPtr.Zero)
            {
                return "[-] Error cannot find ntdll.dll";
            }

            var procAddress = Internals.GetProcAddress(targetDLL, "ZwCreateThreadEx");
            if (procAddress == IntPtr.Zero)
            {
                return "[-] Error cannot find ZwCreateThreadEx";
            }

            const int dwSize = 5;
            if (!Internals.VirtualProtect(procAddress, dwSize, 0x40, out var zero))
            {
                return "[-] Error cannot change memory protection";
            }

            byte[] patch = {0x4c, 0x8b, 0xd1, 0xb8, sysCallId, 0x00, 0x00, 0x00};
            var unmanagedPointer = Marshal.AllocHGlobal(8);
            Marshal.Copy(patch, 0, unmanagedPointer, 8);
            Internals.RtlMoveMemory(procAddress, unmanagedPointer, 8);
            Internals.VirtualProtect(procAddress, dwSize, zero, out zero);
            return "\n[>] Memory location of ZwCreateThreadEx: " + procAddress.ToString("X8") + "\n[+] ZwCreateThreadEx Patched\n";
        }

        internal static string UHooker(byte sysCallId, string apiCall)
        {
            var targetDLL = Internals.LoadLibrary("ntdll.dll");
            if (targetDLL == IntPtr.Zero)
            {
                return "[-] Error cannot find ntdll.dll";
            }

            var procAddress = Internals.GetProcAddress(targetDLL, apiCall);
            if (procAddress == IntPtr.Zero)
            {
                return "[-] Error cannot find " + apiCall;
            }

            const int dwSize = 5;
            if (!Internals.VirtualProtect(procAddress, dwSize, 0x40, out var zero))
            {
                return "[-] Error cannot change memory protection";
            }

            byte[] patch = {0x4c, 0x8b, 0xd1, 0xb8, sysCallId, 0x00, 0x00, 0x00};
            var unmanagedPointer = Marshal.AllocHGlobal(8);
            Marshal.Copy(patch, 0, unmanagedPointer, 8);
            Internals.RtlMoveMemory(procAddress, unmanagedPointer, 8);
            Internals.VirtualProtect(procAddress, dwSize, zero, out zero);
            return "\n[>] Memory location of " + apiCall + ": " + procAddress.ToString("X8") + "\n[+] " + apiCall + " Patched\n";
        }

        internal static string APICall(string dll, string apiCall)
        {
            var targetDLL = Internals.LoadLibrary(dll);
            if (targetDLL == IntPtr.Zero)
            {
                return $"[-] Error cannot find {dll}";
            }

            var procAddress = Internals.GetProcAddress(targetDLL, apiCall);
            if (procAddress == IntPtr.Zero)
            {
                return "[-] Error cannot find " + apiCall;
            }

            Marshal.ReadInt64(procAddress);
            var x = Process.GetCurrentProcess();

            return "\n[>] Memory location of " + apiCall + ": " + $"{procAddress.ToInt64():X8}" + "\n > ASM > " + ReadInt(x.Handle, procAddress);
        }

        internal static string HookRet(string dll, string function)
        {
            var ntdllPtr = Internals.LoadLibrary(dll);
            if (ntdllPtr == IntPtr.Zero)
            {
                return $"[-] Error cannot find {dll}";
            }

            var pFunc = Internals.GetProcAddress(ntdllPtr, function);
            if (pFunc == IntPtr.Zero)
            {
                return $"[-] Error cannot find {function}";
            }

            if (!Internals.VirtualProtect(pFunc, 1, 0x40, out var dwOldProtection))
            {
                return "[-] Error cannot change memory protection";
            }

            byte[] patch = {0xE9};

            var unmanagedPointer = Marshal.AllocHGlobal(1);
            Marshal.Copy(patch, 0, unmanagedPointer, 1);
            Internals.RtlMoveMemory(pFunc, unmanagedPointer, 8);

            if (!Internals.VirtualProtect(pFunc, 1, dwOldProtection, out _))
            {
                return "[-] Error cannot change memory protection back to original";
            }

            return $"\n[>] Successfully hooked {dll} : {function} with 0xE9 # ret";
        }
        
        private static string ByteArrayToString(byte[] ba)
        {
            var hex = new StringBuilder(ba.Length * 2);
            foreach (var b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        private static string ReadInt(IntPtr handle, IntPtr address)
        {
            var dataBuffer = new byte[8];
            Internals.ReadProcessMemory(handle, address, dataBuffer, dataBuffer.Length, out var bytesRead);
            if (bytesRead == IntPtr.Zero)
            {
                Console.WriteLine("Mo bytes has been read");
            }

            return ByteArrayToString(dataBuffer);
        }
    }
}