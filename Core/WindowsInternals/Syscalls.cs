using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;

namespace Core.WindowsInternals
{
    internal static class SysCall
    {
        private static readonly byte[] SYSCALL_DEFAULT = { 074, 138, 203, 185, 000, 001, 001, 001, 016, 006, 196 };

        internal static Internals.Ntstatus ZwOpenProcess(ref IntPtr hProcess, Internals.ProcessAccessFlags processAccess, Internals.ObjectAttributes objAttribute,
            ref Internals.ClientId clientId)
        {
            var ntOpenProcess = GetSyscallDelegate<NtOpenProcessX>(SysCalls.NtOpenProcess, out var alloc);
            var result = ntOpenProcess(ref hProcess, processAccess, objAttribute, ref clientId);            
            Internals.VirtualFree(alloc, (IntPtr)SYSCALL_DEFAULT.Length, Internals.AllocationType.Release);
            return result;
        }

        internal static Internals.Ntstatus ZwCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr lpStartAddress,
            IntPtr lpParameter, int createSuspended, uint stackZeroBits, uint sizeOfStackCommit, uint sizeOfStackReserve, IntPtr lpBytesBuffer)
        {
            var ntCreateThreadExFunc = GetSyscallDelegate<NtCreateThreadExX>(SysCalls.NtCreateThreadEx, out var alloc);
            var result = ntCreateThreadExFunc(out threadHandle, desiredAccess, objectAttributes, processHandle, lpStartAddress, lpParameter, createSuspended, stackZeroBits,
                sizeOfStackCommit, sizeOfStackReserve, lpBytesBuffer);
            Internals.VirtualFree(alloc, (IntPtr)SYSCALL_DEFAULT.Length, Internals.AllocationType.Release);
            return result;
        }

        internal static Internals.Ntstatus ZwWriteVirtualMemory(IntPtr hProcess, ref IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten)
        {
            var ntWriteVirtualMemoryFunc = GetSyscallDelegate<NtWriteVirtualMemoryX>(SysCalls.NtWriteVirtualMemory, out var alloc);
            var result = ntWriteVirtualMemoryFunc(hProcess, lpBaseAddress, lpBuffer, nSize, ref lpNumberOfBytesWritten);
            Internals.VirtualFree(alloc, (IntPtr)SYSCALL_DEFAULT.Length, Internals.AllocationType.Release);
            return result;
        }

        internal static Internals.Ntstatus ZwAllocateVirtualMemory(IntPtr hProcess, ref IntPtr baseAddress, IntPtr zeroBits, ref UIntPtr regionSize, ulong allocationType,
            ulong protect)
        {
            var ntAllocateVirtualMemoryFunc = GetSyscallDelegate<NtAllocateVirtualMemoryX>(SysCalls.ZwAllocateVirtualMemory, out var alloc);
            var result = ntAllocateVirtualMemoryFunc(hProcess, ref baseAddress, zeroBits, ref regionSize, allocationType, protect);
            Internals.VirtualFree(alloc, (IntPtr)SYSCALL_DEFAULT.Length, Internals.AllocationType.Release);
            return result;
        }

        internal static Internals.Ntstatus ZwProtectVirtualMemory(IntPtr hProcess, ref IntPtr lpAddress, ref IntPtr dwSize, uint flNewProtect,
            out Internals.MemoryProtection lpFlOldProtect)
        {
            var ntProtectVirtualMemoryFunc = GetSyscallDelegate<ZwProtectVirtualMemoryX>(SysCalls.ZwProtectVirtualMemory, out var alloc);
            var result = ntProtectVirtualMemoryFunc(hProcess, ref lpAddress, ref dwSize, flNewProtect, out lpFlOldProtect);
            Internals.VirtualFree(alloc, (IntPtr)SYSCALL_DEFAULT.Length, Internals.AllocationType.Release);
            return result;
        }

        internal static Internals.Ntstatus ZwCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref Internals.LargeInteger pMaxSize, uint pageProt,
            uint allocationAttribs, IntPtr hFile)
        {
            var ntCreateSectionFunc = GetSyscallDelegate<NtCreateSectionX>(SysCalls.NtCreateSection, out var alloc);
            var result = ntCreateSectionFunc(ref section, desiredAccess, pAttrs, ref pMaxSize, pageProt, allocationAttribs, hFile);
            Internals.VirtualFree(alloc, (IntPtr)SYSCALL_DEFAULT.Length, Internals.AllocationType.Release);
            return result;
        }

        internal static Internals.Ntstatus ZwMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff,
            ref IntPtr viewSize, int inheritDisposition, uint allocType, uint protections)
        {
            var ntMapViewOfSectionFunc = GetSyscallDelegate<ZwMapViewOfSectionX>(SysCalls.ZwMapViewOfSection, out var alloc);
            var result = ntMapViewOfSectionFunc(section, process, ref baseAddr, zeroBits, commitSize, stuff, ref viewSize, inheritDisposition, allocType, protections);
            Internals.VirtualFree(alloc, (IntPtr)SYSCALL_DEFAULT.Length, Internals.AllocationType.Release);
            return result;
        }

        internal static Internals.Ntstatus ZwCreateProcess(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, bool inheritObjectTable,
            IntPtr sectionHandle, IntPtr debugPort, IntPtr exceptionPort)
        {
            var ntCreateProcessFunc = GetSyscallDelegate<ZwCreateProcessX>(SysCalls.NtCreateProcess, out var alloc);
            var result = ntCreateProcessFunc(out threadHandle, desiredAccess, objectAttributes, processHandle, inheritObjectTable, sectionHandle, debugPort, exceptionPort);
            Internals.VirtualFree(alloc, (IntPtr)SYSCALL_DEFAULT.Length, Internals.AllocationType.Release);
            return result;
        }

        private enum WindowsVersions
        {
            Server2016 = 14393,
            Server2012_R2 = 9600,
            Windows7_SP1 = 7601,
            Windows10_1809 = 17763,
            Windows10_1803 = 17134,
            Windows10_1903 = 18362,
            Windows10_1909 = 18363,
            Windows10_2004 = 19041,
            Windows10_20H2 = 19042,
            Windows10_21H1 = 19043,
            Windows10_21H2 = 19044,
            Windows10_22H2 = 19045,
            Windows10_21H22 = 22000
        }

        private enum SysCalls
        {
            NtOpenProcess = 1,
            NtCreateThreadEx = 2,
            NtWriteVirtualMemory = 3,
            ZwAllocateVirtualMemory = 4,
            NtCreateSection = 5,
            ZwMapViewOfSection = 6,
            NtCreateProcess = 7,
            ZwProtectVirtualMemory = 8,
        }

        [SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate Internals.Ntstatus NtOpenProcessX(ref IntPtr hProcess, Internals.ProcessAccessFlags processAccess, Internals.ObjectAttributes objAttribute,
            ref Internals.ClientId clientId);

        [SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate Internals.Ntstatus NtWriteVirtualMemoryX(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten);

        [SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate Internals.Ntstatus NtAllocateVirtualMemoryX(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref UIntPtr regionSize, ulong allocationType,
            ulong protect);

        [SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate Internals.Ntstatus NtCreateThreadExX(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr lpStartAddress,
            IntPtr lpParameter, int createSuspended, uint stackZeroBits, uint sizeOfStackCommit, uint sizeOfStackReserve, IntPtr lpBytesBuffer);

        [SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate Internals.Ntstatus NtCreateSectionX(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref Internals.LargeInteger pMaxSize, uint pageProtections,
            uint allocationAttribs, IntPtr hFile);

        [SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate Internals.Ntstatus ZwMapViewOfSectionX(IntPtr section, IntPtr process, ref IntPtr baseAddress, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff,
            ref IntPtr viewSize, int inheritDisposition, uint allocationType, uint protections);

        [SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate Internals.Ntstatus ZwProtectVirtualMemoryX(IntPtr hProcess, ref IntPtr lpAddress, ref IntPtr dwSize, uint flNewProtect,
            out Internals.MemoryProtection oldProtect);

        [SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate Internals.Ntstatus ZwCreateProcessX(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, bool inheritObjectTable,
            IntPtr sectionHandle, IntPtr debugPort, IntPtr exceptionPort);

        private static T GetSyscallDelegate<T>(SysCalls syscallType, out IntPtr alloc) where T : Delegate
        {
            alloc = GetOsVersionAndReturnSyscall(syscallType);
            Console.WriteLine($" > [+] {typeof(T)} syscall allocated RW at: 0x{alloc.ToInt64():X}");
            unsafe
            {
                var ptr = (byte*)alloc;
                var allocMemAddress = (IntPtr)ptr;
                var size = (uint)SYSCALL_DEFAULT.Length;
                var func = (T)Marshal.GetDelegateForFunctionPointer((IntPtr)ptr, typeof(T));
                Internals.ZwProtectVirtualMemory(Process.GetCurrentProcess().Handle, ref allocMemAddress, ref size, Internals.MemoryProtection.ExecuteRead,
                    out _);
                Console.WriteLine($" > [+] {typeof(T)} syscall written and change to RX");
                return func;
            }
        }

        private static IntPtr GetOsVersionAndReturnSyscall(SysCalls syscallType)
        {
            var ptr = Internals.VirtualAlloc(IntPtr.Zero, (IntPtr)SYSCALL_DEFAULT.Length, Internals.AllocationType.Commit, Internals.PAGE_READWRITE);
            if (ptr == IntPtr.Zero)
            {
                throw new Exception($"VirtualAlloc failed and returned null pointer - error code {Internals.GetLastError()}");
            }

            Marshal.Copy(SYSCALL_DEFAULT, 0, ptr, SYSCALL_DEFAULT.Length);

            var osVersionInfo = new Internals.OSVersionInfoExW { dwOSVersionInfoSize = Marshal.SizeOf(typeof(Internals.OSVersionInfoExW)) };
            Internals.RtlGetVersion(ref osVersionInfo);
            byte syscallByte;

            if (osVersionInfo.dwPlatformId != Internals.VER_PLATFORM_WIN32_NT)
            {
                throw new NotSupportedException(
                    $"Unsupported Platform ID: {osVersionInfo.dwPlatformId}, get your friendly neighbourhood developer to update the syscalls in core.");
            }

            switch (osVersionInfo.dwBuildNumber)
            {
                case (int)WindowsVersions.Windows10_21H22:
                    syscallByte = syscallType switch
                    {
                        SysCalls.NtOpenProcess =>
                            039,
                        SysCalls.NtCreateThreadEx =>
                            198,
                        SysCalls.NtWriteVirtualMemory =>
                            059,
                        SysCalls.ZwAllocateVirtualMemory =>
                            025,
                        SysCalls.NtCreateSection =>
                            075,
                        SysCalls.ZwMapViewOfSection =>
                            041,
                        SysCalls.NtCreateProcess =>
                            189,
                        SysCalls.ZwProtectVirtualMemory =>
                            081,
                        _ => throw new ArgumentException("Unknown Syscall type: " + syscallType)
                    };
                    break;
                case (int)WindowsVersions.Windows10_22H2:
                    syscallByte = syscallType switch
                    {
                        SysCalls.NtOpenProcess =>
                            039,
                        SysCalls.NtCreateThreadEx =>
                            194,
                        SysCalls.NtWriteVirtualMemory =>
                            059,
                        SysCalls.ZwAllocateVirtualMemory =>
                            025,
                        SysCalls.NtCreateSection =>
                            075,
                        SysCalls.ZwMapViewOfSection =>
                            041,
                        SysCalls.NtCreateProcess =>
                            186,
                        SysCalls.ZwProtectVirtualMemory =>
                            081,
                        _ => throw new ArgumentException("Unknown Syscall type: " + syscallType)
                    };
                    break;
                case (int)WindowsVersions.Windows10_20H2 or
                    (int)WindowsVersions.Windows10_2004 or
                    (int)WindowsVersions.Windows10_21H1 or
                    (int)WindowsVersions.Windows10_21H2:
                    syscallByte = syscallType switch
                    {
                        SysCalls.NtOpenProcess =>
                            039,
                        SysCalls.NtCreateThreadEx =>
                            194,
                        SysCalls.NtWriteVirtualMemory =>
                            059,
                        SysCalls.ZwAllocateVirtualMemory =>
                            025,
                        SysCalls.NtCreateSection =>
                            075,
                        SysCalls.ZwMapViewOfSection =>
                            041,
                        SysCalls.NtCreateProcess =>
                            186,
                        SysCalls.ZwProtectVirtualMemory =>
                            081,
                        _ => throw new ArgumentException("Unknown Syscall type: " + syscallType)
                    };
                    break;
                case (int)WindowsVersions.Windows10_1903 or (int)WindowsVersions.Windows10_1909:
                    syscallByte = syscallType switch
                    {
                        SysCalls.NtOpenProcess =>
                            039,
                        SysCalls.NtCreateThreadEx =>
                            190,
                        SysCalls.NtWriteVirtualMemory =>
                            059,
                        SysCalls.ZwAllocateVirtualMemory =>
                            025,
                        SysCalls.NtCreateSection =>
                            075,
                        SysCalls.ZwMapViewOfSection =>
                            041,
                        SysCalls.NtCreateProcess =>
                            182,
                        SysCalls.ZwProtectVirtualMemory =>
                            081,
                        _ => throw new ArgumentException("Unknown Syscall type: " + syscallType)
                    };
                    break;
                case (int)WindowsVersions.Windows10_1803:
                    syscallByte = syscallType switch
                    {
                        SysCalls.NtOpenProcess =>
                            039,
                        SysCalls.NtCreateThreadEx =>
                            188,
                        SysCalls.NtWriteVirtualMemory =>
                            059,
                        SysCalls.ZwAllocateVirtualMemory =>
                            025,
                        SysCalls.NtCreateSection =>
                            075,
                        SysCalls.ZwMapViewOfSection =>
                            041,
                        SysCalls.NtCreateProcess =>
                            181,
                        SysCalls.ZwProtectVirtualMemory =>
                            081,
                        _ => throw new ArgumentException("Unknown Syscall type: " + syscallType)
                    };
                    break;
                case (int)WindowsVersions.Windows10_1809:
                    syscallByte = syscallType switch
                    {
                        SysCalls.NtOpenProcess =>
                            039,
                        SysCalls.NtCreateThreadEx =>
                            189,
                        SysCalls.NtWriteVirtualMemory =>
                            059,
                        SysCalls.ZwAllocateVirtualMemory =>
                            025,
                        SysCalls.NtCreateSection =>
                            075,
                        SysCalls.ZwMapViewOfSection =>
                            041,
                        SysCalls.NtCreateProcess =>
                            181,
                        SysCalls.ZwProtectVirtualMemory =>
                            081,
                        _ => throw new ArgumentException("Unknown Syscall type: " + syscallType)
                    };
                    break;
                case (int)WindowsVersions.Windows7_SP1:
                    syscallByte = syscallType switch
                    {
                        SysCalls.NtOpenProcess =>
                            039,
                        SysCalls.NtCreateThreadEx =>
                            189,
                        SysCalls.NtWriteVirtualMemory =>
                            059,
                        SysCalls.ZwAllocateVirtualMemory =>
                            025,
                        SysCalls.NtCreateSection =>
                            075,
                        SysCalls.ZwMapViewOfSection =>
                            041,
                        SysCalls.NtCreateProcess =>
                            181,
                        SysCalls.ZwProtectVirtualMemory =>
                            081,
                        _ => throw new ArgumentException("Unknown Syscall type: " + syscallType)
                    };
                    break;
                case (int)WindowsVersions.Server2016:
                    syscallByte = syscallType switch
                    {
                        SysCalls.NtOpenProcess =>
                            039,
                        SysCalls.NtCreateThreadEx =>
                            183,
                        SysCalls.NtWriteVirtualMemory =>
                            059,
                        SysCalls.ZwAllocateVirtualMemory =>
                            025,
                        SysCalls.NtCreateSection =>
                            075,
                        SysCalls.ZwMapViewOfSection =>
                            041,
                        SysCalls.NtCreateProcess =>
                            181,
                        SysCalls.ZwProtectVirtualMemory =>
                            081,
                        _ => throw new ArgumentException("Unknown Syscall type: " + syscallType)
                    };
                    break;
                case (int)WindowsVersions.Server2012_R2:
                {
                    syscallByte = syscallType switch
                    {
                        SysCalls.NtOpenProcess =>
                            038,
                        SysCalls.NtCreateThreadEx =>
                            177,
                        SysCalls.NtWriteVirtualMemory =>
                            058,
                        SysCalls.ZwAllocateVirtualMemory =>
                            024,
                        SysCalls.NtCreateSection =>
                            074,
                        SysCalls.ZwMapViewOfSection =>
                            040,
                        SysCalls.NtCreateProcess =>
                            171,
                        SysCalls.ZwProtectVirtualMemory =>
                            080,
                        _ => throw new ArgumentException("Unknown Syscall type: " + syscallType)
                    };
                    break;
                }
                default:
                    throw new NotSupportedException(
                        $"Windows Build Number Not Supported: {osVersionInfo.dwBuildNumber}, get your friendly neighbourhood developer to update the syscalls in core.");
            }

            unsafe
            {
                var syscall = (byte*)ptr;
                syscall[4] = syscallByte;
                for (byte i = 0; i <= SYSCALL_DEFAULT.Length; i++)
                {
                    syscall[i]--;
                }

                return ptr;
            }
        }
    }
}