using System;
using System.Runtime.InteropServices;

namespace Core.WindowsInternals
{
    internal static class SysCall
    {
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
            Windows10_21H22 = 22000
        }

        internal enum SysCalls
        {
            NtOpenProcess,
            NtCreateThreadEx,
            NtWriteVirtualMemory,
            ZwAllocateVirtualMemory,
            NtCreateSection,
            ZwMapViewOfSection,
            NtCreateProcess,
            ZwProtectVirtualMemory,
            ZwReadVirtualMemory,
            NtCreateThread,
            NtUnmapViewOfSection,
            NtCreateUserProcess,
            ZwFreeVirtualMemory,
            NtQueueApcThread
        }

        internal static byte GetOsVersionAndReturnSyscall(SysCalls syscallType)
        {
            var osVersionInfo = new Internals.OSVersionInfoExW { dwOSVersionInfoSize = Marshal.SizeOf(typeof(Internals.OSVersionInfoExW)) };
            Internals.RtlGetVersion(ref osVersionInfo);

            if (osVersionInfo.dwPlatformId != Internals.VER_PLATFORM_WIN32_NT)
            {
                throw new NotSupportedException(
                    $"Unsupported Platform ID: {osVersionInfo.dwPlatformId}, get your friendly neighbourhood developer to update the syscalls in core.");
            }

            return (byte)(osVersionInfo.dwBuildNumber switch
            {
                (int)WindowsVersions.Windows10_21H22 => syscallType switch
                {
                    SysCalls.NtOpenProcess => 039,
                    SysCalls.NtCreateThreadEx => 198,
                    SysCalls.NtWriteVirtualMemory => 059,
                    SysCalls.ZwAllocateVirtualMemory => 025,
                    SysCalls.NtCreateSection => 075,
                    SysCalls.ZwMapViewOfSection => 041,
                    SysCalls.NtCreateProcess => 189,
                    SysCalls.ZwProtectVirtualMemory => 081,
                    SysCalls.ZwReadVirtualMemory => 0x40,
                    SysCalls.NtCreateThread => 0x4f,
                    SysCalls.NtUnmapViewOfSection => 0x2b,
                    SysCalls.NtCreateUserProcess => 0xce,
                    SysCalls.ZwFreeVirtualMemory => 0x1f,
                    SysCalls.NtQueueApcThread => 0x46,
                    _ => throw new ArgumentException($"Unknown Syscall type: {syscallType}")
                },
                (int)WindowsVersions.Windows10_20H2 or
                    (int)WindowsVersions.Windows10_2004 or
                    (int)WindowsVersions.Windows10_21H1 or
                    (int)WindowsVersions.Windows10_21H2 => syscallType switch
                    {
                        SysCalls.NtOpenProcess => 039,
                        SysCalls.NtCreateThreadEx => 194,
                        SysCalls.NtWriteVirtualMemory => 059,
                        SysCalls.ZwAllocateVirtualMemory => 025,
                        SysCalls.NtCreateSection => 075,
                        SysCalls.ZwMapViewOfSection => 041,
                        SysCalls.NtCreateProcess => 186,
                        SysCalls.ZwProtectVirtualMemory => 081,
                        SysCalls.ZwReadVirtualMemory => 0x40,
                        SysCalls.NtCreateThread => 0x4f,
                        SysCalls.NtUnmapViewOfSection => 0x2b,
                        SysCalls.NtCreateUserProcess => 0xc9,
                        SysCalls.ZwFreeVirtualMemory => 0x1f,
                        SysCalls.NtQueueApcThread => 0x46,
                        _ => throw new ArgumentException($"Unknown Syscall type: {syscallType}")
                    },
                (int)WindowsVersions.Windows10_1903 or
                    (int)WindowsVersions.Windows10_1909 => syscallType switch
                    {
                        SysCalls.NtOpenProcess => 039,
                        SysCalls.NtCreateThreadEx => 190,
                        SysCalls.NtWriteVirtualMemory => 059,
                        SysCalls.ZwAllocateVirtualMemory => 025,
                        SysCalls.NtCreateSection => 075,
                        SysCalls.ZwMapViewOfSection => 041,
                        SysCalls.NtCreateProcess => 182,
                        SysCalls.ZwProtectVirtualMemory => 081,
                        SysCalls.ZwReadVirtualMemory => 0x40,
                        SysCalls.NtCreateThread => 0x4f,
                        SysCalls.NtUnmapViewOfSection => 0x2b,
                        SysCalls.NtCreateUserProcess => 0xc5,
                        SysCalls.ZwFreeVirtualMemory => 0x1f,
                        SysCalls.NtQueueApcThread => 0x46,
                        _ => throw new ArgumentException($"Unknown Syscall type: {syscallType}")
                    },
                (int)WindowsVersions.Windows10_1809 => syscallType switch
                {
                    SysCalls.NtOpenProcess => 039,
                    SysCalls.NtCreateThreadEx => 189,
                    SysCalls.NtWriteVirtualMemory => 059,
                    SysCalls.ZwAllocateVirtualMemory => 025,
                    SysCalls.NtCreateSection => 075,
                    SysCalls.ZwMapViewOfSection => 041,
                    SysCalls.NtCreateProcess => 181,
                    SysCalls.ZwProtectVirtualMemory => 081,
                    SysCalls.ZwReadVirtualMemory => 0x40,
                    SysCalls.NtCreateThread => 0x4f,
                    SysCalls.NtUnmapViewOfSection => 0x2b,
                    SysCalls.NtCreateUserProcess => 0xc4,
                    SysCalls.ZwFreeVirtualMemory => 0x1f,
                    SysCalls.NtQueueApcThread => 0x46,
                    _ => throw new ArgumentException($"Unknown Syscall type: {syscallType}")
                },
                (int)WindowsVersions.Windows10_1803 => syscallType switch
                {
                    SysCalls.NtOpenProcess => 039,
                    SysCalls.NtCreateThreadEx => 188,
                    SysCalls.NtWriteVirtualMemory => 059,
                    SysCalls.ZwAllocateVirtualMemory => 025,
                    SysCalls.NtCreateSection => 075,
                    SysCalls.ZwMapViewOfSection => 041,
                    SysCalls.NtCreateProcess => 181,
                    SysCalls.ZwProtectVirtualMemory => 081,
                    SysCalls.ZwReadVirtualMemory => 0x40,
                    SysCalls.NtCreateThread => 0x4f,
                    SysCalls.NtUnmapViewOfSection => 0x2b,
                    SysCalls.NtCreateUserProcess => 0xc3,
                    SysCalls.ZwFreeVirtualMemory => 0x1f,
                    SysCalls.NtQueueApcThread => 0x46,
                    _ => throw new ArgumentException($"Unknown Syscall type: {syscallType}")
                },
                (int)WindowsVersions.Server2016 => syscallType switch
                {
                    SysCalls.NtOpenProcess => 039,
                    SysCalls.NtCreateThreadEx => 183,
                    SysCalls.NtWriteVirtualMemory => 059,
                    SysCalls.ZwAllocateVirtualMemory => 025,
                    SysCalls.NtCreateSection => 075,
                    SysCalls.ZwMapViewOfSection => 041,
                    SysCalls.NtCreateProcess => 181,
                    SysCalls.ZwProtectVirtualMemory => 081,
                    SysCalls.ZwReadVirtualMemory => 0x40,
                    SysCalls.NtCreateThread => 0x4f,
                    SysCalls.NtUnmapViewOfSection => 0x2b,
                    SysCalls.NtCreateUserProcess => 0xc4,
                    SysCalls.ZwFreeVirtualMemory => 0x1f,
                    SysCalls.NtQueueApcThread => 0x46,
                    _ => throw new ArgumentException($"Unknown Syscall type: {syscallType}")
                },
                (int)WindowsVersions.Windows7_SP1 => syscallType switch
                {
                    SysCalls.NtOpenProcess => 039,
                    SysCalls.NtCreateThreadEx => 189,
                    SysCalls.NtWriteVirtualMemory => 059,
                    SysCalls.ZwAllocateVirtualMemory => 025,
                    SysCalls.NtCreateSection => 075,
                    SysCalls.ZwMapViewOfSection => 041,
                    SysCalls.NtCreateProcess => 181,
                    SysCalls.ZwProtectVirtualMemory => 081,
                    SysCalls.ZwReadVirtualMemory => 0x3d,
                    SysCalls.NtCreateThread => 0x4f,
                    SysCalls.NtUnmapViewOfSection => 0x2b,
                    SysCalls.NtCreateUserProcess => 0xab,
                    SysCalls.ZwFreeVirtualMemory => 0x1c,
                    SysCalls.NtQueueApcThread => 0x43,
                    _ => throw new ArgumentException($"Unknown Syscall type: {syscallType}")
                },
                (int)WindowsVersions.Server2012_R2 => syscallType switch
                {
                    SysCalls.NtOpenProcess => 038,
                    SysCalls.NtCreateThreadEx => 177,
                    SysCalls.NtWriteVirtualMemory => 058,
                    SysCalls.ZwAllocateVirtualMemory => 024,
                    SysCalls.NtCreateSection => 074,
                    SysCalls.ZwMapViewOfSection => 040,
                    SysCalls.NtCreateProcess => 171,
                    SysCalls.ZwProtectVirtualMemory => 080,
                    SysCalls.ZwReadVirtualMemory => 0x3d,
                    SysCalls.NtCreateThread => 0x4f,
                    SysCalls.NtUnmapViewOfSection => 0x2b,
                    SysCalls.NtCreateUserProcess => 0xab,
                    SysCalls.ZwFreeVirtualMemory => 0x1c,
                    SysCalls.NtQueueApcThread => 0x43,
                    _ => throw new ArgumentException($"Unknown Syscall type: {syscallType}")
                },
                _ => throw new NotSupportedException(
                    $"Windows Build Number Not Supported: {osVersionInfo.dwBuildNumber}, get your friendly neighbourhood developer to update the syscalls in core.")
            } - 1);
        }
    }
}