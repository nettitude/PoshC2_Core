using System;
using System.Runtime.InteropServices;

namespace Core.WindowsInternals
{
    internal static class SysCall
    {
        private enum WindowsVersions
        {
            _7601 = 7601,
            _9600 = 9600,
            _14393 = 14393,
            _22000 = 22000,
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
                    $"Unsupported Platform ID: {osVersionInfo.dwPlatformId}, run syscallsextractor and get your friendly neighbourhood developer to update the syscalls in core.");
            }

            // These syscall numbers are the number "+1" to help avoid static detections, so when adding/updating numbers you need to add one to the real number
            return (byte)(osVersionInfo.dwBuildNumber switch
            {
                (int)WindowsVersions._22000 => syscallType switch
                {
                    SysCalls.NtOpenProcess => 0x27,
                    SysCalls.NtCreateThreadEx => 0xc6,
                    SysCalls.NtWriteVirtualMemory => 0x3b,
                    SysCalls.ZwAllocateVirtualMemory => 0x19,
                    SysCalls.NtCreateSection => 0x4b,
                    SysCalls.ZwMapViewOfSection => 0x29,
                    SysCalls.NtCreateProcess => 0xbd,
                    SysCalls.ZwProtectVirtualMemory => 0x51,
                    SysCalls.ZwReadVirtualMemory => 0x40,
                    SysCalls.NtCreateThread => 0x4f,
                    SysCalls.NtUnmapViewOfSection => 0x2b,
                    SysCalls.NtCreateUserProcess => 0xce,
                    SysCalls.ZwFreeVirtualMemory => 0x1f,
                    SysCalls.NtQueueApcThread => 0x46,
                    _ => throw new ArgumentException($"Unknown Syscall type: {syscallType}")
                },
                (int)WindowsVersions._14393 => syscallType switch
                {
                    SysCalls.NtOpenProcess => 0x27,
                    SysCalls.NtCreateThreadEx => 0xb7,
                    SysCalls.NtWriteVirtualMemory => 0x3b,
                    SysCalls.ZwAllocateVirtualMemory => 0x19,
                    SysCalls.NtCreateSection => 0x4b,
                    SysCalls.ZwMapViewOfSection => 0x29,
                    SysCalls.NtCreateProcess => 0xb5,
                    SysCalls.ZwProtectVirtualMemory => 0x51,
                    SysCalls.ZwReadVirtualMemory => 0x40,
                    SysCalls.NtCreateThread => 0x4f,
                    SysCalls.NtUnmapViewOfSection => 0x2b,
                    SysCalls.NtCreateUserProcess => 0xc4,
                    SysCalls.ZwFreeVirtualMemory => 0x1f,
                    SysCalls.NtQueueApcThread => 0x46,
                    _ => throw new ArgumentException($"Unknown Syscall type: {syscallType}")
                },
                (int)WindowsVersions._9600 => syscallType switch
                {
                    SysCalls.NtOpenProcess => 0x26,
                    SysCalls.NtCreateThreadEx => 0xb1,
                    SysCalls.NtWriteVirtualMemory => 0x3a,
                    SysCalls.ZwAllocateVirtualMemory => 0x18,
                    SysCalls.NtCreateSection => 0x4a,
                    SysCalls.ZwMapViewOfSection => 0x28,
                    SysCalls.NtCreateProcess => 0xab,
                    SysCalls.ZwProtectVirtualMemory => 0x50,
                    SysCalls.ZwReadVirtualMemory => 0x3d,
                    SysCalls.NtCreateThread => 0x4f,
                    SysCalls.NtUnmapViewOfSection => 0x2b,
                    SysCalls.NtCreateUserProcess => 0xab,
                    SysCalls.ZwFreeVirtualMemory => 0x1c,
                    SysCalls.NtQueueApcThread => 0x43,
                    _ => throw new ArgumentException($"Unknown Syscall type: {syscallType}")
                },
                (int)WindowsVersions._7601 => syscallType switch
                {
                    SysCalls.NtOpenProcess => 0x24,
                    SysCalls.NtCreateThreadEx => 0xa6,
                    SysCalls.NtWriteVirtualMemory => 0x38,
                    SysCalls.ZwAllocateVirtualMemory => 0x16,
                    SysCalls.NtCreateSection => 0x48,
                    SysCalls.ZwMapViewOfSection => 0x26,
                    SysCalls.NtCreateProcess => 0xa0,
                    SysCalls.ZwProtectVirtualMemory => 0x4e,
                    SysCalls.ZwReadVirtualMemory => 0x3d,
                    SysCalls.NtCreateThread => 0x4c,
                    SysCalls.NtUnmapViewOfSection => 0x28,
                    SysCalls.NtCreateUserProcess => 0xab,
                    SysCalls.ZwFreeVirtualMemory => 0x1c,
                    SysCalls.NtQueueApcThread => 0x43,
                    _ => throw new ArgumentException($"Unknown Syscall type: {syscallType}")
                },
                _ => throw new NotSupportedException(
                    $"Windows Build Number Not Supported: {osVersionInfo.dwBuildNumber}, run syscallsextractor and get your friendly neighbourhood developer to update the syscalls in core.")
            } - 1);
        }
    }
}