using System;
using System.Diagnostics;
using Core.WindowsInternals;

namespace Core.PowerStatusTracker
{
    public static class LockChecker
    {
        public enum LockStatus
        {
            SESSION_LOCK,
            SESSION_NOT_LOCK,
            SESSION_LOCK_UAC
        }

        public static LockStatus GetLockStatus()
        {
            try
            {
                Internals.GetWindowThreadProcessId(Internals.GetForegroundWindow(), out var pid);
                if (0 < pid)
                {
                    if ((bool)Process.GetProcessById((int)pid)?.ProcessName?.ToLower()?.StartsWith("lockapp"))
                        return LockStatus.SESSION_LOCK;
                }
                else if (IntPtr.Zero == Internals.OpenInputDesktop(0, false, 0))
                {
                    if (10 > Environment.OSVersion.Version.Major)
                        return LockStatus.SESSION_LOCK;
                    return LockStatus.SESSION_LOCK_UAC;
                }
            }
            catch
            {
                /*swallow it*/
            }

            return LockStatus.SESSION_NOT_LOCK;
        }
    }
}