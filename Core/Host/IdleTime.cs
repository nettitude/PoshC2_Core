using System;
using System.Runtime.InteropServices;

namespace Core.Host
{
    public static class UserInput
    {
        private struct LastInputInfo
        {
            internal uint size;
            internal int time;
        }

        public static DateTime LastInput => DateTime.UtcNow.AddMilliseconds(-Environment.TickCount).AddMilliseconds(LastInputTicks);

        public static TimeSpan IdleTime => DateTime.UtcNow.Subtract(LastInput);

        private static int LastInputTicks
        {
            get
            {
                var lastInputInfo = default(LastInputInfo);
                lastInputInfo.size = (uint) Marshal.SizeOf(typeof(LastInputInfo));
                GetLastInputInfo(ref lastInputInfo);
                return lastInputInfo.time;
            }
        }

        [DllImport("user32.dll")]
        private static extern bool GetLastInputInfo(ref LastInputInfo plii);
    }
}