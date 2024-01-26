using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Core.WindowsInternals;

namespace Core.PowerStatusTracker
{
    public class PwrNotifier
    {
        public string taskid;
        public bool pwrstatusEnabled = false;

        public void CallNotify(string msg)
        {
            try
            {
                if (!pwrstatusEnabled)
                {
                    Application.ExitThread();
                    Application.Exit();
                }
                else
                {
                    Core.sendData(taskid, Encoding.ASCII.GetBytes(msg));
                }
            }
            catch (NullReferenceException e)
            {
                Core.sendData(taskid, Encoding.ASCII.GetBytes($"Error PwrStatus {e.Message}"));
            }
            //REMOVE THIS BEFORE RELEASE
            //System.IO.File.WriteAllText(@"C:\temp\pwrstatus.txt", msg);
        }

    }

    public class PowerStatusTrackerForm : Form
    {
        [STAThread]
        public static void CreatePwrFrmAsync(PwrNotifier pwr)
        {
            PowerStatusTrackerForm powerForm;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    var ls = LockChecker.GetLockStatus();
                    if (ls != LockChecker.LockStatus.SESSION_NOT_LOCK)
                        pwr?.CallNotify($"WM_WTSSESSION_CHANGE:{Enum.GetName(typeof(LockChecker.LockStatus), ls)}");
                    powerForm = new PowerStatusTrackerForm { PwrNotify = pwr };
                    Application.Run(powerForm);
                }
                catch
                {
                }
            });
        }

        protected override void SetVisibleCore(bool value)
        {
            base.SetVisibleCore(false);
        }

        private PwrNotifier PwrNotify { get; set; }
        private const int NOTIFY_FOR_THIS_SESSION = 0;
        const int WM_QUERYENDSESSION = 0x11;
        const int WM_ENDSESSION = 0x16;
        const int WM_WTSSESSION_CHANGE = 0x2b1;
        const int WM_POWERBROADCAST = 0x0218;
        const int PBT_POWERSETTINGCHANGE = 0x8013;
        const int PBT_APMBATTERYLOW = 0x09;
        const int PBT_APMPOWERSTATUSCHANGE = 0xA;
        const int PBT_APMQUERYSUSPEND = 0x0;
        const int PBT_APMRESUMESUSPEND = 0x07;
        const int PBT_APMSUSPEND = 0x4;
        const uint ENDSESSION_CLOSEAPP = 0x00000001;
        const uint ENDSESSION_CRITICAL = 0x40000000;
        const uint ENDSESSION_LOGOFF = 0x80000000;
        private const int DEVICE_NOTIFY_WINDOW_HANDLE = 0x00000000;
        static Guid GUID_MONITOR_POWER_ON = Guid.Parse("02731015-4510-4526-99e6-e5a17ebd1aea");
        static Guid GUID_BATTERY_PERCENTAGE_REMAINING = Guid.Parse("a7ad8041-b45a-4cae-87a3-eecbb468a9e1");
        static Guid GUID_ACDC_POWER_SOURCE = Guid.Parse("5d3e9a59-e9D5-4b00-a6bd-ff34ff516548");
        IntPtr _hmonitor;
        IContainer components = null;

        protected override CreateParams CreateParams
        {
            get
            {
                var cp = base.CreateParams;
                cp.ExStyle |= 0x80;
                return cp;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct POWERBROADCAST_SETTING
        {
            public Guid PowerSetting;
            public int DataLength;
            public byte Data;
        }

        public PowerStatusTrackerForm()
        {
            InitializeComponent();
            ShowInTaskbar = false;
            WindowState = FormWindowState.Minimized;

            if (!Internals.WTSRegisterSessionNotification(Handle, NOTIFY_FOR_THIS_SESSION))
                Marshal.ThrowExceptionForHR(Marshal.GetLastWin32Error());

            _hmonitor = Internals.RegisterPowerSettingNotification(Handle, ref GUID_MONITOR_POWER_ON, DEVICE_NOTIFY_WINDOW_HANDLE);
            if (IntPtr.Zero == _hmonitor)
                Marshal.ThrowExceptionForHR(Marshal.GetLastWin32Error());
        }

        private enum SessionStatus
        {
            WTS_CONSOLE_CONNECT = 0x1,
            WTS_CONSOLE_DISCONNECT = 0x2,
            WTS_REMOTE_CONNECT = 0x3,
            WTS_REMOTE_DISCONNECT = 0x4,
            WTS_SESSION_LOGON = 0x5,
            WTS_SESSION_LOGOFF = 0x6,
            WTS_SESSION_LOCK = 0x7,
            WTS_SESSION_UNLOCK = 0x8,
            WTS_SESSION_REMOTE_CONTROL = 0x9
        }

        private void InitializeComponent()
        {
            ShowInTaskbar = false;
            SuspendLayout();
            AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new System.Drawing.Size(0, 0);
            FormBorderStyle = FormBorderStyle.None;
            Name = "";
            Text = "";
            WindowState = FormWindowState.Minimized;
            ResumeLayout(false);
        }

        private static string GetPowerStatus()
        {
            Internals.GetSystemPowerStatus(out var lpPower);
            var powerStatus = new StringBuilder();
            bool charging = false, onAc = false;
            if (lpPower.ACLineStatus == 0x0)
            {
                powerStatus.AppendLine("GUID_ACDC_POWER_SOURCE:Unplugged");
                var t = TimeSpan.FromSeconds(lpPower.BatteryLifeTime);
                powerStatus.AppendLine(string.Format("DISCHARGE: {0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms", t.Hours, t.Minutes, t.Seconds, t.Milliseconds));
            }
            else if (onAc = lpPower.ACLineStatus == 1)
                powerStatus.AppendLine("GUID_ACDC_POWER_SOURCE:Plugged");
            else
                powerStatus.AppendLine("GUID_ACDC_POWER_SOURCE:Unknown");


            if (lpPower.BatteryFlag > 0)
            {
                var batteryFlag = "";
                if ((lpPower.BatteryFlag & 1) == 1)
                    batteryFlag += "HIGH";
                else if ((lpPower.BatteryFlag & 2) == 2)
                    batteryFlag += "LOW";
                else if ((lpPower.BatteryFlag & 4) == 4)
                    batteryFlag = "CRITICAL";
                else if ((lpPower.BatteryFlag & 8) == 8)
                    charging = true;
                else if ((lpPower.BatteryFlag & 128) == 128)
                    batteryFlag = "NONE";
                else if ((lpPower.BatteryFlag & 0xFF) == 0xFF)
                    batteryFlag = "UNKNOWN";

                if (!string.IsNullOrEmpty(batteryFlag))
                    powerStatus.AppendLine($"BATTERY:{batteryFlag}");
            }

            if (charging)
                powerStatus.AppendLine("CHRG:CHARGING");
            else if (!onAc)
                powerStatus.AppendLine("CHRG:DISCHARGING");

            powerStatus.AppendLine(lpPower.BatteryLifePercent == 0xFF ? "PERCENT:UNKNOWN" : $"PERCENT:{lpPower.BatteryLifePercent}");
            return powerStatus.ToString().Trim();
        }

        private static void TranslateEndSession(uint param, ref string message)
        {
            switch (param)
            {
                case 0:
                    message += "ENDSESSION_SHUTDOWN";
                    break;
                case ENDSESSION_CLOSEAPP:
                    message += "ENDSESSION_CLOSEAPP";
                    break;
                case ENDSESSION_CRITICAL:
                    message += "ENDSESSION_CRITICAL";
                    break;
                case ENDSESSION_LOGOFF:
                    message += "ENDSESSION_LOGOFF";
                    break;
            }
        }

        protected override void WndProc(ref Message m)
        {
            try
            {
                var message = "";
                switch (m.Msg)
                {
                    case WM_QUERYENDSESSION:
                        message = "WM_QUERYENDSESSION:";
                        TranslateEndSession((uint)m.LParam.ToInt32(), ref message);
                        break;
                    case WM_ENDSESSION:
                        message = "WM_ENDSESSION:";
                        TranslateEndSession((uint)m.LParam.ToInt32(), ref message);
                        break;
                    case WM_WTSSESSION_CHANGE:
                        message = $"WM_WTSSESSION_CHANGE:{Enum.GetName(typeof(SessionStatus), m.WParam.ToInt32())?.Substring(4)}";
                        break;
                    case WM_POWERBROADCAST:
                        message = "WM_POWERBROADCAST:";
                        switch (m.WParam.ToInt32())
                        {
                            case PBT_POWERSETTINGCHANGE:
                                var s = (POWERBROADCAST_SETTING)Marshal.PtrToStructure(m.LParam, typeof(POWERBROADCAST_SETTING));
                                if (s.PowerSetting == GUID_MONITOR_POWER_ON)
                                    if (0x00 == s.Data)
                                        message += "GUID_MONITOR_POWER_ON:OFF";
                                    else
                                        message += "GUID_MONITOR_POWER_ON:On";
                                else if (s.PowerSetting == GUID_BATTERY_PERCENTAGE_REMAINING)
                                {
                                    if (s.Data % 10 == 0 || s.Data < 10)
                                        message += $"GUID_BATTERY_PERCENTAGE_REMAINING:{s.Data}";
                                }
                                else if (s.PowerSetting == GUID_ACDC_POWER_SOURCE)
                                {
                                    switch (s.Data)
                                    {
                                        case 0x0:
                                            message += "GUID_ACDC_POWER_SOURCE:Plugged";
                                            break;
                                        case 0x1:
                                            message += "GUID_ACDC_POWER_SOURCE:Unplugged";
                                            break;
                                        case 0x2:
                                            message += "GUID_ACDC_POWER_SOURCE:UPS";
                                            break;
                                    }
                                }

                                break;
                            case PBT_APMBATTERYLOW:
                                message += "PBT_APMBATTERYLOW";
                                break;
                            case PBT_APMQUERYSUSPEND:
                                message += "PBT_APMQUERYSUSPEND";
                                break;
                            case PBT_APMSUSPEND:
                                message += "PBT_APMSUSPEND";
                                break;
                            case PBT_APMRESUMESUSPEND:
                                message += "PBT_APMRESUMESUSPEND";
                                break;
                            case PBT_APMPOWERSTATUSCHANGE:
                                message += $"PBT_APMPOWERSTATUSCHANGE:\r\n{GetPowerStatus()}";
                                break;
                        }

                        break;
                }

                if (!string.IsNullOrEmpty(message))
                    PwrNotify?.CallNotify(message);
                base.WndProc(ref m);
            }
            catch (Exception)
            {
                Console.WriteLine();
            }
        }

        protected override void OnHandleDestroyed(EventArgs e)
        {
            Internals.WTSUnRegisterSessionNotification(Handle);
            Internals.UnregisterPowerSettingNotification(_hmonitor);
            base.OnHandleDestroyed(e);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && components != null)
                components.Dispose();
            base.Dispose(disposing);
        }
    }
}