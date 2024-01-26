using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Drawing;
using System.Windows.Forms;
using System.IO;

namespace Core.Host
{
    public class WindowStation
    {
        public delegate bool EnumWindowStationsDelegate(string windowsStation, IntPtr lParam);
        public delegate bool EnumDesktopsDelegate(string desktop, IntPtr lParam);
        public delegate bool EnumDesktopWindowsDelegate(IntPtr hWnd, int lParam);
        public const uint WINSTA_ALL_ACCESS = 0x0000037F;
        const int SRCCOPY = 0x00CC0020;
        const int CAPTUREBLT = 0x40000000;
        const int MAXIMUM_ALLOWED = 0x02000000;

        [DllImport("user32.dll", EntryPoint = "GetSystemMetrics")]
        public static extern int GetSystemMetrics(int abc);

        [DllImport("user32.dll")]
        public static extern bool EnumWindowStations(
            EnumWindowStationsDelegate lpEnumFunc,
            IntPtr lParam
        );

        [DllImport("user32.dll")]
        public static extern bool SetProcessWindowStation(
            IntPtr hDesktop
        );

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr OpenWindowStation(string name, bool fInherit, uint needAccess);

        [DllImport("user32.dll")]
        public static extern bool CloseWindowStation(IntPtr winStation);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool EnumDesktops(
            IntPtr winStation,
            EnumDesktopsDelegate EnumFunc,
            IntPtr lParam
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr OpenDesktop(
            [MarshalAs(UnmanagedType.LPTStr)] string DesktopName,
            uint Flags,
            bool Inherit,
            uint Access
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr OpenInputDesktop(
            uint Flags,
            bool Inherit,
            uint Access
        );

        [DllImport("user32.dll")]
        public static extern bool CloseDesktop(
            IntPtr hDesktop
        );

        [DllImport("user32.dll")]
        public static extern bool EnumDesktopWindows(
            IntPtr hDesktop,
            EnumDesktopWindowsDelegate EnumFunc,
            IntPtr lParam
        );

        [DllImport("user32", SetLastError = true)]
        public static extern IntPtr GetProcessWindowStation();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern int GetWindowText(
            IntPtr hWnd,
            StringBuilder lpWindowText,
            int nMaxCount
        );

        [DllImport("user32.dll")]
        public static extern bool IsWindowVisible(
            IntPtr hwnd
        );

        [DllImport("user32.dll")]
        public static extern IntPtr GetWindowThreadProcessId(
            IntPtr hWnd,
            out IntPtr ProcessId
        );

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr FindWindowEx(IntPtr hwndParent, IntPtr hwndChildAfter, string lpszClass, string lpszWindow);

        [DllImport("user32.dll")]
        public static extern IntPtr GetDC(IntPtr WindowHandle);

        [DllImport("user32.dll")]
        private static extern IntPtr GetWindowRect(IntPtr WindowHandle, ref Rect rect);

        [DllImport("User32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool PrintWindow(IntPtr hwnd, IntPtr hDC, uint nFlags);

        [DllImport("gdi32.dll")]
        public static extern bool BitBlt(IntPtr hdcDest, int nxDest, int nyDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, int dwRop);

        [DllImport("gdi32.dll")]
        public static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int width, int nHeight);

        [DllImport("gdi32.dll")]
        public static extern IntPtr CreateCompatibleDC(IntPtr hdc);

        [DllImport("gdi32.dll")]
        public static extern IntPtr DeleteDC(IntPtr hdc);

        [DllImport("gdi32.dll")]
        public static extern IntPtr DeleteObject(IntPtr hObject);

        [DllImport("user32.dll")]
        public static extern IntPtr GetDesktopWindow();

        [DllImport("user32.dll")]
        public static extern IntPtr GetWindowDC(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern bool ReleaseDC(IntPtr hWnd, IntPtr hDc);

        [DllImport("gdi32.dll")]
        public static extern IntPtr SelectObject(IntPtr hdc, IntPtr hObject);

        [StructLayout(LayoutKind.Sequential)]
        private struct Rect
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        public static Bitmap CaptureRegion(Rectangle region)
        {
            IntPtr desktophWnd;
            IntPtr desktopDc;
            IntPtr memoryDc;
            IntPtr bitmap;
            IntPtr oldBitmap;
            bool success;
            Bitmap result;

            desktophWnd = GetDesktopWindow();
            //desktopDc = GetWindowDC(inputDesktop);
            desktopDc = GetWindowDC(desktophWnd);
            memoryDc = CreateCompatibleDC(desktopDc);
            bitmap = CreateCompatibleBitmap(desktopDc, region.Width, region.Height);
            oldBitmap = SelectObject(memoryDc, bitmap);

            success = BitBlt(memoryDc, 0, 0, region.Width, region.Height, desktopDc, region.Left, region.Top, SRCCOPY | CAPTUREBLT);

            try
            {
                result = Image.FromHbitmap(bitmap);
            }
            finally
            {
                SelectObject(memoryDc, oldBitmap);
                DeleteObject(bitmap);
                DeleteDC(memoryDc);
                ReleaseDC(desktophWnd, desktopDc);
            }

            return result;
        }

        public static Bitmap CaptureDesktop()
        {
            return CaptureDesktop(false);
        }

        public static Bitmap CaptureDesktop(bool workingAreaOnly)
        {
            Rectangle desktop;
            Screen[] screens;

            desktop = Rectangle.Empty;
            screens = Screen.AllScreens;

            for (int i = 0; i < screens.Length; i++)
            {
                Screen screen;

                screen = screens[i];

                desktop = Rectangle.Union(desktop, workingAreaOnly ? screen.WorkingArea : screen.Bounds);
            }

            return CaptureRegion(desktop);
        }

        public static Bitmap Capture(IntPtr handle)
        {
            Rect rect = new Rect();
            GetWindowRect(handle, ref rect);
            Bitmap Bmp = new Bitmap(rect.Right - rect.Left, rect.Bottom - rect.Top);

            Graphics memoryGraphics = Graphics.FromImage(Bmp);
            IntPtr dc = memoryGraphics.GetHdc();
            bool success = PrintWindow(handle, dc, 0);
            memoryGraphics.ReleaseHdc(dc);

            return Bmp;
        }

        public static string CaptureCSSingle(IntPtr handle)
        {
            Rect rect = new Rect();
            GetWindowRect(handle, ref rect);
            Bitmap Bmp = new Bitmap(rect.Right - rect.Left, rect.Bottom - rect.Top);
            Graphics memoryGraphics = Graphics.FromImage(Bmp);
            IntPtr dc = memoryGraphics.GetHdc();
            bool success = PrintWindow(handle, dc, 0);
            memoryGraphics.ReleaseHdc(dc);
            MemoryStream msimage = new MemoryStream();
            Bmp.Save(msimage, System.Drawing.Imaging.ImageFormat.Png);
            return Convert.ToBase64String(msimage.ToArray());
        }

        public static void CaptureCS()
        {
            var processes = System.Diagnostics.Process.GetProcesses();
            foreach (var p in processes)
            {
                try
                {
                    var handle = p.MainWindowHandle;
                    Rect rect = new Rect();
                    GetWindowRect(handle, ref rect);
                    Bitmap Bmp = new Bitmap(rect.Right - rect.Left, rect.Bottom - rect.Top);

                    Graphics memoryGraphics = Graphics.FromImage(Bmp);
                    IntPtr dc = memoryGraphics.GetHdc();
                    bool success = PrintWindow(handle, dc, 0);
                    memoryGraphics.ReleaseHdc(dc);
                    MemoryStream msimage = new MemoryStream();
                    Bmp.Save(msimage, System.Drawing.Imaging.ImageFormat.Png);
                    Console.WriteLine(Convert.ToBase64String(msimage.ToArray()));
                }
                catch
                {

                }
            }
        }
    }
}
