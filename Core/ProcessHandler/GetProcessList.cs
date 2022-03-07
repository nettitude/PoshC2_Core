using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Principal;
using System.Diagnostics;
using System.Collections.Generic;
using Core.WindowsInternals;

namespace Core.ProcessHandler
{
    internal static class ProcHandler
    {
        // https://www.pinvoke.net/default.aspx/kernel32.createtoolhelp32snapshot
        internal static string GetProcesses()
        {
            var handleToSnapshot = IntPtr.Zero;
            var pids = new StringBuilder();
            try
            {
                var procEntry = new Internals.ProcessEntry32 {dwSize = (uint) Marshal.SizeOf(typeof(Internals.ProcessEntry32))};
                handleToSnapshot = Internals.CreateToolhelp32Snapshot((uint) Internals.SnapshotFlags.Process, 0);

                pids.Append("PID".PadRight(10) + "USER".PadRight(15) + "ARCH".PadRight(10) + "PPID".PadRight(10) + "NAME" + "\n");
                pids.Append("===".PadRight(10) + "====".PadRight(15) + "====".PadRight(10) + "====".PadRight(10) + "====" + "\n");
                for (Internals.Process32First(handleToSnapshot, ref procEntry); Internals.Process32Next(handleToSnapshot, ref procEntry);)
                {
                    var arch = "";
                    var proc = Process.GetProcessById((int) procEntry.th32ProcessID);
                    var is32Os = Is32BitArch();
                    if (is32Os == false)
                    {
                        try
                        {
                            Internals.IsWow64Process(proc.Handle, out var is64Bit);
                            arch = is64Bit ? "x86" : "x64";
                        }
                        catch
                        {
                        }
                    }
                    else
                    {
                        arch = "x86";
                    }

                    pids.Append(procEntry.th32ProcessID.ToString().PadRight(10));
                    pids.Append(GetProcessUser(proc).PadRight(15));
                    pids.Append(arch.PadRight(10));
                    pids.Append(procEntry.th32ParentProcessID.ToString().PadRight(10));
                    pids.Append(procEntry.szExeFile);
                    pids.Append("\n");
                }
            }
            catch
            {
            }
            finally
            {
                Internals.CloseHandle(handleToSnapshot);
            }

            return pids.ToString();
        }

        private static bool Is32BitArch()
        {
            var v = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITEW6432");

            return IntPtr.Size == 4 && v == null;
        }

        // Get username from process
        // https://stackoverflow.com/questions/777548/how-do-i-determine-the-owner-of-a-process-in-c

        private static string GetProcessUser(Process process)
        {
            var processHandle = IntPtr.Zero;
            try
            {
                Internals.OpenProcessToken(process.Handle, 8, out processHandle);
                var wi = new WindowsIdentity(processHandle);
                var user = wi.Name;
                return user.Contains(@"\") ? user.Substring(user.IndexOf(@"\", StringComparison.Ordinal) + 1) : user;
            }
            catch
            {
                return "";
            }
            finally
            {
                if (processHandle != IntPtr.Zero)
                {
                    Internals.CloseHandle(processHandle);
                }
            }
        }

        internal static void DLLSearcher(List<string> checks)
        {
            var results = new List<string>();
            var localAll = Process.GetProcesses();
            foreach (var proc in localAll)
            {
                try
                {
                    foreach (var module in proc.Modules)
                    {
                        var moduleName = module.ToString().Replace("System.Diagnostics.ProcessModule (", "").Replace(")", "").ToLower();
                        if (checks.Contains(moduleName))
                        {
                            results.Add(string.Format(moduleName));
                        }
                    }
                }
                catch (Exception)
                {
                }

                if (results.Count > 0)
                {
                    Console.WriteLine("\nProcess Name: {0} & PID:{1}", proc.ProcessName, proc.Id);
                    foreach (var r in results)
                    {
                        Console.WriteLine("Found: {0}", r);
                    }

                    results.Clear();
                }
            }
        }
    }
}