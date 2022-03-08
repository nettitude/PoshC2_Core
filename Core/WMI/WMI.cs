using System;
using System.Management;
using System.Text;

namespace Core.WMI
{
    internal static class WMI
    {
        internal static void WMIKillProcess(string machineName, int processId)
        {
            try
            {
                var connectoptions = new ConnectionOptions();
                var query = new SelectQuery($"select * from Win32_process where ProcessId = '{processId}'");
                ManagementScope scope = new ManagementScope($@"\\{machineName}\root\cimv2");

                using (var searcher = new ManagementObjectSearcher(scope, query))
                {
                    foreach (ManagementObject process in searcher.Get())
                    {
                        process.InvokeMethod("Terminate", null);
                    }
                }

                Console.WriteLine("[+] Process terminated");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot run WMI: {e.Message}");
            }
        }

        internal static void WMITaskList(string machineName, string processName = "", string user = "", string pass = "", string domain = "")
        {
            var output = new StringBuilder();
            try
            {
                var opt = new ConnectionOptions();
                if (!string.IsNullOrEmpty(processName))
                {
                    output.Append($"\n[+] Running WMI process list against: {machineName} for process {processName} \n");
                }
                else
                {
                    output.Append($"\n[+] Running WMI process list all against: {machineName} \n");
                }
                if (!string.IsNullOrEmpty(user) && !string.IsNullOrEmpty(pass) && !string.IsNullOrEmpty(domain))
                {
                    output.Append($"\n[+] Will run with the provided credentials for the account {domain}\\{user} \n");
                    string authority = $"ntlmdomain:{domain.ToUpper()}";
                    opt.Authority = authority;
                    opt.Username = user;
                    opt.Password = pass;
                    opt.Impersonation = ImpersonationLevel.Impersonate;
                    opt.Authentication = AuthenticationLevel.Default;
                    opt.Timeout = TimeSpan.FromSeconds(30);
                }
                               
                var path = $@"\\{machineName}\root\cimv2";
                var scope = new ManagementScope(path, opt);
                scope.Connect();
                var query = new ObjectQuery(string.Format("Select * From Win32_Process"));
               
                if (!string.IsNullOrEmpty(processName))
                {
                    query = new ObjectQuery($"Select * From Win32_Process Where Name = '{processName}'");
                }

                var searcher = new ManagementObjectSearcher(scope, query);
                var processList = searcher.Get();
                foreach (var managementBaseObject in processList)
                {
                    var obj = (ManagementObject) managementBaseObject;
                    var argList = new[] {"", ""};
                    var returnVal = Convert.ToInt32(obj.InvokeMethod("GetOwner", argList));
                    if (returnVal == 0)
                    {
                        var userName = $"{argList[1]}\\{argList[0]}";
                        output.Append($"[>] {obj["Name"]} ({obj["ProcessId"]}) running under {userName} on {machineName}\n");
                    }
                }
            }
            catch (Exception e)
            {
                output.Append($"[-] Cannot run WMI: {e.Message}");
            }

            Console.WriteLine(output.ToString());
        }
    }
}
