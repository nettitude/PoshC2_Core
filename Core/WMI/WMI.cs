using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
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
                var query = new SelectQuery("select Caption,Status,Name,Handle,ProcessId from Win32_Process where ProcessId = '" + processId + "'");
                var scope = new ManagementScope(@"\\" + machineName + @"\root\cimv2");

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
                    var authority = $"ntlmdomain:{domain.ToUpper()}";
                    opt.Authority = authority;
                    opt.Username = user;
                    opt.Password = pass;
                    opt.Impersonation = ImpersonationLevel.Impersonate;
                    opt.Authentication = AuthenticationLevel.Default;
                    opt.EnablePrivileges = true;
                    opt.Timeout = TimeSpan.FromSeconds(30);
                }
                               
                var path = $@"\\{machineName}\root\cimv2";
                var scope = new ManagementScope(path, opt);
                scope.Connect();
                var query = new ObjectQuery("Select * FROM Win32_Process");
               
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
                        var userName = argList[1] + "\\" + argList[0];
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
        internal static void WMIQuery(string machineName, string wmiNamespace = @"root\cimv2", string userQuery = "", string user = "", string pass = "", string domain = "")
        {
            var output = new StringBuilder();
            try
            {
                var opt = new ConnectionOptions();
                if (string.IsNullOrEmpty(userQuery))
                {
                    output.Append("\n[-] Need to provide a valid WMI query to execute \n");
                }
                else
                {
                    output.Append($"\n[+] Running WMI query \"{userQuery}\" against {machineName} \n");
                    if (!string.IsNullOrEmpty(user) && !string.IsNullOrEmpty(pass) && !string.IsNullOrEmpty(domain))
                    {
                        output.Append($"\n[+] Will run with the provided credentials for the account {domain}\\{user} \n");
                        var authority = $"ntlmdomain:{domain.ToUpper()}";
                        opt.Authority = authority;
                        opt.Username = user;
                        opt.Password = pass;
                        opt.Impersonation = ImpersonationLevel.Impersonate;
                        opt.Authentication = AuthenticationLevel.Default;
                        opt.EnablePrivileges = true;
                        opt.Timeout = TimeSpan.FromSeconds(30);
                    }

                    var path = $@"\\{machineName}\{wmiNamespace}";
                    var scope = new ManagementScope(path, opt);
                    scope.Connect();
                    var query = new ObjectQuery(userQuery);

                    var searcher = new ManagementObjectSearcher(scope, query);
                    var queryResults = searcher.Get();

                    
                    var results = new List<OrderedDictionary>();

                    foreach (var managementBaseObject in queryResults)
                    {
                        var properties = new OrderedDictionary();
                        foreach (var prop in managementBaseObject.Properties)
                        {
                            properties.Add(prop.Name, prop.Value);
                        }
                        results.Add(properties);
                    }


                    output.Append("[+] Results:");
                    //Code adapted from Seatbelt
                    foreach (var result in results)
                    {
                        var myEnumerator = result.GetEnumerator();
                        
                        while (myEnumerator.MoveNext())
                        {
                            output.Append("\n");
                            var value = myEnumerator.Value;
                            if (value == null)
                            {
                                continue;
                            }

                            var valueType = value.GetType();
                            var valueName = myEnumerator.Key?.ToString();

                            if (valueType.IsArray)
                            {
                                var elemType = valueType.GetElementType();
                                var name = $"{valueName}({valueType.Name})";
                                if (elemType == typeof(string))
                                {
                                    output.Append($"  {name,-30}:");
                                    foreach (var s in (string[])value)
                                    {
                                        output.Append($"      {s}");
                                    }
                                }
                                else
                                {
                                    IEnumerable<string> s = ((IEnumerable)value).Cast<object>()
                                        .Select(x => x.ToString())
                                        .ToArray();

                                    var v = string.Join(",", (string[])s);

                                    output.Append($"  {name,-30}: {v}");
                                }
                            }
                            else
                            {
                                output.Append($"{valueName,-30}: {value}");
                            }
                        }
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
