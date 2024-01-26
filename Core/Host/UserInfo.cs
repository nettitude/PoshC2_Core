using System;
using System.Collections.Generic;
using System.Management;
using System.DirectoryServices;
using System.Collections;

namespace Core.Host
{
    internal static class UserInfo
    {
        public static void GetUserInfo()
        {
            try
            {
                var wmiData = new ManagementObjectSearcher(@"root\cimv2", "Select * from win32_operatingsystem");
                var data = wmiData.Get();

                foreach (var result in data)
                {
                    Console.WriteLine("LastBootTime: " + ManagementDateTimeConverter.ToDateTime(result["LastBootUpTime"].ToString()));
                }

                wmiData = new ManagementObjectSearcher(@"root\cimv2", "Select * from Win32_UserAccount Where LocalAccount = True");
                data = wmiData.Get();

                Console.WriteLine("\r\n======================");
                Console.WriteLine("Local Users");
                Console.WriteLine("======================");
                foreach (var result in data)
                {
                    Console.WriteLine(result["Name"]);
                }

                Console.WriteLine("\r\n======================");
                Console.WriteLine("Local Groups");
                Console.WriteLine("======================");
                wmiData = new ManagementObjectSearcher(@"root\cimv2", "Select * from Win32_Group Where LocalAccount = True");
                data = wmiData.Get();

                foreach (var result in data)
                {
                    Console.WriteLine(result["Name"]);
                }

                Console.WriteLine("\r\n=========================");
                Console.WriteLine("Members of Local Groups");
                Console.WriteLine("=========================");
                wmiData = new ManagementObjectSearcher(@"root\cimv2", "Select * from Win32_Group Where LocalAccount = True");
                data = wmiData.Get();

                var members = new List<string>();
                var cn = Environment.GetEnvironmentVariable("COMPUTERNAME");
                foreach (var result in data)
                {
                    var wmiDataG = new ManagementObjectSearcher(@"root\cimv2",
                        $"Select * from Win32_GroupUser Where GroupComponent=\"Win32_Group.Domain='{cn}',Name='{result["Name"]}'\"");
                    var gData = wmiDataG.Get();

                    if (gData.Count > 0)
                    {
                        Console.WriteLine("\r\n> " + result["Name"]);
                        Console.WriteLine("======================");
                        foreach (var gMember in gData)
                        {
                            var splitArgs = gMember.GetPropertyValue("PartComponent").ToString().Split(new[] {","}, StringSplitOptions.RemoveEmptyEntries);
                            var sDomain = splitArgs[0].Split(new[] {"="}, StringSplitOptions.RemoveEmptyEntries)[1].Replace("\"", "");
                            var sUser = splitArgs[1].Split(new[] {"="}, StringSplitOptions.RemoveEmptyEntries)[1].Replace("\"", "");
                            members.Add(sDomain + "\\" + sUser);
                        }

                        members.ForEach(i => Console.Write("{0}\r\n", i));
                        members.Clear();
                    }
                }

                try
                {
                    Console.WriteLine("\r\n==========================");
                    Console.WriteLine($"Domain UserInfo ({Environment.UserName})");
                    Console.WriteLine("==========================");
                    var searcher = new DirectorySearcher {Filter = $"(&(objectCategory=user)(cn={Environment.UserName}))"};
                    searcher.FindAll();

                    foreach (SearchResult searchResult in searcher.FindAll())
                    {
                        if (searchResult.Properties.PropertyNames == null) continue;
                        foreach (string propName in searchResult.Properties.PropertyNames)
                        {
                            var valueCollection =
                                searchResult.Properties[propName];
                            foreach (var propertyValue in valueCollection)
                            {
                                Console.WriteLine(propName + ": " + propertyValue);
                            }
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error: {e.Message}");
                }

                try
                {
                    Console.WriteLine("\r\n===================================");
                    Console.WriteLine($"Domain Password Policy ({Environment.UserDomainName})");
                    Console.WriteLine("===================================");

                    Console.WriteLine($"Using DirectoryEntry: WinNT://{Environment.UserDomainName}");

                    var root = new DirectoryEntry($"WinNT://{Environment.UserDomainName}");
                    Console.WriteLine("Name: " + root.Properties["Name"].Value);
                    Console.WriteLine("MinPasswordLength: " + root.Properties["MinPasswordLength"].Value);
                    Console.WriteLine("MinPasswordAge: " + (int) root.Properties["MinPasswordAge"].Value / 86400);
                    Console.WriteLine("MaxPasswordAge: " + (int) root.Properties["MaxPasswordAge"].Value / 86400);
                    Console.WriteLine("PasswordHistoryLength: " + root.Properties["PasswordHistoryLength"].Value);
                    Console.WriteLine("MaxBadPasswordsAllowed: " + root.Properties["MaxBadPasswordsAllowed"].Value);
                    Console.WriteLine("AutoUnlockInterval: " + (int) root.Properties["AutoUnlockInterval"].Value / 60);
                    Console.WriteLine("LockoutObservationInterval: " + (int) root.Properties["LockoutObservationInterval"].Value / 60);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error: {e.Message}");
                }

                try
                {
                    Console.WriteLine("\r\n===================================");
                    Console.WriteLine("GetEnvironmentVariables: ");
                    Console.WriteLine("\r\n===================================");
                    foreach (DictionaryEntry de in Environment.GetEnvironmentVariables())
                    {
                        Console.WriteLine("{0} = {1}", de.Key, de.Value);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error GetEnvironmentVariables: {e.Message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: {0}", ex);
            }
        }
    }
}