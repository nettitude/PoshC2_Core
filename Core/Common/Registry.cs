using System;

namespace Core.Common
{
    internal static class Registry
    {
        public static void WriteHKCURegKey(string regKey, string name, string value)
        {
            var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(regKey);
            if (key == null)
            {
                Console.WriteLine($"[-] Failed to create key: {regKey}");
                return;
            }

            key.SetValue(name, value);
            key.Close();
        }

        public static void RegReadUninstall()
        {
            const string regKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
            using var uninstallKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(regKey);
            if (uninstallKey == null) return;
            var productKeys = uninstallKey.GetSubKeyNames();
            foreach (var keyName in productKeys)
            {
                var installPath = (string) Microsoft.Win32.Registry.GetValue($"HKEY_LOCAL_MACHINE\\{regKey}\\{keyName}", "UninstallString", null);
                var displayName = (string) Microsoft.Win32.Registry.GetValue($"HKEY_LOCAL_MACHINE\\{regKey}\\{keyName}", "DisplayName", null);
                if (installPath != null)
                {
                    Console.WriteLine($"Key Value {keyName}:\n > {displayName} : {installPath}");
                }
            }
        }

        public static void LsReg(string regKey, string hive = "HKEY_LOCAL_MACHINE")
        {
            var openRegKey = hive switch
            {
                "HKEY_CLASSES_ROOT" => Microsoft.Win32.Registry.ClassesRoot.OpenSubKey(regKey, false),
                "HKEY_CURRENT_USER" => Microsoft.Win32.Registry.CurrentUser.OpenSubKey(regKey, false),
                "HKEY_LOCAL_MACHINE" => Microsoft.Win32.Registry.LocalMachine.OpenSubKey(regKey, false),
                "HKEY_USERS" => Microsoft.Win32.Registry.Users.OpenSubKey(regKey, false),
                "HKEY_CURRENT_CONFIG" => Microsoft.Win32.Registry.CurrentConfig.OpenSubKey(regKey, false),
                _ => throw new NotSupportedException($"Unknown hive: {hive}")
            };

            using (openRegKey)
            {
                if (openRegKey != null)
                {
                    var productKeys = openRegKey.GetSubKeyNames();
                    foreach (var keyName in productKeys)
                    {
                        try
                        {
                            Console.WriteLine(keyName);
                            using var key2 = openRegKey.OpenSubKey(keyName);
                            foreach (var valueName in key2.GetValueNames())
                            {
                                try
                                {
                                    string value = null;
                                    string[] strArrayValue = null;
                                    byte[] byteValue = null;
                                    try
                                    {
                                        value = Microsoft.Win32.Registry.GetValue($"{hive}\\{regKey}\\{keyName}", valueName, null).ToString();
                                    }
                                    catch
                                    {
                                        // deliberate pass
                                    }

                                    try
                                    {
                                        strArrayValue = (string[]) Microsoft.Win32.Registry.GetValue($"{hive}\\{regKey}\\{keyName}", valueName, null);
                                    }
                                    catch
                                    {
                                        // deliberate pass
                                    }

                                    try
                                    {
                                        byteValue = (byte[]) Microsoft.Win32.Registry.GetValue($"{hive}\\{regKey}\\{keyName}", valueName, null);
                                    }
                                    catch
                                    {
                                        // deliberate pass
                                    }

                                    if (strArrayValue != null)
                                    {
                                        Console.WriteLine($" > {valueName} : ");
                                        foreach (var val in strArrayValue)
                                        {
                                            Console.WriteLine($"  >> {val}");
                                        }
                                    }
                                    else if (byteValue != null)
                                    {
                                        Console.Write($" > {valueName} : \n  >> ");
                                        foreach (var val in byteValue)
                                        {
                                            Console.Write(val);
                                        }

                                        Console.WriteLine("");
                                    }
                                    else if (value != null)
                                    {
                                        var strKeyName = string.IsNullOrEmpty(valueName) ? "Default" : valueName;

                                        Console.WriteLine($" > {strKeyName} : {value}");
                                    }
                                    else
                                    {
                                        Console.WriteLine(valueName);
                                    }
                                }
                                catch (Exception e)
                                {
                                    Console.WriteLine(e.Message);
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e.Message);
                        }
                    }
                }
            }
        }

        public static void ReadReg(string regPath, string regKey)
        {
            try
            {
                var installPath = (string) Microsoft.Win32.Registry.GetValue(regPath, regKey, null);
                if (installPath != null)
                {
                    Console.WriteLine($"Key Value: {installPath}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading RegKey: {ex.Message}");
            }
        }
    }
}