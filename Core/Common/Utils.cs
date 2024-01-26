using System;
using System.IO;
using System.Linq;
using System.Management;

namespace Core.Common
{
    internal static class Utils
    {
        internal static void SearchRecentFiles(string path, DateTime timeThreshold)
        {
            try
            {
                DirectoryInfo dirInfo = new DirectoryInfo(path);

                // Iterate through the files in the current directory
                foreach (FileInfo file in dirInfo.GetFiles())
                {
                    // Check if the file was modified or created after the time threshold
                    if (file.LastWriteTime >= timeThreshold || file.CreationTime >= timeThreshold)
                    {
                        Console.WriteLine(file.FullName + " - Last Modified: " + file.LastWriteTime);
                    }
                }

                // Recursively search through subdirectories
                foreach (DirectoryInfo subDir in dirInfo.GetDirectories())
                {
                    SearchRecentFiles(subDir.FullName, timeThreshold);
                }
            }
            catch (UnauthorizedAccessException)
            {
                // Handle any permission-related issues if required
                Console.WriteLine($"Access to directory '{path}' is denied.");
            }
            catch (Exception ex)
            {
                // Handle any other exceptions if needed
                Console.WriteLine($"An error occurred while searching directory '{path}': {ex.Message}");
            }
        }
        internal static void FindFile(string name, string extension, string drive = "C:", string host = "127.0.0.1")
        {
            try
            {
                var scope = new ManagementScope($"\\\\{host}\\root\\CIMV2", null);
                scope.Connect();
                var query = new ObjectQuery($"Select * from CIM_DataFile Where ((Drive = '{drive}') AND (FileName = '{name}') AND (Extension = '{extension}'))");
                var searcher = new ManagementObjectSearcher(scope, query);

                foreach (var wmiObject in searcher.Get())
                {
                    Console.WriteLine("{0}", (string) wmiObject["Name"]);
                }

                Console.WriteLine("End of search");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        internal static byte[] Combine(byte[] first, byte[] second)
        {
            var combined = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, combined, 0, first.Length);
            Buffer.BlockCopy(second, 0, combined, first.Length, second.Length);
            return combined;
        }

        internal static Type LoadAssembly(string assemblyName)
        {
            return Type.GetType(assemblyName, name => { return AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(z => z.FullName == name.FullName); }, null, true);
        }
    }
}