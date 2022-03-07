using System;
using System.Linq;
using System.Management;

namespace Core.Common
{
    internal static class Utils
    {
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
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
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
            return Type.GetType(assemblyName, (name) => { return AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(z => z.FullName == name.FullName); }, null, true);
        }
    }
}