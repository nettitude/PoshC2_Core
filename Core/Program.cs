using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using Core.Common;

namespace Core
{
    public static class Program
    {
        public static readonly Dictionary<string, string> ARGUMENTS = new();

        public static void PrintHelp()
        {
            Console.WriteLine("");
            Console.WriteLine("PoshC2 - Core Module");
            Console.WriteLine("===========================================");

            var coreMethods = typeof(Core).GetMethods();
            try
            {
                foreach (var coreMethod in coreMethods)
                {
                    var method = typeof(Core).GetMethod(coreMethod.Name);
                    var attributes = method?.GetCustomAttributes(true);
                    if (attributes is not {Length: > 0}) continue;
                    Console.WriteLine((attributes[0] as CoreDispatch)?.Usage);
                    Console.WriteLine($"\t{(attributes[0] as CoreDispatch)?.Description}");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error in help: {e}");
            }
        }

        public static void Main(string[] args)
        {
            if (args.Length == 0 || args.Length > 1 && (args[1].ToLower() == "-help" || args[1].ToLower() == "help" || args[1].ToLower() == "?" || args[1].ToLower() == "-h"))
            {                
                PrintHelp();
                Console.WriteLine($"FileVersion: {FileVersionInfo.GetVersionInfo((Assembly.GetExecutingAssembly()).Location).FileVersion}");
                Console.WriteLine($"ProductVersion: {FileVersionInfo.GetVersionInfo((Assembly.GetExecutingAssembly()).Location).ProductVersion}");
                return;
            }

            try
            {
                Run(args.ToList());
            }
            catch (Exception e)
            {
                Console.WriteLine("Core generated an error: '{0}'", e);
            }
        }

        private static void Run(List<string> args)
        {
            if (args.Count < 1)
            {
                Console.WriteLine("Error: No args passed to run");
                return;
            }

            var methodName = args[0].ToLower().Replace("-", "");

            // parse args like in SharpWMI - https://github.com/GhostPack/SharpWMI/blob/master/SharpWMI/Program.cs
            foreach (var argument in args)
            {
                var idx = argument.IndexOf('=');
                if (idx > 0)
                    ARGUMENTS[argument.Substring(0, idx)] = argument.Substring(idx + 1);
            }

            var coreMethods = typeof(Core).GetMethods();
            MethodInfo method;

            var coreMethod = coreMethods.FirstOrDefault(i => methodName == i.Name.ToLower());

            if (coreMethod != null)
            {
                method = typeof(Core).GetMethod(coreMethod.Name);
            }
            else
            {
                Console.WriteLine("[!] No command found in core");
                return;
            }

            if (method == null)
            {
                Console.WriteLine("[-] Unable to get method - GetMethod returned null");
                return;
            }
            
            var parameters = method.GetParameters();
            
            if (parameters.Length == 0)
            {
                // The method has no parameters
                method.Invoke(null, null);
                return;
            }

            method.Invoke(null, new object[] {args.ToArray()});
        }
    }
}