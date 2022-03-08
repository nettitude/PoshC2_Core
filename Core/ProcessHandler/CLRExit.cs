using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;
using Core.WindowsInternals;

namespace Core.ProcessHandler
{
    public static class CLRExit
    {
        public static void StopEnvironmentExit()
        {
            var methods = new List<MethodInfo>(typeof(Environment).GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic));
            var exitMethod = methods.Find(methodInfo => methodInfo.Name == "Exit");
            RuntimeHelpers.PrepareMethod(exitMethod.MethodHandle);
            var exitMethodPtr = exitMethod.MethodHandle.GetFunctionPointer();

            unsafe
            {
                var target = exitMethod.MethodHandle.GetFunctionPointer();
                Console.WriteLine($"Writing ret to memory location: {exitMethodPtr.ToString("x")}");

                if (Internals.VirtualProtectEx((IntPtr) (-1), target, 1, Internals.PAGE_READWRITE, out var flOldProtect))
                {
                    *(byte*) target = 0xc3; // ret
                    Internals.VirtualProtectEx((IntPtr) (-1), target, 1, flOldProtect, out flOldProtect);
                }
            }
        }
    }
}