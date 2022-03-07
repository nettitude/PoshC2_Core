using System;

namespace Core.Arp
{
    internal static class Arp
    {
        internal static void RunArp(string[] args)
        {
            try
            {
                if (args.Length < 2)
                {
                    Console.WriteLine("Usage: ArpScan 172.16.0.1/24 true");
                }
                else
                {
                    var result = ArpScanner.DoScan(args[1]);

                    if (args.Length > 2 && !string.IsNullOrEmpty(args[2]))
                    {
                        Console.WriteLine("");
                        Console.WriteLine($"[+] ArpScan / IP resolution against: {args[1]}");
                        Console.WriteLine("================================================================");
                        foreach (var kvp in result)
                        {
                            var hostname = ArpScanner.GetHostByNetBiosAddress(kvp.Key);

                            Console.WriteLine("IP Address = {0}, Hostname = {1}, MAC = {2}", kvp.Key, hostname, kvp.Value);
                        }
                    }
                    else
                    {
                        Console.WriteLine($"[+] ArpScan against: {args[1]}");
                        Console.WriteLine("=================================================");
                        foreach (var kvp in result)
                        {
                            Console.WriteLine("IP Address = {0}, MAC = {1}", kvp.Key, kvp.Value);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error: {e}");
            }
        }
    }
}