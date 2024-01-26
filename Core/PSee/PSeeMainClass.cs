using System;
using System.Text;

namespace Core.PSee
{
    internal static class PSeeMainClass
    {
        internal static void Run()
        {
            try
            {
                Console.WriteLine("#################");
                Console.WriteLine("MachineEnum");
                Console.WriteLine("#################");
                try
                {
                    MachineEnum();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }

                Console.WriteLine("#################");
                Console.WriteLine("UserEnum");
                Console.WriteLine("#################");
                try
                {
                    UserEnum();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }

                Console.WriteLine("#################");
                Console.WriteLine("RecentFiles");
                Console.WriteLine("#################");
                try
                {
                    RecentFiles(50);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }

                Console.WriteLine("####################");
                Console.WriteLine("Suspicious Processes");
                Console.WriteLine("####################");
                try
                {
                    Processes();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }

                Console.WriteLine("#################");
                Console.WriteLine("ChromeBookmarks");
                Console.WriteLine("#################");
                try
                {
                    ChromeBook();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }

                Console.WriteLine("#################");
                Console.WriteLine("IEBookmarks");
                Console.WriteLine("#################");
                try
                {
                    IeBook();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }

                Console.WriteLine("#################");
                Console.WriteLine("EnumSoftware");
                Console.WriteLine("#################");
                try
                {
                    EnumSoftware();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        internal static void MachineEnum()
        {
            var sb = new StringBuilder();
            foreach (var n in PSeeMain.MachineEnum())
            {
                sb.Append("\t");
                sb.Append(n.Key);
                sb.Append(":");
                sb.AppendLine(n.Value);
            }

            Console.WriteLine(sb.ToString());
        }

        internal static void UserEnum()
        {
            var sb = new StringBuilder();
            foreach (var n in PSeeMain.UserEnum())
            {
                sb.Append("\t");
                sb.Append(n.Key);
                sb.Append(": ");
                sb.AppendLine(n.Value);
            }

            Console.WriteLine(sb.ToString());
        }

        internal static void RecentFiles(int fileCount = 10)
        {
            var sb = new StringBuilder();
            foreach (var n in PSeeMain.RecentFiles(fileCount)) sb.AppendLine("\t" + n);

            Console.WriteLine(sb.ToString());
        }

        internal static void Processes()
        {
            var sb = new StringBuilder();
            foreach (var n in PSeeMain.EnumProcesses()) sb.AppendLine("\t" + n);
            Console.WriteLine(sb.ToString());
        }

        internal static void ChromeBook()
        {
            var sb = new StringBuilder();
            foreach (var n in PSeeMain.ChrBookmarks()) sb.AppendLine("\t" + n);
            Console.WriteLine(sb.ToString());
        }

        internal static void IeBook()
        {
            var sb = new StringBuilder();
            foreach (var n in PSeeMain.IeBookmarks()) sb.AppendLine("\t" + n);
            Console.WriteLine(sb.ToString());
        }

        internal static void EnumSoftware()
        {
            var sb = new StringBuilder();
            foreach (var n in PSeeMain.InstSoftware()) sb.AppendLine("\t" + n);
            Console.WriteLine(sb.ToString());
        }
    }
}