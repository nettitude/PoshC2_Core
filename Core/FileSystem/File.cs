using System;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Core.FileSystem
{
    internal enum FileSystemRights : uint
    {
        // https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/geteffectivepermission-method-in-class-win32-directory
        ReadData = 1,
        ListDirectory = ReadData, // For directories
        WriteData = 2,
        CreateFiles = WriteData, // For directories
        AppendData = 4,
        CreateDirectories = AppendData, // For directories
        ReadExtendedAttributes = 8,
        WriteExtendedAttributes = 16,
        ExecuteFile = 32, // For files
        Traverse = ExecuteFile, // For directories
        DeleteSubdirectoriesAndFiles = 64,
        ReadAttributes = 128,
        WriteAttributes = 256,
        Delete = 65536,
        ReadPermissions = 131072,
        ChangePermissions = 262144,
        ChangeOwner = 524288,
        Synchronize = 1048576

        // These map to what Explorer sets, and are what most users want.
        // However, an ACL editor will also want to set the Synchronize
        // bit when allowing access, and exclude the synchronize bit when
        // denying access.
    }

    internal static class File
    {
        internal static void GetFileACL(string path)
        {
            var fileSecurity = System.IO.File.GetAccessControl(path);
            var orderedResults = fileSecurity.GetAccessRules(true, true, typeof(NTAccount))
                .Cast<FileSystemAccessRule>()
                .OrderBy(rule => rule.IdentityReference.Value);
            try
            {
                var sid = fileSecurity.GetOwner(typeof(SecurityIdentifier));
                var ntAccount = sid.Translate(typeof(NTAccount)) as NTAccount;
                Console.WriteLine($" Owner: {ntAccount?.Value}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error running GetFileACL: {e.Message}");
            }
            var dateTime = System.IO.File.GetLastAccessTime(path);
            Console.WriteLine($" Last access time : {dateTime}");
            foreach (var rule in orderedResults)
            {
                try
                {
                    var accessMask = int.Parse(rule.FileSystemRights.ToString());
                    Console.Write(" > Account:{0} (", rule.IdentityReference.Value);
                    //https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask-format?redirectedfrom=MSDN
                    //https://blog.cjwdev.co.uk/2011/06/28/permissions-not-included-in-net-accessrule-filesystemrights-enum/
                    foreach (var accessRule in Enum.GetValues(typeof(FileSystemRights)))
                    {
                        if (((uint) accessRule & (uint) accessMask) != 0)
                        {
                            Console.Write($"{accessRule},");
                        }
                    }

                    Console.WriteLine($" {accessMask})");
                }
                catch (Exception)
                {
                    Console.WriteLine(" > Account:{0} ({1}", rule.IdentityReference.Value, rule.FileSystemRights + ")");
                }
            }
        }

        internal static void GetFolderACL(string path)
        {
            var folderSecurity = System.IO.Directory.GetAccessControl(path);
            var orderedResults = folderSecurity.GetAccessRules(true, true, typeof(NTAccount))
                .Cast<FileSystemAccessRule>()
                .OrderBy(rule => rule.IdentityReference.Value);
            try
            {
                var sid = folderSecurity.GetOwner(typeof(SecurityIdentifier));
                var ntAccount = sid.Translate(typeof(NTAccount)) as NTAccount;
                Console.WriteLine($" Owner: {ntAccount?.Value}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error running GetFolderACL: {e.Message}");
            }
            
            var dt = System.IO.File.GetLastAccessTime(path);
            Console.WriteLine($" Last access time : {dt}");
            foreach (var rule in orderedResults)
            {
                try
                {
                    var accessMask = int.Parse(rule.FileSystemRights.ToString());
                    Console.Write(" > Account:{0} (", rule.IdentityReference.Value);
                    //https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask-format?redirectedfrom=MSDN
                    //https://blog.cjwdev.co.uk/2011/06/28/permissions-not-included-in-net-accessrule-filesystemrights-enum/
                    foreach (var accessRule in Enum.GetValues(typeof(FileSystemRights)))
                    {
                        if (((uint) accessRule & (uint) accessMask) != 0)
                        {
                            Console.Write($"{accessRule},");
                        }
                    }

                    Console.WriteLine($" {accessMask})");
                }
                catch (Exception)
                {
                    Console.WriteLine(" > Account:{0} ({1}", rule.IdentityReference.Value, rule.FileSystemRights + ")");
                }
            }
        }
    }
}
