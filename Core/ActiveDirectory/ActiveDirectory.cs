using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Text;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;
using System.Collections;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Reflection;
using Core.WindowsInternals;

namespace Core.ActiveDirectory
{
    internal static class ActiveDirectory
    {
        //https://stackoverflow.com/questions/926227/how-to-detect-if-machine-is-joined-to-domain
        private static bool IsInDomain()
        {
            var result = Internals.NetGetJoinInformation(null, out var pDomain, out var status);
            if (pDomain != IntPtr.Zero)
            {
                Internals.NetApiBufferFree(pDomain);
            }

            if (result == Internals.ERROR_SUCCESS)
            {
                return status == Internals.NetJoinStatus.NetSetupDomainName;
            }

            throw new Exception("Domain Info Get Failed", new Win32Exception());
        }

        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
        // https://docs.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netgetaadjoininformation
        // https://support.microsoft.com/en-us/help/2909958/exceptions-in-windows-powershell-other-dynamic-languages-and-dynamical
        // https://deploywindows.com/2020/09/16/dont-wrap-dsregcmd-with-powershell-use-this-to-get-azure-ad-information-from-the-local-computer/
        public static void GetAADJoinInformation()
        {
            var ptrUserInfo = IntPtr.Zero;
            var ptrJoinCertificate = IntPtr.Zero;
            var joinInfo = new Internals.DsregJoinInfo();

            Internals.NetFreeAadJoinInformation(IntPtr.Zero);
            var retValue = Internals.NetGetAadJoinInformation(null, out var ptrJoinInfo);

            if (retValue == 0)
            {
                Console.WriteLine("[+] Starting Aad Enum:");

                try
                {
                    var ptrJoinInfoObject = new Internals.DsregJoinInfo();
                    joinInfo = (Internals.DsregJoinInfo) Marshal.PtrToStructure(ptrJoinInfo, ptrJoinInfoObject.GetType());

                    var fieldInfo = typeof(Internals.DsregJoinInfo).GetFields(BindingFlags.Public | BindingFlags.Instance);
                    foreach (var info in fieldInfo)
                    {
                        var value = info.GetValue(joinInfo);
                        Console.WriteLine($" > {info.Name} : {value}");
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[-] Error running Aad Enum: {e.Message}");
                }

                try
                {
                    Console.WriteLine("\n[+] Starting UserInfo Enum:");
                    ptrUserInfo = joinInfo.pUserInfo;
                    var ptrUserInfoObject = new Internals.DsregUserInfo();
                    var userInfo = (Internals.DsregUserInfo) Marshal.PtrToStructure(ptrUserInfo, ptrUserInfoObject.GetType());

                    var fieldInfo = typeof(Internals.DsregUserInfo).GetFields(BindingFlags.Public | BindingFlags.Instance);
                    foreach (var info in fieldInfo)
                    {
                        var value = info.GetValue(userInfo);
                        Console.WriteLine($" > {info.Name} : {value}");
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[-] Error running UserInfo Enum: {e.Message}");
                }

                try
                {
                    Console.WriteLine("\n[+] Starting JoinCertificate Enum:");
                    ptrJoinCertificate = joinInfo.pJoinCertificate;
                    var ptrJoinCertificateObject = new Internals.CertContex();
                    var joinCertificate = Marshal.PtrToStructure(ptrJoinCertificate, ptrJoinCertificateObject.GetType());
                    var fieldInfo = typeof(Internals.CertContex).GetFields(BindingFlags.Public | BindingFlags.Instance);
                    foreach (var info in fieldInfo)
                    {
                        var value = info.GetValue(joinCertificate);
                        Console.WriteLine($" > {info.Name} : {value}");
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[-] Error running JoinCertificate Enum: {e.Message}");
                }

                Console.WriteLine("\n[+] Starting Connect Enum:");
                try
                {
                    Console.WriteLine(IsInDomain() ? " > DomainJoined : true" : " > DomainJoined : false");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[-] Error running Domain Join Check Enum: {e.Message}");
                }

                switch ((Internals.DsregJoinType) joinInfo.joinType)
                {
                    case Internals.DsregJoinType.DsregDeviceJoin:
                    {
                        Console.WriteLine(" > AzureAD Joined : true");
                        break;
                    }
                    case Internals.DsregJoinType.DsregUnknownJoin:
                    {
                        Console.WriteLine(" > Device is not joined");
                        break;
                    }
                    case Internals.DsregJoinType.DsregWorkplaceJoin:
                    {
                        Console.WriteLine(" > Workplace Joined : true");
                        break;
                    }
                    default:
                        throw new ArgumentOutOfRangeException("Unknown join type: " + joinInfo.joinType);
                }

                try
                {
                    if (ptrJoinInfo != IntPtr.Zero)
                    {
                        Marshal.Release(ptrJoinInfo);
                    }

                    if (ptrUserInfo != IntPtr.Zero)
                    {
                        Marshal.Release(ptrUserInfo);
                    }

                    if (ptrJoinCertificate != IntPtr.Zero)
                    {
                        Marshal.Release(ptrJoinCertificate);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine($"\n[-] Error Releasing PTRs: {e.Message}");
                }
            }
            else
            {
                Console.WriteLine("[-] No NetGetAadJoinInformation Info");
            }
        }

        // Convert an object to a byte array
        private static byte[] ObjectToByteArray(object obj)
        {
            if (obj == null)
                return null;

            var bf = new BinaryFormatter();
            var ms = new MemoryStream();
            bf.Serialize(ms, obj);

            return ms.ToArray();
        }

        public static void NetSessionEnumFunc(string computer)
        {
            var sessionInfo = new List<Internals.SessionInfo>(); // TODO we never actually do anything with this but add to it?
            // arguments for NetSessionEnum
            const int queryLevel = 10;
            var entriesRead = 0;
            var totalRead = 0;
            var resumeHandle = 0;
            var userName = string.Empty;

            // get session information
            var result = Internals.NetSessionEnum(computer, string.Empty, userName, queryLevel, out var ptrInfo, -1, ref entriesRead, ref totalRead, ref resumeHandle);

            // locate the offset of the initial intPtr
            var offset = ptrInfo.ToInt64();

            // 0 = success
            if (result == 0 && offset > 0)
            {
                // work out how much to increment the pointer by finding out the size of the structure
                var increment = Marshal.SizeOf(typeof(Internals.SessionInfo10));

                // parse all the result structures
                for (var i = 0; i < entriesRead; i++)
                {
                    // create a new int ptr at the given offset and cast the pointer as our result structure
                    var newIntPtr = new IntPtr(offset);
                    var info = (Internals.SessionInfo10) Marshal.PtrToStructure(newIntPtr, typeof(Internals.SessionInfo10));

                    // return all the sections of the structure - have to do it this way for V2
                    var session = new Internals.SessionInfo
                    {
                        ComputerName = computer,
                        CName = info.sesi10_cname,
                        UserName = info.sesi10_username,
                        Time = info.sesi502_time,
                        IdleTime = info.sesi502_idle_time
                    };
                    Console.WriteLine($"{computer} {info.sesi10_cname} {info.sesi10_username} {info.sesi502_time} {info.sesi502_idle_time}");
                    offset = newIntPtr.ToInt64();
                    offset += increment;
                    sessionInfo.Add(session);
                }

                // free up the result buffer
                Internals.NetApiBufferFree(ptrInfo);
            }
            else
            {
                Console.WriteLine($@"[Get-NetSession] Error: {new Win32Exception(result).Message}");
            }
        }

        public static void LocalGroupMember(string computer, string groupName)
        {
            try
            {
                Console.WriteLine("\r\n===================================");
                Console.WriteLine($"LocalGroupMember ({computer})");
                Console.WriteLine("===================================");

                Console.WriteLine($"Using DirectoryEntry: WinNT://{computer}/{groupName},group");

                var root = new DirectoryEntry($"WinNT://{computer}/{groupName},group");

                Console.WriteLine("Name: " + root.Properties["Name"].Value);
                Console.WriteLine("AccountName: " + root.Properties["AccountName"].Value);


                foreach (string propName in root.Properties.PropertyNames)
                {
                    var valueCollection = root.Properties[propName];
                    foreach (var propertyValue in valueCollection)
                    {
                        if (propName.Contains("objectSid"))
                        {
                            var valueAsByteArray = ObjectToByteArray(propertyValue);
                            var asciiString = Encoding.UTF8.GetString(valueAsByteArray);
                            Console.WriteLine(propName + ": " + asciiString);
                        }
                        else
                        {
                            Console.WriteLine(propName + ": " + propertyValue);
                        }
                    }
                }

                foreach (var member in (IEnumerable) root.Invoke("Members"))
                {
                    using var memberEntry = new DirectoryEntry(member);
                    Console.WriteLine("- " + memberEntry.Path); // No groups displayed...
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public static void NetShareEnum(string hostname)
        {
            //https://github.com/tevora-threat/SharpView/blob/master/SharpView/PowerView.cs
            // arguments for NetShareEnum
            var shareInfos = new List<Internals.ShareInfo>(); // TODO we never actually do anything with this but add to it?
            const int queryLevel = 1;
            var ptrInfo = IntPtr.Zero;
            var entriesRead = 0;
            var totalRead = 0;
            var resumeHandle = 0;

            // get the raw share information
            var result = Internals.NetShareEnum(hostname, queryLevel, ref ptrInfo, Internals.MAX_PREFERRED_LENGTH, ref entriesRead, ref totalRead, ref resumeHandle);

            // locate the offset of the initial intPtr
            var offset = ptrInfo.ToInt64();

            // 0 = success
            if (result == 0 && offset > 0)
            {
                // work out how much to increment the pointer by finding out the size of the structure
                var increment = Marshal.SizeOf(typeof(Internals.ShareInfo1));

                // parse all the result structures
                for (var i = 0; i < entriesRead; i++)
                {
                    // create a new int ptr at the given offset and cast the pointer as our result structure
                    var newIntPtr = new IntPtr(offset);
                    var info = (Internals.ShareInfo1) Marshal.PtrToStructure(newIntPtr, typeof(Internals.ShareInfo1));

                    // return all the sections of the structure - have to do it this way for V2
                    shareInfos.Add(new Internals.ShareInfo
                    {
                        Name = info.shi1_netname,
                        Type = info.shi1_type,
                        Remark = info.shi1_remark,
                        ComputerName = hostname
                    });
                    Console.WriteLine($"\\\\{hostname}\\{info.shi1_netname} - {info.shi1_type} {info.shi1_remark}");
                    offset = newIntPtr.ToInt64();
                    offset += increment;
                }

                // free up the result buffer
                Internals.NetApiBufferFree(ptrInfo);
            }
            else
            {
                Console.WriteLine($@" Error accessing {hostname}: {new Win32Exception(result).Message}");
            }
        }


        public static void AdSearcher(string ldapSearch, string searchRoot, string property, bool recurse = false, bool resolve = false)
        {
            Console.WriteLine("\r\n==============================================================================");
            Console.WriteLine($"Domain Searcher ({ldapSearch})");
            Console.WriteLine("==============================================================================");

            var members = new List<string>();
            var memberOfs = new List<string>();

            var searcher = new DirectorySearcher();
            if (!string.IsNullOrEmpty(searchRoot))
            {
                Console.WriteLine($"searchRoot ({searchRoot})");
                var entry = new DirectoryEntry(searchRoot);
                searcher = new DirectorySearcher(entry);
            }

            //searcher.Filter = $"(&(objectCategory=user)(cn=))";
            searcher.Filter = ldapSearch;
            searcher.Filter = ldapSearch;

            if (!string.IsNullOrEmpty(property))
            {
                foreach (var varProperty in property.Split(','))
                {
                    searcher.PropertiesToLoad.Add(varProperty);
                }
            }

            foreach (SearchResult searchResult in searcher.FindAll())
            {
                if (searchResult.Properties.PropertyNames == null) continue;
                Console.WriteLine(); // Adding a new line in order to be able to visually differentiate between multiple results
                foreach (string propName in searchResult.Properties.PropertyNames)
                {
                    var valueCollection = searchResult.Properties[propName];
                    foreach (var propertyValue in valueCollection)
                    {
                        if (propName.Contains("userpassword"))
                        {
                            var byteArrayValue = ObjectToByteArray(propertyValue);
                            var asciiString = Encoding.ASCII.GetString(byteArrayValue);
                            Console.WriteLine(propName + ": " + asciiString);
                        }
                        else if (propName == "member")
                        {
                            Console.WriteLine(propName + ": " + propertyValue);
                            members.Add(propertyValue.ToString());
                        }
                        else if (propName == "memberof")
                        {
                            Console.WriteLine(propName + ": " + propertyValue);
                            memberOfs.Add(propertyValue.ToString());
                        }
                        else if (propName.Contains("badpasswordtime") || propName.Contains("pwdlastset") || propName.Contains("lastlogontimestamp") || propName.Contains("lockouttime"))
                        {
                            var time = DateTime.FromFileTime((long) propertyValue);
                            Console.WriteLine(propName + ": (CONVERTED) " + time);
                        }
                        else if (!string.IsNullOrEmpty(property) && propName.Contains("adspath"))
                        {
                            // Do nothing
                        }
                        else
                        {
                            Console.WriteLine(propName + ": " + propertyValue);
                        }
                    }
                }
            }

            if (resolve)
            {
                // finally do a lookup for the samaccountname of member
                Console.WriteLine("[+] Resolving group names:");
                foreach (var memberCN in memberOfs)
                {
                    try
                    {
                        AdSearcher("(&(objectCategory=group))", $"LDAP://{memberCN}", "samaccountname");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Error running resolver {e.Message}");
                    }
                }
            }

            if (recurse)
            {
                // finally do a recursive lookup for the samaccountname of members
                Console.WriteLine("[+] Doing recursive query:");
                foreach (var memberCN in members)
                {
                    try
                    {
                        AdSearcher("(&(objectCategory=group))", $"LDAP://{memberCN}", "member", true);
                        AdSearcher("(&(objectCategory=user))", $"LDAP://{memberCN}", "samaccountname");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Error running recursive {e.Message}");
                    }
                }
            }
        }
    }
}
