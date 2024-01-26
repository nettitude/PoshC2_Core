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
using System.Security.Principal;
using Core.WindowsInternals;

namespace Core.ActiveDirectory
{
    internal static class ActiveDirectory
    {
        [Flags]
		public enum SupportedEncryptionTypes : int
		{
			DES_CBC_CRC = 0x01,
			DES_CBC_MD5 = 0x02,
			RC4_HMAC = 0x04,
			AES128_CTS_HMAC_SHA1_96 = 0x08,
			AES256_CTS_HMAC_SHA1_96 = 0x10
		}
		[Flags]
		public enum UserAccountControl : int
		{
			SCRIPT = 0x00000001,
			ACCOUNTDISABLE = 0x00000002,
			HOMEDIR_REQUIRED = 0x00000008,
			LOCKOUT = 0x00000010,
			PASSWD_NOTREQD = 0x00000020,
			PASSWD_CANT_CHANGE = 0x00000040,
			ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x00000080,
			TEMP_DUPLICATE_ACCOUNT = 0x00000100,
			NORMAL_ACCOUNT = 0x00000200,
			INTERDOMAIN_TRUST_ACCOUNT = 0x00000800,
			WORKSTATION_TRUST_ACCOUNT = 0x00001000,
			SERVER_TRUST_ACCOUNT = 0x00002000,
			DONT_EXPIRE_PASSWD = 0x00010000,
			MNS_LOGON_ACCOUNT = 0x00020000,
			SMARTCARD_REQUIRED = 0x00040000,
			TRUSTED_FOR_DELEGATION = 0x00080000,
		 	NOT_DELEGATED = 0x00100000,
			USE_DES_KEY_ONLY = 0x00200000,
			DONT_REQUIRE_PREAUTH = 0x00400000,
			PASSWORD_EXPIRED = 0x00800000,
			TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000,
			PARTIAL_SECRETS_ACCOUNT = 0x04000000,
			USE_AES_KEYS = 0x08000000
		}
		[Flags]
		public enum SamAccountType : int
		{
			SAM_DOMAIN_OBJECT = 0x0,
			SAM_GROUP_OBJECT = 0x10000000,
			SAM_NON_SECURITY_GROUP_OBJECT = 0x10000001,
			SAM_ALIAS_OBJECT = 0x20000000,
			SAM_NON_SECURITY_ALIAS_OBJECT = 0x20000001,
			SAM_USER_OBJECT = 0x30000000,
			SAM_NORMAL_USER_ACCOUNT = 0x30000000,
			SAM_MACHINE_ACCOUNT = 0x30000001,
			SAM_TRUST_ACCOUNT = 0x30000002,
			SAM_APP_BASIC_GROUP = 0x40000000,
			SAM_APP_QUERY_GROUP = 0x40000001,
			SAM_ACCOUNT_TYPE_MAX = 0x7fffffff
		}
		[Flags]
		public enum TrustAttributes : int
		{
			TRUST_ATTRIBUTE_NON_TRANSITIVE = 0x00000001,
			TRUST_ATTRIBUTE_UPLEVEL_ONLY = 0x00000002,
			TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 0x00000004,
			TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 0x00000008,
			TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x00000010,
			TRUST_ATTRIBUTE_WITHIN_FOREST = 0x00000020,
			TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL = 0x00000040,
			TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION = 0x00000080,
			TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION = 0x00000200,
			TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION = 0x00000800,
			TRUST_ATTRIBUTE_PIM_TRUST = 0x00000400
		}
		[Flags]
		public enum PkiEnrollmentFlag : int
		{
			CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001,
			CT_FLAG_PEND_ALL_REQUESTS = 0x00000002,
			CT_FLAG_PUBLISH_TO_KRA_CONTAINER = 0x00000004,
			CT_FLAG_PUBLISH_TO_DS = 0x00000008,
            CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010,
			CT_FLAG_AUTO_ENROLLMENT = 0x00000020,
			CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040,
			CT_FLAG_ADD_OCSP_NOCHECK = 0x00001000,
			CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS = 0x00004000,
			CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00008000,
			CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x00010000,
			CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000
		}
		[Flags]
		public enum CertificateNameFlag : uint
		{
			CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001,
			CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000,
			CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000,
			CT_FLAG_SUBJECT_ALT_REQUIRE_SPN = 0x00800000,
			CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000,
			CT_FLAG_SUBJECT_ALT_REQUIRE_UPN = 0x02000000,
			CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000,
			CT_FLAG_SUBJECT_ALT_REQUIRE_DNS = 0x08000000,
			CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN= 0x10000000,
			CT_FLAG_SUBJECT_REQUIRE_EMAIL = 0x20000000,
			CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME = 0x40000000,
			CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000,
			CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008
		}
		[Flags]
		public enum PrivateKeyFlag : int
		{
			CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL = 0x00000001,
			CT_FLAG_EXPORTABLE_KEY = 0x00000010,
			CT_FLAG_STRONG_KEY_PROTECTION_REQUIRED = 0x00000020,
			CT_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM = 0x00000040,
			CT_FLAG_REQUIRE_SAME_KEY_RENEWAL = 0x00000080,
			CT_FLAG_USE_LEGACY_PROVIDER = 0x00000100,
			CT_FLAG_ATTEST_NONE = 0x00000000,
			CT_FLAG_ATTEST_REQUIRED = 0x00002000,
			CT_FLAG_ATTEST_PREFERRED = 0x00001000,
			CT_FLAG_ATTESTATION_WITHOUT_POLICY = 0x00004000,
			CT_FLAG_EK_TRUST_ON_USE = 0x00000200,
			CT_FLAG_EK_VALIDATE_CERT = 0x00000400,
			CT_FLAG_EK_VALIDATE_KEY = 0x00000800,
			CT_FLAG_HELLO_LOGON_KEY = 0x00200000
		}

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
                        else if (propName.ToLower() == "objectsid" || propName.ToLower() == "ms-ds-creatorsid")
                        {
                            Console.WriteLine(propName + ": " + new SecurityIdentifier((byte[])propertyValue, 0));
                        }
                        else if (propName.Contains("badpasswordtime") || propName.Contains("pwdlastset") || propName.Contains("lastlogontimestamp") || propName.Contains("lockouttime") || propName.Contains("lastlogon"))
                        {
                            var time = DateTime.FromFileTimeUtc((long)propertyValue).ToString("u");
                            Console.WriteLine(propName + ": (CONVERTED) " + time + " UTC");
                        }
                        else if (propName.ToLower() == "accountexpires")
						{
							var accountExpiration = Convert.ToInt64(propertyValue.ToString());
							if (accountExpiration == 0 || accountExpiration == long.MaxValue)
							{
								Console.WriteLine(propName + ": (CONVERTED) Never");
							}
							else
							{
								Console.WriteLine(propName + ": (CONVERTED) " + DateTime.FromFileTimeUtc(accountExpiration).ToString("u") + " UTC");
							}
						}
						else if (propName.ToLower() == "samaccounttype")
						{
							var sat = (SamAccountType) Convert.ToInt32(propertyValue.ToString());
							Console.WriteLine(propName + ": " + propertyValue + " (" + sat.ToString() + ")");
						}
						else if (propName.ToLower() == "useraccountcontrol")
						{
							var uac = (UserAccountControl) Convert.ToInt32(propertyValue.ToString());
							Console.WriteLine(propName + ": " + propertyValue + " (" + uac.ToString() + ")");
						}
						else if (propName.ToLower() == "objectguid" || propName.ToLower() == "ms-ds-consistencyguid")
						{
							var guid = new Guid((byte[])propertyValue);
							Console.WriteLine(propName + ": " + guid.ToString());
						}
						else if (propName.ToLower() == "trusttype")
						{
							int trustType = Convert.ToUInt16(propertyValue.ToString());
							if (trustType == 1)
							{
								Console.WriteLine(propName + ": " + propertyValue + " (TRUST_TYPE_DOWNLEVEL)");
							}
						        else if (trustType == 2)
							{
								Console.WriteLine(propName + ": " + propertyValue + " (TRUST_TYPE_UPLEVEL)");
							}
						        else if (trustType == 3)
							{
								Console.WriteLine(propName + ": " + propertyValue + " (TRUST_TYPE_MIT)");
							}
						        else if (trustType == 4)
							{
								Console.WriteLine(propName + ": " + propertyValue + " (TRUST_TYPE_DCE)");
							}
						}
						else if (propName.ToLower() == "trustdirection")
						{
							int trustDirection = Convert.ToUInt16(propertyValue.ToString());
							if (trustDirection == 0)
							{
								Console.WriteLine(propName + ": " + propertyValue + " (TRUST_DIRECTION_DISABLED)");
							}
							else if (trustDirection == 1)
							{
								Console.WriteLine(propName + ": " + propertyValue + " (TRUST_DIRECTION_INBOUND)");
							}
							else if (trustDirection == 2)
							{
								Console.WriteLine(propName + ": " + propertyValue + " (TRUST_DIRECTION_OUTBOUND)");
							}
							else if (trustDirection == 3)
							{
								Console.WriteLine(propName + ": " + propertyValue + " (TRUST_DIRECTION_BIDIRECTIONAL)");
							}
						}
						else if (propName.ToLower() == "trustattributes")
						{
							var ta = (TrustAttributes) Convert.ToInt32(propertyValue.ToString());
							Console.WriteLine(propName + ": " + propertyValue + " (" + ta.ToString() + ")");
						}
						else if (propName.ToLower() == "msds-supportedencryptiontypes")
						{
							var set = (SupportedEncryptionTypes) Convert.ToInt32(propertyValue.ToString());
							Console.WriteLine(propName + ": " + propertyValue + " (" + set.ToString() + ")");
						}
						else if (propName.ToLower() == "mspki-enrollment-flag")
						{
							var pef = (PkiEnrollmentFlag) Convert.ToInt32(propertyValue.ToString());
							Console.WriteLine(propName + ": " + propertyValue + " (" + pef.ToString() + ")");
						}
						else if (propName.ToLower() == "mspki-certificate-name-flag")
						{
							var cnf = (CertificateNameFlag) Convert.ToUInt32(propertyValue.ToString());
							Console.WriteLine(propName + ": " + propertyValue + " (" + cnf.ToString() + ")");
						}
						else if (propName.ToLower() == "mspki-private-key-flag")
						{
							var pkf = (PrivateKeyFlag) Convert.ToInt32(propertyValue.ToString());
							Console.WriteLine(propName + ": " + propertyValue + " (" + pkf.ToString() + ")");
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
