using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Collections;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Net.Sockets;

namespace Core.Arp
{
    public static class ArpScanner
    {
        private class MacState
        {
            public int counter;
            public readonly AutoResetEvent doneEvent = new(false);

            public Dictionary<string, string> Results { get; set; }
        }

        private class IpQueryState
        {
            public IpQueryState(MacState state)
            {
                CurrentState = state;
            }

            public MacState CurrentState { get; }

            public string Query { get; set; }
        }

        public static Dictionary<string, string> DoScan(string ipString)
        {
            return DoScan(ipString, 100);
        }


        private static Dictionary<string, string> DoScan(string ipString, ushort maxThreads)
        {
            ThreadPool.SetMaxThreads(maxThreads, maxThreads);
            var results = new Dictionary<string, string>();
            if (ipString.StartsWith("127.0.0.1") || ipString.StartsWith("169")) return results;
            var state = new MacState {Results = results};
            if (Pv4Tools.IsIpRangeFormat(ipString))
            {
                var ipRange = Pv4Tools.IpEnumerator[ipString];

                foreach (var unused in ipRange)
                {
                    state.counter++;
                }

                foreach (var ip in ipRange)
                {
                    var ipq = new IpQueryState(state) {Query = ip};
                    ThreadPool.QueueUserWorkItem(GetMacAddress, ipq);
                }

                state.doneEvent.WaitOne();
            }
            else
            {
                var ipq = new IpQueryState(state) {Query = ipString};
                GetMacAddress(ipq);
            }

            return results;
        }

        public static string GetHostByNetBiosAddress(string ipaddress)
        {
            try
            {
                return Dns.GetHostEntry(ipaddress).HostName;
            }
            catch
            {
                return "Unknown";
            }
        }

        private static void GetMacAddress(object state)
        {
            if (state is not IpQueryState queryState)
            {
                throw new ArgumentException("Null query state when getting MAC address");
            }

            try
            {
                if (!IPAddress.TryParse(queryState.Query, out var ipAddress))
                {
                    Console.WriteLine($"IP Address {queryState.Query} is invalid ");
                    return;
                }

                var uintAddress = BitConverter.ToUInt32(ipAddress.GetAddressBytes(), 0);
                var macAddress = new byte[6];
                var macAddressLen = macAddress.Length;
                var retValue = Kernel32Imports.SendARP(uintAddress, 0, macAddress, ref macAddressLen);
                if (retValue != 0)
                {
                    return;
                }

                var str = new string[macAddressLen];
                for (var i = 0; i < macAddressLen; i++)
                    str[i] = macAddress[i].ToString("x2");
                var mac = string.Join(":", str);

                if (queryState.Query != null)
                    queryState.CurrentState.Results.Add(queryState.Query, mac);
            }
            finally
            {
                if (Interlocked.Decrement(ref queryState.CurrentState.counter) == 0)
                    queryState.CurrentState.doneEvent.Set();
            }
        }

        private static class Kernel32Imports
        {
            [DllImport("iphlpapi.dll", ExactSpelling = true)]
            public static extern int SendARP(uint destIp, uint srcIp, byte[] pMacAddress, ref int phyAddressLen);

            [DllImport("ws2_32.dll", SetLastError = true)]
            internal static extern IntPtr getHostByAddress([In] ref uint address, [In] int len, [In] ProtocolFamily type);
        }

        private class Pv4Tools
        {
            private static readonly Regex IP_CIDR_REGEX =
                new(@"^(?<ip>(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(\/(?<cidr>(\d|[1-2]\d|3[0-2])))$");

            private static readonly Regex IP_RANGE_REGEX =
                new(
                    @"^(?<ip>(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?<from>([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])))(\-(?<to>([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])))$");

            public static Pv4Tools IpEnumerator => new();

            public IpRange this[string value] => new(value);

            public static bool IsIpRangeFormat(string ipRange)
            {
                return IP_CIDR_REGEX.Match(ipRange).Success || IP_RANGE_REGEX.Match(ipRange).Success;
            }

            private static Match IpCidrMatch(string ipCidr)
            {
                return IP_CIDR_REGEX.Match(ipCidr);
            }

            private static Match IpRangeMatch(string ipRange)
            {
                return IP_RANGE_REGEX.Match(ipRange);
            }

            public class IpRange : IEnumerable<string>
            {
                private readonly string _ipCidr;

                public IpRange(string ipCidr)
                {
                    _ipCidr = ipCidr;
                }

                public IEnumerator<string> GetEnumerator()
                {
                    return new IpRangeEnumerator(_ipCidr);
                }

                private IEnumerator GetEnumerator1()
                {
                    return GetEnumerator();
                }

                IEnumerator IEnumerable.GetEnumerator()
                {
                    return GetEnumerator1();
                }
            }

            private class IpRangeEnumerator : IEnumerator<string>
            {
                private readonly string _ipCidr;
                private uint _loAddress;
                private uint _hiAddress;
                private uint? _current;

                public IpRangeEnumerator(string ipCidr)
                {
                    _ipCidr = ipCidr;
                    var cidrMatch = IpCidrMatch(ipCidr);
                    var rangeMch = IpRangeMatch(ipCidr);
                    if (cidrMatch.Success)
                        ProcessCidrRange(cidrMatch);
                    else if (rangeMch.Success)
                        ProcessIpRange(rangeMch);

                    if (!cidrMatch.Success && !rangeMch.Success)
                        throw new Exception("IP Range must either be in IP/CIDR or IP to-from format");
                }

                private void ProcessIpRange(Match rangeMch)
                {
                    var startIp = IPAddress.Parse(rangeMch.Groups["ip"].Value);
                    var fromRange = ushort.Parse(rangeMch.Groups["from"].Value);
                    var toRange = ushort.Parse(rangeMch.Groups["to"].Value);

                    if (fromRange > toRange)
                        throw new Exception("IP Range the from must be less than the to");
                    if (toRange > 254)
                        throw new Exception("IP Range the to must be less than 254");
                    var arrIpBytes = startIp.GetAddressBytes();
                    Array.Reverse(arrIpBytes);
                    var ipAsUint = BitConverter.ToUInt32(arrIpBytes, 0);
                    _loAddress = ipAsUint;
                    _hiAddress = ipAsUint + (uint) (toRange - fromRange) + 1;
                }

                private void ProcessCidrRange(Match cidrMatch)
                {
                    var ip = IPAddress.Parse(cidrMatch.Groups["ip"].Value);
                    var cidr = int.Parse(cidrMatch.Groups["cidr"].Value);

                    switch (cidr)
                    {
                        case <= 0:
                            throw new Exception("CIDR can't be negative");
                        case > 32:
                            throw new Exception("CIDR can't be more 32");
                        case 32:
                        {
                            var arrIpBytes = ip.GetAddressBytes();
                            Array.Reverse(arrIpBytes);
                            var ipAsUint = BitConverter.ToUInt32(arrIpBytes, 0);
                            _loAddress = ipAsUint;
                            _hiAddress = ipAsUint;
                            break;
                        }
                        default:
                        {
                            var arrIpBytes = ip.GetAddressBytes();
                            Array.Reverse(arrIpBytes);
                            var ipAsUint = BitConverter.ToUInt32(arrIpBytes, 0);
                            var uMask = uint.MaxValue >> cidr;
                            var lMask = uMask ^ uint.MaxValue;
                            _loAddress = ipAsUint & lMask;
                            _hiAddress = ipAsUint | uMask;
                            break;
                        }
                    }
                }

                private static uint HostToNetwork(uint host)
                {
                    var hostBytes = BitConverter.GetBytes(host);
                    Array.Reverse(hostBytes);
                    return BitConverter.ToUInt32(hostBytes, 0);
                }

                public string Current
                {
                    get
                    {
                        if (string.IsNullOrEmpty(_ipCidr) || !_current.HasValue)
                            throw new InvalidOperationException();

                        return UIntToIpString(HostToNetwork(_current.Value));
                    }
                }

                public bool MoveNext()
                {
                    if (!_current.HasValue)
                    {
                        _current = _loAddress;
                        if (_current == _hiAddress) //handles if /32 used
                            return true;
                    }
                    else
                        _current++;

                    if ((0xFF & _current) == 0 || (0xFF & _current) == 255)
                        _current++;

                    return _current < _hiAddress;
                }

                public void Reset()
                {
                    _current = _loAddress;
                    if ((0xFF & _current) == 0 || (0xFF & _current) == 255)
                        _current++;
                }

                private object Current1 => Current;

                object IEnumerator.Current => Current1;

                public void Dispose()
                {
                }
            }

            private static string UIntToIpString(uint address)
            {
                var num1 = 15;
                var chPtr = new char[15];
                var num2 = (int) (address >> 24 & (long) byte.MaxValue);
                do
                {
                    chPtr[--num1] = (char) (48 + num2 % 10);
                    num2 /= 10;
                } while (num2 > 0);

                int num3;
                chPtr[num3 = num1 - 1] = '.';
                var num4 = (int) (address >> 16 & (long) byte.MaxValue);
                do
                {
                    chPtr[--num3] = (char) (48 + num4 % 10);
                    num4 /= 10;
                } while (num4 > 0);

                int num5;
                chPtr[num5 = num3 - 1] = '.';
                var num6 = (int) (address >> 8 & (long) byte.MaxValue);
                do
                {
                    chPtr[--num5] = (char) (48 + num6 % 10);
                    num6 /= 10;
                } while (num6 > 0);

                int startIndex;
                chPtr[startIndex = num5 - 1] = '.';
                var num7 = (int) (address & (long) byte.MaxValue);
                do
                {
                    chPtr[--startIndex] = (char) (48 + num7 % 10);
                    num7 /= 10;
                } while (num7 > 0);

                return new string(chPtr, startIndex, 15 - startIndex);
            }
        }
    }
}