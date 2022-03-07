using System.Text.RegularExpressions;
using System.Threading;

namespace Core.Common
{
    internal static class Timer
    {
        internal static void Turtle(string[] args)
        {
            var beacon = args[1];
            var beaconTime = CheckTime(beacon);
            Thread.Sleep(beaconTime);
        }

        public static int CheckTime(string beacon)
        {
            int beaconTime;
            if (beacon.ToLower().Contains("s"))
            {
                beacon = Regex.Replace(beacon, "s", "", RegexOptions.IgnoreCase);
                if (!int.TryParse(beacon, out beaconTime))
                {
                    beaconTime = 5;
                }
            }
            else if (beacon.ToLower().Contains("m"))
            {
                beacon = Regex.Replace(beacon, "m", "", RegexOptions.IgnoreCase);
                if (!int.TryParse(beacon, out beaconTime))
                {
                    beaconTime = 5;
                }
                beaconTime *= 60;
            }
            else if (beacon.ToLower().Contains("h"))
            {
                beacon = Regex.Replace(beacon, "h", "", RegexOptions.IgnoreCase);
                if (!int.TryParse(beacon, out beaconTime))
                {
                    beaconTime = 5;
                }
                beaconTime *= 60;
                beaconTime *= 60;
            }
            else if (!int.TryParse(beacon, out beaconTime))
            {
                beaconTime = 5;
            }
            return beaconTime * 1000;
        }
    }
}
