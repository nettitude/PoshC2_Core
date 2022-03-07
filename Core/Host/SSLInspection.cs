using System;
using System.Net;

namespace Core.Host
{
    internal static class SslInspection
    {
        public static void Check(string[] args)
        {
            var url = "";
            var proxyUrl = "";
            var proxyUser = "";
            var proxyPass = "";
            var userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko";

            try
            {
                url = args[1];

                if (args.Length >= 2)
                {
                    proxyUrl = args[2];
                }

                if (args.Length >= 3)
                {
                    proxyUser = args[3];
                }

                if (args.Length >= 4)
                {
                    proxyPass = args[4];
                }

                if (args.Length >= 5)
                {
                    userAgent = args[5];
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }


            ServicePointManager.SecurityProtocol = (SecurityProtocolType) 3072;

            Console.WriteLine("[+] Starting SSLChecker\n");
            var req = (HttpWebRequest) WebRequest.Create(url);
            req.UserAgent = userAgent;

            if (!string.IsNullOrEmpty(proxyUrl))
            {
                var proxy = new WebProxy {Address = new Uri(proxyUrl), Credentials = new NetworkCredential(proxyUser, proxyPass)};

                if (string.IsNullOrEmpty(proxyUser))
                {
                    proxy.UseDefaultCredentials = true;
                }

                proxy.BypassProxyOnLocal = false;
                req.Proxy = proxy;
            }
            else
            {
                req.Proxy.Credentials = CredentialCache.DefaultCredentials;
            }

            req.Timeout = 10000;
            try
            {
                req.GetResponse();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in SSLInspection.Check(): {e.Message}\n");
            }

            if (req.ServicePoint.Certificate != null)
            {
                var expiration = req.ServicePoint.Certificate.GetExpirationDateString();
                var certName = req.ServicePoint.Certificate.Subject;
                var certEffectiveDate = req.ServicePoint.Certificate.GetEffectiveDateString();
                var certIssuer = req.ServicePoint.Certificate.Issuer;


                Console.WriteLine("Cert for site {0}. Check details:\n", url);
                Console.WriteLine("Cert name: {0}", certName);
                Console.WriteLine("Cert effective date: {0}", certEffectiveDate);
                Console.WriteLine("Cert Expiry: {0}", expiration);
                Console.WriteLine("Cert issuer: {0}", certIssuer);

                req.ServicePoint.Certificate.Reset();
            }
            else
            {
                Console.WriteLine("[-] Request certificate is null");
            }
        }
    }
}