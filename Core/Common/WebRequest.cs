using System;
using System.Net;

namespace Core.Common
{
    internal static class WebRequest
    {
        internal static WebClient Curl(string df = null, string purl = null, string proxyUser = null, string proxyPassword = null,
            string useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36")
        {
            try
            {
                ServicePointManager.SecurityProtocol = (SecurityProtocolType) 192 | (SecurityProtocolType) 768 | (SecurityProtocolType) 3072;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            var webClientObject = new WebClient();

            if (!string.IsNullOrEmpty(purl))
            {
                Console.WriteLine(purl);
                var proxy = new WebProxy {Address = new Uri(purl), Credentials = new NetworkCredential(proxyUser, proxyPassword)};
                if (string.IsNullOrEmpty(proxyUser))
                {
                    proxy.UseDefaultCredentials = true;
                }

                proxy.BypassProxyOnLocal = false;
                webClientObject.Proxy = proxy;
            }
            else
            {
                if (null != webClientObject.Proxy)
                    webClientObject.Proxy.Credentials = CredentialCache.DefaultCredentials;
            }

            if (!string.IsNullOrEmpty(df))
            {
                webClientObject.Headers.Add("Host", df);
            }

            webClientObject.Headers.Add("User-Agent", useragent);
            webClientObject.Headers.Add("Referer", "");

            return webClientObject;
        }
    }
}