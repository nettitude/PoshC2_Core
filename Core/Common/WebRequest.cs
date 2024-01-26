using System;
using System.Net;

namespace Core.Common
{
    internal static class WebRequest
    {
        internal static WebClient Curl(string df = null, string purl = null, string proxyUser = null, string proxyPassword = null, string[] headers = null)
        {
            try
            {
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)192 | (SecurityProtocolType)768 | (SecurityProtocolType)3072;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            var webClientObject = new WebClient();

            if (!string.IsNullOrWhiteSpace(purl))
            {
                Console.WriteLine(purl);
                var proxy = new WebProxy { Address = new Uri(purl), Credentials = new NetworkCredential(proxyUser, proxyPassword) };
                if (string.IsNullOrWhiteSpace(proxyUser))
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

            if (!string.IsNullOrWhiteSpace(df))
            {
                webClientObject.Headers.Add("Host", df);
            }

            webClientObject.Headers.Add("Referer", "");

            if (headers != null)
            {
                foreach (var header in headers)
                {
                    if (!header.Contains(":"))
                    {
                        Console.WriteLine($"Invalid header format: {header}, expected key:value, skipping...");
                        continue;
                    }

                    if (header.Split(':')[0].ToLower() == "cookie")
                    {
                        Console.WriteLine($"{HttpRequestHeader.Cookie}: {header.Split(':')[1]}");
                        webClientObject.Headers.Add(HttpRequestHeader.Cookie, header.Split(':')[1]);
                    }
                    else
                    {
                        Console.WriteLine($"{header.Split(':')[0]}: {header.Split(':')[1]}");
                        webClientObject.Headers.Add(header.Split(':')[0], header.Split(':')[1]);
                    }
                   
                }
            }
            
            if (webClientObject.Headers.Get("User-Agent") == null)
            {
                webClientObject.Headers.Add("User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.69");
            }

            return webClientObject;
        }
    }
}