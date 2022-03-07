using System;
using System.Data;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Net;
using System.Management;

namespace Core.Host
{
    public static class ServicePerms

    {
        private static void DumpFolderPerms(IEnumerable<string> folderList, DataSet dataSet, string path)
        {
            dataSet.Tables.Add("folders");
            dataSet.Tables["folders"].Columns.Add("Folder");
            dataSet.Tables["folders"].Columns.Add("Permissions");

            foreach (var value in folderList)
            {
                string cPermString = null;
                try
                {
                    var fileSecurity = new FileSecurity(value, AccessControlSections.Access);
                    var arc = fileSecurity.GetAccessRules(true, true, typeof(NTAccount));
                    foreach (FileSystemAccessRule rule in arc)
                    {
                        var permString = rule.IdentityReference + " " + rule.AccessControlType + " " + rule.FileSystemRights;

                        // is this case sensitive
                        if (permString.Contains("Users") & permString.Contains("Modify"))
                        {
                            permString = "<b><div style=\"color:red;\">**" + permString + "</div></b>";
                        }

                        if (permString.Contains("Users") & permString.Contains("FullControl"))
                        {
                            permString = "<b><div style=\"color:red;\">**" + permString + "</div></b>";
                        }

                        if (permString.Contains("Everyone") & permString.Contains("Modify"))
                        {
                            permString = "<b><div style=\"color:red;\">**" + permString + "</div></b>";
                        }

                        if (permString.Contains("Everyone") & permString.Contains("FullControl"))
                        {
                            permString = "<b><div style=\"color:red;\">**" + permString + "</div></b>";
                        }

                        cPermString = cPermString + permString + " <br>";
                    }
                }
                catch
                {
                }

                dataSet.Tables["folders"].Rows.Add(value, cPermString);
            }

            var hostName = Dns.GetHostName();
            var contents = ConvertDataTableToHtml(dataSet.Tables["services"]);
            var contentsFolders = ConvertDataTableToHtml2(dataSet.Tables["folders"]);
            try
            {
                File.WriteAllText(@"" + path + "\\Report-" + hostName + ".html", contents + contentsFolders);
                Console.WriteLine("[+] Written file to: " + path + "Report-" + hostName + ".html");
            }
            catch
            {
                Console.WriteLine("[-] ERROR file to: " + path + "Report-" + hostName + ".html");
            }
        }

        public static void DumpServices(string path)
        {
            Dns.GetHostName();
            var folderList = new List<string>();
            var ds = new DataSet();
            ds.Tables.Add("services");
            ds.Tables["services"].Columns.Add("Service Name");
            ds.Tables["services"].Columns.Add("Unquoted");
            ds.Tables["services"].Columns.Add("ImagePath");
            ds.Tables["services"].Columns.Add("Permissions");
            ds.Tables["services"].Columns.Add("Service Information");

            var query = new ObjectQuery("SELECT * FROM Win32_Service");
            var searcher = new ManagementObjectSearcher(query);
            foreach (var queryObj in searcher.Get())
            {
                var input = "";
                try
                {
                    if (queryObj["PathName"].ToString() == "")
                    {
                        continue;
                    }

                    input = queryObj["PathName"].ToString();
                }
                catch
                {
                }

                var match = Regex.Match(input, @"^(.+?).exe", RegexOptions.IgnoreCase);

                // Here we check the Match instance.
                if (match.Success)
                {
                    //Check for unquotes service paths
                    var servicePath = match.Groups[1].Value + ".exe";
                    string unquoted;
                    if (!servicePath.Contains("\"") && servicePath.Contains(" "))
                    {
                        unquoted = "Unquoted**";
                    }
                    else
                    {
                        unquoted = "False";
                    }

                    // Finally, we get the Group value and display it.
                    var key = match.Groups[1].Value + ".exe";
                    key = key.Replace("\"", "");
                    string permsString = null;
                    try
                    {
                        var fileSecurity = new FileSecurity(key, AccessControlSections.Access);
                        //file_info.Directory.Parent

                        var arc = fileSecurity.GetAccessRules(true, true, typeof(NTAccount));
                        foreach (FileSystemAccessRule rule in arc)
                        {
                            // find if users modify
                            // if it contains everyone or users with modify or fullControl then flag as bold or something.....
                            // or search through the html after.....
                            var currentPermsString = rule.IdentityReference + " " + rule.AccessControlType + " " + rule.FileSystemRights;

                            // is this case sensitive
                            if (currentPermsString.Contains("Users") & currentPermsString.Contains("Modify"))
                            {
                                currentPermsString = "<b><div style=\"color:red;\">**" + currentPermsString + "</div></b>";
                            }

                            if (currentPermsString.Contains("Users") & currentPermsString.Contains("FullControl"))
                            {
                                currentPermsString = "<b><div style=\"color:red;\">**" + currentPermsString + "</div></b>";
                            }

                            if (currentPermsString.Contains("Everyone") & currentPermsString.Contains("Modify"))
                            {
                                currentPermsString = "<b><div style=\"color:red;\">**" + currentPermsString + "</div></b>";
                            }

                            if (currentPermsString.Contains("Everyone") & currentPermsString.Contains("FullControl"))
                            {
                                currentPermsString = "<b><div style=\"color:red;\">**" + currentPermsString + "</div></b>";
                            }

                            permsString = permsString + currentPermsString + " <br>";
                        }
                    }
                    catch
                    {
                        permsString = "Path not found: " + key + "\n";
                    }

                    try
                    {
                        var file = new FileInfo(key);
                        var directory2 = file.Directory;

                        while (directory2 != null)
                        {
                            if (!folderList.Contains(directory2.FullName.ToLower()))
                            {
                                folderList.Add(directory2.FullName.ToLower());
                            }

                            directory2 = directory2.Parent;
                        }
                    }
                    catch
                    {
                    }

                    var serviceInformation = "";
                    
                    // Try and see if the service can be stopped or restarted
                    var svc = new ServiceController(queryObj["Name"].ToString());
                    try
                    {
                        serviceInformation = svc.Status.ToString();
                        var canStop = svc.CanPauseAndContinue;
                        var canStart = svc.CanStop;
                        var canShutdown = svc.CanShutdown;
                        serviceInformation = serviceInformation + "<br>CanPauseAndContinue:" + canStop + "<br>CanStart:" + canStart + "<br>CanShutdown:" + canShutdown;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Error" + ex);
                    }

                    ds.Tables["services"].Rows.Add(queryObj["DisplayName"] + " (" + queryObj["Name"] + ")", unquoted, queryObj["PathName"].ToString(), permsString,
                        serviceInformation);
                }
            }

            try
            {
                DumpFolderPerms(folderList, ds, path);
            }
            catch
            {
            }
        }

        private static string ConvertDataTableToHtml(DataTable targetTable)
        {
            if (targetTable == null)
            {
                throw new ArgumentNullException(nameof(targetTable));
            }

            var builder = new StringBuilder();
            builder.Append("<html>");
            builder.Append("<head>");
            builder.Append("<title>");
            builder.Append("Page-");
            builder.Append(Guid.NewGuid().ToString());
            builder.Append("</title>");
            builder.Append("</head>");
            builder.Append("<body>");
            builder.Append("<h1>Service Permissions - Search for ** to find any vulnerabilities........</h1>");
            builder.Append("<table border='1px' cellpadding='5' cellspacing='0' ");
            builder.Append("style='border: solid 1px Black; font-size: small;'>");
            builder.Append("<tr align='left' valign='top'>");
            foreach (DataColumn column in targetTable.Columns)
            {
                builder.Append("<td align='left' valign='top'>");
                builder.Append(column.ColumnName);
                builder.Append("</td>");
            }

            builder.Append("</tr>");
            foreach (DataRow row in targetTable.Rows)
            {
                builder.Append("<tr align='left' valign='top'>");
                foreach (DataColumn column2 in targetTable.Columns)
                {
                    builder.Append("<td align='left' valign='top'>");
                    builder.Append(row[column2.ColumnName]);
                    builder.Append("</td>");
                }

                builder.Append("</tr>");
            }

            builder.Append("</table>");
            builder.Append("</body>");
            builder.Append("</html>");
            return builder.ToString();
        }

        private static string ConvertDataTableToHtml2(DataTable targetTable)
        {
            if (targetTable == null)
            {
                throw new ArgumentNullException(nameof(targetTable));
            }

            var builder = new StringBuilder();
            builder.Append("<html>");
            builder.Append("<head>");
            builder.Append("<title>");
            builder.Append("Page-");
            builder.Append(Guid.NewGuid().ToString());
            builder.Append("</title>");
            builder.Append("</head>");
            builder.Append("<body>");
            builder.Append("<table border='1px' cellpadding='5' cellspacing='0' ");
            builder.Append("style='border: solid 1px Black; font-size: small;'>");
            builder.Append("<tr align='left' valign='top'>");
            foreach (DataColumn column in targetTable.Columns)
            {
                builder.Append("<td align='left' valign='top'>");
                builder.Append(column.ColumnName);
                builder.Append("</td>");
            }

            builder.Append("</tr>");
            foreach (DataRow row in targetTable.Rows)
            {
                builder.Append("<tr align='left' valign='top'>");
                foreach (DataColumn column2 in targetTable.Columns)
                {
                    builder.Append("<td align='left' valign='top'>");
                    builder.Append(row[column2.ColumnName]);
                    builder.Append("</td>");
                }

                builder.Append("</tr>");
            }

            builder.Append("</table>");
            builder.Append("</body>");
            builder.Append("</html>");
            return builder.ToString();
        }
    }
}