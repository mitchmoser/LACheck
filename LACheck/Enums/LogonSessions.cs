using System;
using System.Collections.Generic;
using System.Management;
using System.Text.RegularExpressions;
using System.Linq;
using System.Xml.Linq;
using WSManAutomation; //Add Reference -> windows\system32\wsmauto.dll (or COM: Microsoft WSMan Automation V 1.0 Library)


namespace LACheck.Enums
{
    public class Session
    {
        public string authenticationpackage;
        public string domain;
        public string logonid;
        public string logontype;
        public string status;
        public DateTime starttime;
        // get set to search through list of sessions by username
        public string username { get; set; }
        public string userprincipalname { get; set; }
    }
    class LogonSessions
    {
        // Exclude services running as local accounts
        static string[] exclusions = { "ANONYMOUS LOGON", "DWM-1", "DWM-2", "IUSR", "LOCAL SERVICE", "NETWORK SERVICE", "SYSTEM", "UMFD-0", "UMFD-1", "UMFD-2", "UMFD-3", "UMFD-4" };
        public static void GetSessionsWinRM(string host, Utilities.Arguments arguments)
        {
            List<Session> sessions = new List<Session>();
            sessions = LoggedOnUserWinRM(sessions, host, arguments);
            sessions = LogonSessionWinRM(sessions, host, arguments);

            //get distinct list of users from sessions
            List<string> userprincipalnames = sessions.Select(x => x.userprincipalname).Distinct().ToList();
            Utilities.SessionInfo.ComputerSessions computer = new Utilities.SessionInfo.ComputerSessions();
            computer.hostname = host;
            foreach (string upns in userprincipalnames)
            {
                // winrm & wmi session enum includes the user that ran the query as a 'session'
                // remove this false positive
                if (upns != arguments.user)
                {
                    //retrieve the most recent session for each distinct user
                    Session sestime = sessions.Where(x => x.userprincipalname == upns).OrderByDescending(x => x.starttime).First();

                    Utilities.SessionInfo.UserSession storedSession = new Utilities.SessionInfo.UserSession();
                    storedSession.domain = sestime.domain;
                    storedSession.username = sestime.username;
                    computer.sessions.Add(storedSession);

                    Console.WriteLine($"[session] {host} - {sestime.domain}\\{sestime.username} {sestime.starttime} ({arguments.user})");
                }
            }
            Utilities.SessionInfo.AllComputerSessions.computers.Add(computer);
        }
        public static List<Session> LoggedOnUserWinRM(List<Session> sessions, string host, Utilities.Arguments arguments)
        {
            try
            {
                //https://bohops.com/2020/05/12/ws-management-com-another-approach-for-winrm-lateral-movement/
                //https://github.com/bohops/WSMan-WinRM/blob/master/SharpWSManWinRM.cs
                IWSManEx wsman = new WSMan();
                IWSManConnectionOptions options = (IWSManConnectionOptions)wsman.CreateConnectionOptions();
                IWSManSession winrm = (IWSManSession)wsman.CreateSession(host, 0, options);

                //https://docs.microsoft.com/en-us/windows/win32/winrm/querying-for-specific-instances-of-a-resource
                //https://stackoverflow.com/questions/29645896/how-to-retrieve-cim-instances-from-a-linux-host-using-winrm
                //https://docs.microsoft.com/en-us/windows/win32/wmisdk/wql-operators
                //https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-loggedonuser
                string resource = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/*";
                string wql = "SELECT * FROM Win32_LoggedOnUser";
                string dialect = "http://schemas.microsoft.com/wbem/wsman/1/WQL";
                IWSManEnumerator response = winrm.Enumerate(resource, wql, dialect);
                // Enumerate returned CIM instances.

                while (!response.AtEndOfStream)
                {
                    string item = response.ReadItem();
                    XDocument doc = XDocument.Parse(item);
                    XNamespace nsw = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd";
                    IEnumerable<XElement> wElements = doc.Descendants(nsw + "SelectorSet");

                    Session temp = new Session();

                    foreach (XElement element in wElements)
                    {
                        var selectors = element.Descendants(nsw + "Selector");
                        foreach (XElement selector in selectors)
                        {
                            IEnumerable<XAttribute> attList = selector.Attributes();
                            foreach (XAttribute att in attList)
                            {
                                switch (att.Value)
                                {
                                    case "Domain":
                                        temp.domain = selector.Value;
                                        //resolve netbios name to fqdn if present
                                        if (Utilities.BloodHound.NetBiosDomain.ContainsKey(temp.domain.ToUpper()))
                                            temp.domain = Utilities.BloodHound.NetBiosDomain[temp.domain.ToUpper()];
                                        break;
                                    case "Name":
                                        temp.username = selector.Value;
                                        break;
                                    case "LogonId":
                                        temp.logonid = selector.Value;
                                        break;
                                }
                                temp.userprincipalname = $"{temp.username}@{temp.domain}";
                            }
                        }
                        //skip SYSTEM and LOCAL SERVICE
                        if (exclusions.Contains(temp.username.ToString()))
                        {
                            continue; // Skip to the next session
                        }
                        sessions.Add(temp);
                    }
                }
            }
            catch (Exception ex)
            {
                if (arguments.verbose)
                {
                    Console.WriteLine($"[!] {host} - Unable to query services over WinRM: {ex.Message}");
                }
            }
            return sessions;
        }
        public static List<Session> LogonSessionWinRM(List<Session> sessions, string host, Utilities.Arguments arguments)
        {
            foreach (Session session in sessions)
            {
                //skip SYSTEM sessions
                if (exclusions.Contains(session.username))
                {
                    continue; // Skip to the next session
                }
                try
                {
                    //https://bohops.com/2020/05/12/ws-management-com-another-approach-for-winrm-lateral-movement/
                    //https://github.com/bohops/WSMan-WinRM/blob/master/SharpWSManWinRM.cs
                    IWSManEx wsman = new WSMan();
                    IWSManConnectionOptions options = (IWSManConnectionOptions)wsman.CreateConnectionOptions();
                    IWSManSession winrm = (IWSManSession)wsman.CreateSession(host, 0, options);

                    //https://docs.microsoft.com/en-us/windows/win32/winrm/querying-for-specific-instances-of-a-resource
                    //https://stackoverflow.com/questions/29645896/how-to-retrieve-cim-instances-from-a-linux-host-using-winrm
                    //https://docs.microsoft.com/en-us/windows/win32/wmisdk/wql-operators
                    //https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logonsession
                    string resource = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/*";
                    string wql = String.Format("SELECT LogonId,LogonType,StartTime FROM Win32_LogonSession WHERE LogonId={0}", session.logonid);
                    string dialect = "http://schemas.microsoft.com/wbem/wsman/1/WQL";
                    IWSManEnumerator response = winrm.Enumerate(resource, wql, dialect);
                    // Enumerate returned CIM instances.
                    while (!response.AtEndOfStream)
                    {
                        string item = response.ReadItem();
                        XDocument doc = XDocument.Parse(item);

                        string logonId = doc.Descendants("LogonId").First().Value;
                        session.logonid = logonId;

                        string logonType = doc.Descendants("LogonType").First().Value;
                        session.logontype = logonType;

                        string startTime = doc.Descendants("Datetime").First().Value;
                        DateTime sessionstart = DateTime.Parse(startTime);
                        session.starttime = sessionstart;
                    }
                }
                catch (Exception ex)
                {
                    if (arguments.verbose)
                    {
                        Console.WriteLine($"[!] {host} - Unable to query sessions over WinRM: {ex.Message}");
                    }
                }
            }
            return sessions;
        }
        public static void GetSessionsWMI(string host, string ns, Utilities.Arguments arguments)
        {
            

            List<Session> sessions = new List<Session>();
            sessions = LoggedOnUserWMI(sessions, host, ns, arguments);
            sessions = LogonSessionWMI(sessions, host, ns, arguments);

            //get distinct list of users from sessions
            List<string> userprincipalnames = sessions.Select(x => x.userprincipalname).Distinct().ToList();
            Utilities.SessionInfo.ComputerSessions computer = new Utilities.SessionInfo.ComputerSessions();
            computer.hostname = host;
            foreach (string upn in userprincipalnames)
            {
                // if /user argument was not specified 
                // or /user argument does not match current enumerated session
                if (upn != arguments.user)
                {
                    //retrieve the most recent session for each distinct user
                    Session sestime = sessions.Where(x => x.userprincipalname == upn).OrderByDescending(x => x.starttime).First();

                    Utilities.SessionInfo.UserSession storedSession = new Utilities.SessionInfo.UserSession();
                    
                    storedSession.domain = sestime.domain;
                    storedSession.username = sestime.username;
                    computer.sessions.Add(storedSession);

                    Console.WriteLine($"[session] {host} - {sestime.domain}\\{sestime.username} {sestime.starttime} ({arguments.user})");
                }
            }
            Utilities.SessionInfo.AllComputerSessions.computers.Add(computer);
        }
        public static List<Session> LoggedOnUserWMI(List<Session> sessions, string host, string ns, Utilities.Arguments arguments)
        {
            ManagementScope scope = new ManagementScope(string.Format(@"\\{0}\{1}", host, ns));

            //https://docs.microsoft.com/en-us/windows/win32/wmisdk/wql-operators
            //https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-loggedonuser
            SelectQuery query = new SelectQuery("SELECT * FROM Win32_LoggedOnUser");

            //pattern to match for Antecedent & Dependent
            //example Antecedent: \\.\root\cimv2:Win32_Account.Domain="contoso",Name="bob"
            //example Dependent:  \\.\root\cimv2:Win32_LogonSession.LogonId="37324052"
            string pattern = "\"(.*?)\"";
            Regex regex = new Regex(pattern);

            try
            {
                scope.Connect();
                //https://stackoverflow.com/questions/842533/in-c-sharp-how-do-i-query-the-list-of-running-services-on-a-windows-server
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query))
                {
                    ManagementObjectCollection users = searcher.Get();
                    foreach (ManagementObject user in users)
                    {
                        Session temp = new Session();
                        temp.logonid = regex.Matches(user["Dependent"].ToString())[0].ToString().Replace("\"", "");
                        temp.username = regex.Matches(user["Antecedent"].ToString())[1].ToString().Replace("\"", "");
                        temp.domain = regex.Matches(user["Antecedent"].ToString())[0].ToString().Replace("\"", "");
                        //resolve netbios name to fqdn if present
                        if (Utilities.BloodHound.NetBiosDomain.ContainsKey(temp.domain.ToUpper()))
                            temp.domain = Utilities.BloodHound.NetBiosDomain[temp.domain.ToUpper()];
                        temp.userprincipalname = $"{temp.username}@{temp.domain}";
                        //skip SYSTEM and LOCAL SERVICE
                        if (exclusions.Contains(temp.username.ToString()))
                        {
                            continue; // Skip to the next session
                        }
                        sessions.Add(temp);
                    }
                }
            }
            catch (Exception ex)
            {
                if (arguments.verbose)
                {
                    Console.WriteLine($"[!] {host} - Unable to query services over WMI: {ex.Message}");
                }
            }
            return sessions;
        }
        public static List<Session> LogonSessionWMI(List<Session> sessions, string host, string ns, Utilities.Arguments arguments)
        {
            foreach (Session session in sessions)
            {
                //skip SYSTEM sessions
                if (exclusions.Contains(session.username))
                {
                    continue; // Skip to the next session
                }
                ManagementScope scope = new ManagementScope(string.Format(@"\\{0}\{1}", host, ns));

                //https://docs.microsoft.com/en-us/windows/win32/wmisdk/wql-operators
                //https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logonsession
                SelectQuery query = new SelectQuery(String.Format("SELECT LogonId,LogonType,StartTime FROM Win32_LogonSession WHERE LogonId={0}", session.logonid));

                try
                {
                    scope.Connect();
                    //https://stackoverflow.com/questions/842533/in-c-sharp-how-do-i-query-the-list-of-running-services-on-a-windows-server
                    using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query))
                    {
                        ManagementObjectCollection results = searcher.Get();
                        foreach (ManagementObject result in results)
                        {
                            if (!String.IsNullOrEmpty(result["LogonId"].ToString()))
                            {
                                session.logonid = result["LogonId"].ToString();
                            }
                            if (!String.IsNullOrEmpty(result["LogonType"].ToString()))
                            {
                                session.logontype = result["LogonType"].ToString();
                            }
                            if (!String.IsNullOrEmpty(result["StartTime"].ToString()))
                            {
                                DateTime sessionstart = ManagementDateTimeConverter.ToDateTime(result["StartTime"].ToString());
                                session.starttime = sessionstart;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    if (arguments.verbose)
                    {
                        Console.WriteLine($"[!] {host} - Unable to query services over WMI: {ex.Message}");
                    }
                }
            }
            return sessions;
        }
    }
}
