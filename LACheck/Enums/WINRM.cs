using System;
using System.Linq;
using System.Xml.Linq;
using WSManAutomation; //Add Reference -> windows\system32\wsmauto.dll (or COM: Microsoft WSMan Automation V 1.0 Library)


namespace LACheck.Enums
{
    class WINRM
    {
        public static void Check(string host, string ns, string wql, Utilities.Arguments arguments)
        {
            try
            {
                //https://bohops.com/2020/05/12/ws-management-com-another-approach-for-winrm-lateral-movement/
                //https://github.com/bohops/WSMan-WinRM/blob/master/SharpWSManWinRM.cs
                IWSManEx wsman = new WSMan();
                IWSManConnectionOptions options = (IWSManConnectionOptions)wsman.CreateConnectionOptions();
                IWSManSession session = (IWSManSession)wsman.CreateSession(host, 0, options);

                //https://docs.microsoft.com/en-us/windows/win32/winrm/querying-for-specific-instances-of-a-resource
                //https://stackoverflow.com/questions/29645896/how-to-retrieve-cim-instances-from-a-linux-host-using-winrm
                string resource = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/*";
                string dialect = "http://schemas.microsoft.com/wbem/wsman/1/WQL";
                IWSManEnumerator response = session.Enumerate(resource, wql, dialect);
                // Enumerate returned CIM instances.
                string results = "";
                while (!response.AtEndOfStream)
                {
                    string item = response.ReadItem();
                    XDocument doc = XDocument.Parse(item);
                    var resultSet = from e in doc.Elements() select e;

                    foreach (var element in resultSet)
                    {
                        results += element;
                    }
                }
                if (results != "")
                {
                    Console.WriteLine($"[WinRM] Admin Success: {host} as {arguments.userprincipalname}");
                    Utilities.BloodHound.LACheckSessions.AdminSuccess.Add(host);
                    if (arguments.edr)
                    {
                        Enums.EDR.EDRCheckWinRM(host, arguments);
                    }
                    if (arguments.logons)
                    {
                        Enums.LogonSessions.GetSessionsWinRM(host, arguments);
                    }
                    if (arguments.registry)
                    {
                        //unfinished
                        //Enums.Registry.GetCurrentUsersWinRM(host, arguments.verbose);
                    }
                    if (arguments.services)
                    {
                        Enums.Services.GetServicesWinRM(host, arguments);
                    }
                }
                if (arguments.verbose && results == "")
                {
                    Console.WriteLine($"[!] {host} - no WinRM response for query");
                }
            }
            catch (Exception ex)
            {
                if (arguments.verbose)
                {
                    Console.WriteLine($"[!] {host} WinRM Error: {ex.Message.Trim()}");
                }
            }

        }
    }
}