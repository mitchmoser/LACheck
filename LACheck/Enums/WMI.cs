using System;
using System.Management;


namespace LACheck.Enums
{
    class WMI
    {
        public static void Check(string host, string ns, string wql, Utilities.Arguments arguments)
        {
            try
            {
                ManagementScope scope = new ManagementScope(string.Format(@"\\{0}\{1}", host, ns));
                SelectQuery query = new SelectQuery(wql);
                scope.Connect();
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query))
                {
                    ManagementObjectCollection test = searcher.Get();
                }
                Console.WriteLine($"[RPC] Admin Success: {host} as {arguments.user}");
                Utilities.BloodHound.LACheckSessions.AdminSuccess.Add(host);
                if (arguments.edr)
                {
                    Enums.EDR.EDRCheckWMI(host, ns, arguments);
                }
                if (arguments.logons)
                {
                    Enums.LogonSessions.GetSessionsWMI(host, ns, arguments);
                }
                if (arguments.registry)
                {
                    Enums.Registry.GetCurrentUsersWMI(host, ns, arguments);
                }
                if (arguments.services)
                {
                    Enums.Services.GetServicesWMI(host, ns, arguments);
                }

            }
            catch (Exception ex)
            {
                if (arguments.verbose)
                {
                    Console.WriteLine($"[!] {host} - RPC Error: {ex.Message.Trim()}");
                }
            }
        }
    }
}
