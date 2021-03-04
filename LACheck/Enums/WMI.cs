using System;
using System.Management;

namespace LACheck.Enums
{
    class WMI
    {
        public static void Check(string host, string ns, string wql, bool logons, bool services, bool verbose)
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
                Console.WriteLine("[RPC] Admin Success: {0}", host);
                if (logons)
                {
                    Enums.LogonSessions.GetSessions(host, ns, verbose);
                }
                if (services)
                {
                    Enums.Services.GetServicesWMI(host, ns, verbose);
                }

            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] RPC on {0} - {1}", host, ex.Message.Trim());
                }
            }
        }
    }
}
