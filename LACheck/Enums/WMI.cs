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
                Console.WriteLine("[RPC] Admin Success: {0}", host);
                if (arguments.edr)
                {
                    Enums.EDR.EDRCheckWMI(host, ns, arguments.verbose);
                }
                if (arguments.logons)
                {
                    Enums.LogonSessions.GetSessionsWMI(host, ns, arguments.verbose);
                }
                if (arguments.services)
                {
                    Enums.Services.GetServicesWMI(host, ns, arguments.verbose);
                }

            }
            catch (Exception ex)
            {
                if (arguments.verbose)
                {
                    Console.WriteLine("[!] RPC on {0} - {1}", host, ex.Message.Trim());
                }
            }
        }
    }
}
