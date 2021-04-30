using System;
using System.IO;


namespace LACheck.Enums
{
    class SMB
    {
        public static void Check(string host, Utilities.Arguments arguments)
        {
            try
            {
                string share = "\\\\" + host + "\\C$";
                System.Security.AccessControl.DirectorySecurity ds = Directory.GetAccessControl(share);
                Console.WriteLine($"[SMB] Admin Success: {host} as {arguments.user}");
                Utilities.BloodHound.LACheckSessions.AdminSuccess.Add(host);
                if (arguments.edr)
                {
                    Enums.EDR.EDRCheckSMB(host, arguments);
                }
                if (arguments.logons)
                {
                    Enums.NetLogons.GetLoggedOnUsers(host, arguments);
                    Enums.RDP.GetRDPUsers(host, arguments);
                }
                if (arguments.services)
                {
                    Enums.Services.GetServicesSMB(host, arguments);
                }
                if (arguments.registry)
                {
                    Enums.Registry.RegistryCheck(host, arguments);
                }
            }
            catch (Exception ex)
            {
                if (arguments.verbose)
                {
                    Console.WriteLine($"[!] {host} - SMB Error: {ex.Message.Trim()}");
                }
            }
        }
    }
}
