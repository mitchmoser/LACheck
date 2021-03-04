using System;
using System.IO;
using System.ServiceProcess;

namespace LACheck.Enums
{
    class SMB
    {
        public static void Check(string host, bool logons, bool registry, bool services, bool verbose)
        {
            try
            {
                string share = "\\\\" + host + "\\C$";
                System.Security.AccessControl.DirectorySecurity ds = Directory.GetAccessControl(share);
                Console.WriteLine("[SMB] Admin Success: {0}", host);
                if (logons)
                {
                    Enums.NetLogons.GetLoggedOnUsers(host, verbose);
                    Enums.RDP.GetRDPUsers(host, verbose);
                }
                if (services)
                {
                    Enums.Services.GetServicesSMB(host, verbose);
                }
                if (registry)
                {
                    Enums.Registry.RegistryCheck(host, verbose);
                }
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] SMB on {0} - {1}", host, ex.Message.Trim());
                }
            }
        }
    }
}
