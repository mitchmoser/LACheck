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
                Console.WriteLine("[SMB] Admin Success: {0}", host);
                if (arguments.edr)
                {
                    Enums.EDR.EDRCheckSMB(host);
                }
                if (arguments.logons)
                {
                    Enums.NetLogons.GetLoggedOnUsers(host, arguments.verbose);
                    Enums.RDP.GetRDPUsers(host, arguments.verbose);
                }
                if (arguments.services)
                {
                    Enums.Services.GetServicesSMB(host, arguments.verbose);
                }
                if (arguments.registry)
                {
                    Enums.Registry.RegistryCheck(host, arguments.verbose);
                }
            }
            catch (Exception ex)
            {
                if (arguments.verbose)
                {
                    Console.WriteLine("[!] SMB on {0} - {1}", host, ex.Message.Trim());
                }
            }
        }
    }
}
