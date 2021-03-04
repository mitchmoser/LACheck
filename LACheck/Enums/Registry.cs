using System;
using Microsoft.Win32;
using System.ServiceProcess;

namespace LACheck.Enums
{
    class Registry
    {
        public static void RegistryCheck(string host, bool verbose)
        {
            //check status of Remote Registry service
            bool reconfig = Enums.Services.RemoteRegistryStatus(host, verbose);
            //if changes are needed to start Remote Registry
            if (reconfig)
            {
                //1. record initial state
                ServiceController remoteRegistry = new ServiceController("Remote Registry", host);
                int startType = Enums.Services.GetStartType(remoteRegistry, host, verbose);
                //2. make changes
                // been getting "Access is Denied" on this one unless run under Administrator context
                // may need to create a service to start Remote Registry as SYSTEM
                if (verbose)
                {
                    Console.WriteLine("[!] {0} - setting Remote Registry start mode to Automatic", host);
                }
                Enums.Services.ChangeStartMode(remoteRegistry, ServiceStartMode.Automatic, host);
                if (verbose)
                {
                    Console.WriteLine("[!] {0} - starting Remote Registry", host);
                }
                Enums.Services.StartRemoteRegistry(remoteRegistry, host, verbose);
                //3. perform checks
                Enums.Registry.GetCurrentUser(host, verbose);
                //4. restore changes
                //stop Remote Registry
                Enums.Services.StopRemoteRegistry(remoteRegistry, host, verbose);
                ServiceStartMode svcStartMode;
                //https://docs.microsoft.com/en-us/dotnet/api/system.serviceprocess.servicestartmode
                switch (startType)
                {
                    case 2:
                        svcStartMode = ServiceStartMode.Automatic;
                        break;
                    case 3:
                        svcStartMode = ServiceStartMode.Manual;
                        break;
                    case 4:
                        svcStartMode = ServiceStartMode.Disabled;
                        break;
                    default:
                        svcStartMode = ServiceStartMode.Automatic;
                        break;
                }
                //revert Remote Registry start mode
                Enums.Services.ChangeStartMode(remoteRegistry, svcStartMode, host);
            }
            else
            {
                //perform checks w/o reconfiguring
                Enums.Registry.GetCurrentUser(host, verbose);
            }
        }
        public static void GetCurrentUser(string host, bool verbose)
        {
            try
            {
                /* https://docs.microsoft.com/en-us/dotnet/api/microsoft.win32.registryhive
                 * iterate through SIDs in "\\Computer\HKEY_USERS\" hive
                 * attempt to access "Volatile Environment" for each SID
                 * get values from USERDOMAIN and USERNAME keys
                */
                RegistryKey baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.Users, host);
                string[] sids = baseKey.GetSubKeyNames();
                foreach (string sid in sids)
                {
                    string target = sid + "\\Volatile Environment";
                    try
                    {
                        RegistryKey key = baseKey.OpenSubKey(target);
                        string domain = key.GetValue("USERDOMAIN").ToString();
                        string username = key.GetValue("USERNAME").ToString();
                        Console.WriteLine("[registry] {0} - {1}\\{2}", host, domain, username);
                    }
                    catch
                    {
                        // if the SID doesn't have "Volatile Environment" no biggie, onto the next
                        continue;
                    }
                }
                baseKey.Close();

            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] {0} - Registry error: {1}", host, ex.Message.Trim());
                }
            }

        }
    }
}
