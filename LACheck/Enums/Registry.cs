using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Management;
using System.ServiceProcess;
using System.Xml.Linq;
using WSManAutomation; //Add Reference -> windows\system32\wsmauto.dll (or COM: Microsoft WSMan Automation V 1.0 Library)


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
        public static void GetCurrentUsersWinRM(string host, bool verbose)
        {
            /* https://docs.microsoft.com/en-us/dotnet/api/microsoft.win32.registryhive
             * get SIDs from Win32_UserProfile WMI class
             * iterate through SIDs in "\\Computer\HKEY_USERS\" hive
             * attempt to access "Volatile Environment" for each SID
             * get values from USERDOMAIN and USERNAME keys
            */
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
                //https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ee886409(v=vs.85)
                string resource = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/*";
                string wql = "Select SID from Win32_UserProfile";
                string dialect = "http://schemas.microsoft.com/wbem/wsman/1/WQL";
                IWSManEnumerator response = winrm.Enumerate(resource, wql, dialect);
                // Enumerate returned CIM instances.
                while (!response.AtEndOfStream)
                {
                    string item = response.ReadItem();
                    XDocument doc = XDocument.Parse(item);
                    IEnumerable<XElement> sids = doc.Descendants("SID");
                    
                    //iterate through SIDs in "\\Computer\HKEY_USERS\" hive
                    foreach (XElement sid in sids)
                    {
                        Console.WriteLine(sid.Value);
                        // TODO:
                        // attempt to access "Volatile Environment" for each SID
                        // get values from USERDOMAIN and USERNAME keys

                        // possibly use CIMSession but requires Microsoft.Management.Infrastructure namespace import
                        //https://docs.microsoft.com/en-us/windows/win32/wmisdk/connecting-to-wmi-remotely-with-c-
                    }
                }
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] {0} - Unable to query registry over WinRM: {1}", host, ex.Message);
                }
            }
        }
        public static void GetCurrentUsersWMI(string host, string ns, bool verbose)
        {
            /* https://docs.microsoft.com/en-us/dotnet/api/microsoft.win32.registryhive
             * get SIDs from Win32_UserProfile WMI class
             * iterate through SIDs in "\\Computer\HKEY_USERS\" hive
             * attempt to access "Volatile Environment" for each SID
             * get values from USERDOMAIN and USERNAME keys
            */
            ManagementScope scope = new ManagementScope(string.Format(@"\\{0}\{1}", host, ns));

            //https://docs.microsoft.com/en-us/windows/win32/wmisdk/wql-operators
            //https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ee886409(v=vs.85)
            ObjectQuery querySIDs = new ObjectQuery("Select SID from Win32_UserProfile");

            try
            {
                scope.Connect();
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, querySIDs);
                ManagementObjectCollection userSIDs = searcher.Get();

                //loop through each SID attempting to access "Volatile Environment"
                foreach (ManagementObject user in userSIDs)
                {
                    string sid = user["SID"].ToString();
                    string domain = "";
                    string username = "";

                    ManagementClass registry = new ManagementClass(scope, new ManagementPath("StdRegProv"), null);
                    ManagementBaseObject inParams = registry.GetMethodParameters("GetStringValue");

                    inParams["hDefKey"] = 0x80000003;// HKEY_USERS;
                    inParams["sSubKeyName"] = sid + "\\Volatile Environment";

                    //pull USERNAME key
                    inParams["sValueName"] = "USERNAME";
                    ManagementBaseObject getUsername = registry.InvokeMethod("GetStringValue", inParams, null);

                    if (getUsername.Properties["sValue"].Value != null)
                    {
                        username = getUsername.Properties["sValue"].Value.ToString();
                    }

                    //pull USERDOMAIN key
                    inParams["sValueName"] = "USERDOMAIN";
                    ManagementBaseObject getDomain = registry.InvokeMethod("GetStringValue", inParams, null);

                    if (getDomain.Properties["sValue"].Value != null)
                    {
                        domain = getDomain.Properties["sValue"].Value.ToString();
                    }

                    if (!String.IsNullOrEmpty(domain) && !String.IsNullOrEmpty(username))
                        Console.WriteLine("[registry] {0} - {1}\\{2}", host, domain, username);
                }

            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] {0} - Unable to query registry over WMI: {1}", host, ex.Message);
                }
            }
            //try
            //{
            /* https://docs.microsoft.com/en-us/dotnet/api/microsoft.win32.registryhive
             * iterate through SIDs in "\\Computer\HKEY_USERS\" hive
             * attempt to access "Volatile Environment" for each SID
             * get values from USERDOMAIN and USERNAME keys
            */
            /*
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
            */
        }
    }
}
