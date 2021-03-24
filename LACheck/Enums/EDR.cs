using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Xml.Linq;
using WSManAutomation; //Add Reference -> windows\system32\wsmauto.dll (or COM: Microsoft WSMan Automation V 1.0 Library)


namespace LACheck.Enums
{
    class EDR
    {
        public static Dictionary<string, string> EDRList = new Dictionary<string, string>
        {
            { "psepfilter.sys" , "Absolute" },
            { "atrsdfw.sys" , "Altiris (Symantec)" },
            { "cve.sys" , "Absolute" },
            { "aswsp.sys" , "Avast" },
            { "avgtpx86.sys" , "AVG Technologies" },
            { "avgtpx64.sys" , "AVG Technologies" },
            { "atc.sys" , "BitDefender" },
            { "avc3.sys" , "BitDefender" },
            { "avckf.sys" , "BitDefender" },
            { "bddevflt.sys" , "BitDefender" },
            { "bdsandbox.sys" , "BitDefender" },
            { "bdsvm.sys" , "BitDefender" },
            { "edrsensor.sys" , "BitDefender" },
            { "gzflt.sys" , "BitDefender" },
            { "hbflt.sys" , "BitDefender" },
            { "trufos.sys" , "BitDefender" },
            { "brcow_x_x_x_x.sys" , "Bromium" },
            { "brfilter.sys" , "Bromium" },
            { "carbonblackk.sys" , "Carbon Black" },
            { "cbk7.sys" , "Carbon Black" },
            { "cbstream.sys" , "Carbon Black" },
            { "parity.sys" , "Carbon Black" },
            { "cposfw.sys" , "Check Point Software Technologies" },
            { "dsfa.sys" , "Check Point Software Technologies" },
            { "epregflt.sys" , "Check Point Software Technologies" },
            { "medlpflt.sys" , "Check Point Software Technologies" },
            { "csaam.sys" , "Cisco" },
            { "csaav.sys" , "Cisco" },
            { "csacentr.sys" , "Cisco" },
            { "csaenh.sys" , "Cisco" },
            { "csareg.sys" , "Cisco" },
            { "csascr.sys" , "Cisco" },
            { "rvsavd.sys" , "CJSC Returnil Software" },
            { "cfrmd.sys" , "Comodo Security Solutions" },
            { "cmdccav.sys" , "Comodo Security Solutions" },
            { "cmdguard.sys" , "Comodo Security Solutions" },
            { "cmdmnefs.sys" , "Comodo Security Solutions" },
            { "mydlpmf.sys" , "Comodo Security Solutions" },
            { "im.sys" , "CrowdStrike" },
            { "csagent.sys" , "CrowdStrike" },
            { "csboot.sys" , "CrowdStrike" },
            { "csdevicecontrol.sys" , "CrowdStrike" },
            { "cspcm2.sys" , "CrowdStrike" },
            { "cybkerneltracker.sys" , "CyberArk Software" },
            { "crexecprev.sys" , "Cybereason" },
            { "cyoptics.sys" , "Cylance Inc." },
            { "cyprotectdrv32.sys" , "Cylance Inc." },
            { "cyprotectdrv64.sys" , "Cylance Inc." },
            { "groundling32.sys" , "Dell Secureworks" },
            { "groundling64.sys" , "Dell Secureworks" },
            { "esensor.sys" , "Endgame" },
            { "edevmon.sys" , "ESET" },
            { "ehdrv.sys" , "ESET" },
            { "fsatp.sys" , "F-Secure" },
            { "fsgk.sys" , "F-Secure" },
            { "fshs.sys" , "F-Secure" },
            { "fekern.sys", "FireEye" },
            { "wfp_mrt.sys", "FireEye" },
            { "eaw.sys" , "Raytheon Cyber Solutions" },
            { "hexisfsmonitor.sys" , "Hexis Cyber Solutions" },
            { "klifaa.sys" , "Kaspersky" },
            { "klifks.sys" , "Kaspersky" },
            { "klifsm.sys" , "Kaspersky" },
            { "lragentmf.sys" , "LogRhythm" },
            { "mbamwatchdog.sys" , "Malwarebytes" },
            { "epdrv.sys" , "McAfee" },
            { "hdlpflt.sys" , "McAfee" },
            { "mfeaskm.sys" , "McAfee" },
            { "mfeeeff.sys" , "McAfee" },
            { "mfehidk.sys" , "McAfee" },
            { "mfencfilter.sys" , "McAfee" },
            { "mfencoas.sys" , "McAfee" },
            { "mfprom.sys" , "McAfee" },
            { "swin.sys" , "McAfee" },
            { "libwamf.sys" , "OPSWAT Inc" },
            { "amfsm.sys" , "Panda Security" },
            { "amm8660.sys" , "Panda Security" },
            { "amm6460.sys" , "Panda Security" },
            { "psinfile.sys" , "Panda Security" },
            { "psinproc.sys" , "Panda Security" },
            { "sentinelmonitor.sys" , "SentinelOne" },
            { "bhdrvx86.sys" , "Symantec" },
            { "bhdrvx64.sys" , "Symantec" },
            { "diflt.sys" , "Symantec" },
            { "emxdrv2.sys" , "Symantec" },
            { "evmf.sys" , "Symantec" },
            { "fencry.sys" , "Symantec" },
            { "gefcmp.sys" , "Symantec" },
            { "geprotection.sys" , "Symantec" },
            { "pgpfs.sys" , "Symantec" },
            { "pgpwdefs.sys" , "Symantec" },
            { "reghook.sys" , "Symantec" },
            { "sisipsfilefilter.sys" , "Symantec" },
            { "spbbcdrv.sys" , "Symantec" },
            { "ssrfsf.sys" , "Symantec" },
            { "symrg.sys" , "Symantec" },
            { "symefa.sys" , "Symantec" },
            { "symefasi.sys" , "Symantec" },
            { "symefa64.sys" , "Symantec" },
            { "symafr.sys" , "Symantec" },
            { "symevent.sys" , "Symantec" },
            { "symhsm.sys" , "Symantec" },
            { "sysmon.sys" , "Symantec" },
            { "virtfile.sys" , "Symantec" },
            { "vfsenc.sys" , "Symantec" },
            { "vxfsrep.sys" , "Symantec" },
            { "safe-agent.sys" , "SAFE-Cyberdefense" },
            { "savonaccess.sys" , "Sophos" },
            { "sld.sys" , "Sophos" },
            { "acdriver.sys" , "Trend Micro" },
            { "fileflt.sys" , "Trend Micro" },
            { "hfileflt.sys" , "Trend Micro" },
            { "tmesflt.sys" , "Trend Micro" },
            { "tmevtmgr.sys" , "Trend Micro" },
            { "tmfileencdmk.sys" , "Trend Micro" },
            { "tmumh.sys" , "Trend Micro" },
            { "tmums.sys" , "Trend Micro" },
            { "sakfile.sys" , "Trend Micro" },
            { "sakmfile.sys" , "Trend Micro" },
            { "dgdmk.sys" , "Verdasys Inc." },
            { "ssfmonm.sys" , "Webroot Software, Inc." },
        };

        public static void EDRCheckSMB(string host)
        {
            string x64path = @"\\" + host + @"\C$\windows\system32\drivers";
            string x86path = @"\\" + host + @"\C$\windows\sysnative\drivers";
            List<string> drivers = new List<string>();

            try
            {
                string[] x64fileEntries = Directory.GetFiles(x64path, "*.sys");
                //strip out file path
                foreach (string file in x64fileEntries)
                    drivers.Add(Path.GetFileName(file).ToLower().ToLower());
            }
            catch {/*nothing*/ }

            try
            {
                string[] x86fileEntries = Directory.GetFiles(x86path, "*.sys");
                //strip out file path
                foreach (string file in x86fileEntries)
                    drivers.Add(Path.GetFileName(file).ToLower());                
            }
            catch {/*nothing*/ }

            // only continues if drivers were returned
            if ( drivers.Any() )
            {
                //dedup list of drivers
                drivers = drivers.Distinct().ToList();

                List<string> matches = new List<string>();
                foreach (string driver in drivers)
                {
                    //Console.WriteLine(driver);
                    if (EDRList.ContainsKey(driver))
                    {
                        matches.Add(EDRList[driver]);
                    }
                }

                //dedup list of matches
                matches = matches.Distinct().ToList();

                if (matches.Any())
                {
                    Console.WriteLine("[EDR] {0} - Found: {1}", host, String.Join(", ", matches.ToArray()));
                }
                else
                {
                    Console.WriteLine("[EDR] {0} - no EDR found", host);
                }
                
            }
        }
        public static void EDRCheckWinRM(string host, bool verbose)
        {
            try
            {
                List<string> drivers = new List<string>();
                List<string> matches = new List<string>();

                //https://bohops.com/2020/05/12/ws-management-com-another-approach-for-winrm-lateral-movement/
                //https://github.com/bohops/WSMan-WinRM/blob/master/SharpWSManWinRM.cs
                IWSManEx wsman = new WSMan();
                IWSManConnectionOptions options = (IWSManConnectionOptions)wsman.CreateConnectionOptions();
                IWSManSession winrm = (IWSManSession)wsman.CreateSession(host, 0, options);

                //https://docs.microsoft.com/en-us/windows/win32/winrm/querying-for-specific-instances-of-a-resource
                //https://stackoverflow.com/questions/29645896/how-to-retrieve-cim-instances-from-a-linux-host-using-winrm
                //https://docs.microsoft.com/en-us/windows/win32/wmisdk/wql-operators
                //https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/cim-datafile
                string resource = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/*";
                string wql = @"Select name from CIM_DataFile where (Path = '\\windows\\system32\\drivers\\' OR Path = '\\windows\\sysnative\\drivers\\') AND Extension = 'sys'";
                string dialect = "http://schemas.microsoft.com/wbem/wsman/1/WQL";
                IWSManEnumerator response = winrm.Enumerate(resource, wql, dialect);
                // Enumerate returned CIM instances.
                while (!response.AtEndOfStream)
                {
                    string item = response.ReadItem();
                    XDocument doc = XDocument.Parse(item);

                    //WMI Query gets full path of each match
                    string driverPath = doc.Descendants("Name").First().Value;
                    //remove the path from each driver
                    string driverName = Path.GetFileName(driverPath.ToLower());
                    drivers.Add(driverName);
                }

                foreach (string driver in drivers)
                {
                    if (EDRList.ContainsKey(driver))
                    {
                        matches.Add(EDRList[driver]);
                    }
                }
                //dedup list of matches
                matches = matches.Distinct().ToList();

                if (matches.Any())
                {
                    Console.WriteLine("[EDR] {0} - Found: {1}", host, String.Join(", ", matches.ToArray()));
                }
                else
                {
                    Console.WriteLine("[EDR] {0} - no EDR found", host);
                }
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] {0} - Unable to query drivers over WinRM: {1}", host, ex.Message);
                }
            }
            /*
            ManagementScope scope = new ManagementScope(string.Format(@"\\{0}\{1}", host, ns));

            //https://docs.microsoft.com/en-us/windows/win32/wmisdk/wql-operators
            //https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/cim-datafile

            SelectQuery query = new SelectQuery(@"Select * from CIM_DataFile where (Path = '\\windows\\system32\\drivers\\' OR Path = '\\windows\\sysnative\\drivers\\') AND Extension = 'sys'");

            try
            {
                scope.Connect();
                //https://stackoverflow.com/questions/842533/in-c-sharp-how-do-i-query-the-list-of-running-services-on-a-windows-server
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query))
                {
                    ManagementObjectCollection paths = searcher.Get();
                    List<string> drivers = new List<string>();
                    List<string> matches = new List<string>();

                    //WMI Query gets full path of each match
                    foreach (ManagementObject path in paths)
                    {
                        //remove the path from each driver
                        drivers.Add(Path.GetFileName(path["Name"].ToString().ToLower()));
                    }

                    foreach (string driver in drivers)
                    {
                        if (EDRList.ContainsKey(driver))
                        {
                            matches.Add(EDRList[driver]);
                        }
                    }
                    //dedup list of matches
                    matches = matches.Distinct().ToList();

                    if (matches.Any())
                    {
                        Console.WriteLine("[EDR] {0} - Found: {1}", host, String.Join(", ", matches.ToArray()));
                    }
                    else
                    {
                        Console.WriteLine("[EDR] {0} - no EDR found", host);
                    }
                }
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] {0} - Unable to query drivers: {1}", host, ex.Message);
                }
            }
            */
        }
        public static void EDRCheckWMI(string host, string ns, bool verbose)
        {
            ManagementScope scope = new ManagementScope(string.Format(@"\\{0}\{1}", host, ns));

            //https://docs.microsoft.com/en-us/windows/win32/wmisdk/wql-operators
            //https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/cim-datafile

            SelectQuery query = new SelectQuery(@"Select name from CIM_DataFile where (Path = '\\windows\\system32\\drivers\\' OR Path = '\\windows\\sysnative\\drivers\\') AND Extension = 'sys'");

            try
            {
                scope.Connect();
                //https://stackoverflow.com/questions/842533/in-c-sharp-how-do-i-query-the-list-of-running-services-on-a-windows-server
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query))
                {
                    ManagementObjectCollection paths = searcher.Get();
                    List<string> drivers = new List<string>(); 
                    List<string> matches = new List<string>();
                    
                    //WMI Query gets full path of each match
                    foreach (ManagementObject path in paths)
                    {
                        //remove the path from each driver
                        drivers.Add(Path.GetFileName(path["Name"].ToString().ToLower()));
                    }

                    foreach (string driver in drivers)
                    {
                        if (EDRList.ContainsKey(driver))
                        {
                            matches.Add(EDRList[driver]);
                        }
                    }
                    //dedup list of matches
                    matches = matches.Distinct().ToList();

                    if (matches.Any())
                    {
                        Console.WriteLine("[EDR] {0} - Found: {1}", host, String.Join(", ", matches.ToArray()));
                    }
                    else
                    {
                        Console.WriteLine("[EDR] {0} - no EDR found", host);
                    }
                }
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] {0} - Unable to query drivers over WMI: {1}", host, ex.Message);
                }
            }
        }

    }
}
