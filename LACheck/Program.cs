using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;


namespace LACheck
{
    class Program
    {
        static void Main(string[] args)
        {
            var parsedArgs = Utilities.Options.ParseArgs(args);
            Utilities.Arguments arguments = Utilities.Options.ArgumentValues(parsedArgs);

            if (arguments != null)
            {
                Utilities.Options.PrintOptions(arguments);
                if (arguments.validate)
                {
                    Utilities.Options.ValidateCredentials();
                }

                Dictionary<string, string> hosts = new Dictionary<string, string>();
                if (!String.IsNullOrEmpty(arguments.ldap))
                {
                    Dictionary<string, string> ldap = Utilities.LDAP.SearchLDAP(arguments.ldap, arguments);
                    if (ldap != null)
                        hosts = hosts.Union(ldap.Where(k => !hosts.ContainsKey(k.Key))).ToDictionary(k => k.Key, v => v.Value);
                }
                if (!String.IsNullOrEmpty(arguments.ou))
                {
                    Dictionary<string, string> ou = Utilities.LDAP.SearchOU(arguments.ou, arguments);
                    if (ou != null)
                        hosts = hosts.Union(ou.Where(k => !hosts.ContainsKey(k.Key))).ToDictionary(k => k.Key, v => v.Value);
                }
                if (!String.IsNullOrEmpty(arguments.targets))
                {
                    List<string> targets = arguments.targets.Split(',').ToList();
                    foreach (string target in targets)
                    {
                        if (!hosts.ContainsKey(target.ToUpper()))
                        {
                            string SID = null;
                            //only resolve SID if needed for bloodhound output
                            if (arguments.bloodhound)
                                SID = Utilities.LDAP.GetComputerSID(target, arguments);
                            //add hostname:SID pair to hosts dictionary
                            hosts.Add(target.ToUpper(), SID);
                        }
                    }
                }
                if (hosts.Count == 0)
                {
                    Console.WriteLine("[!] No hosts specified - use /targets, /ldap, or /ou flags");
                    Utilities.Options.Usage();
                    //Environment.Exit(0);
                }

                //https://docs.microsoft.com/en-us/windows/win32/wmisdk/wql-operators
                //https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem
                //https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logonsession
                //string wql = "Select * from Win32_LogonSession Where LogonType = 10";
                string wql = "SELECT PartOfDomain FROM Win32_ComputerSystem";
                string ns = @"root\cimv2";

                //https://blog.danskingdom.com/limit-the-number-of-c-tasks-that-run-in-parallel/
                var listOfChecks = new List<Action>();

                foreach (KeyValuePair<string, string> host in hosts)
                {
                    // Note that we create the Action here, but do not start it.
                    listOfChecks.Add(() => EnumerateHost(host.Key, ns, wql, arguments));
                }
                Utilities.Status.totalCount = hosts.Count();
                Utilities.Status.currentCount = 0;
                Utilities.Status.StartOutputTimer();
                //https://devblogs.microsoft.com/pfxteam/parallel-invoke-vs-explicit-task-management/
                var options = new ParallelOptions { MaxDegreeOfParallelism = arguments.threads };
                Parallel.Invoke(options, listOfChecks.ToArray());
                Console.WriteLine("[+] Finished enumerating hosts");
                if (arguments.bloodhound)
                {
                    //filter dictionary of all resolved host:SID pairs only keeping hosts where Admin Checks succeeded
                    Dictionary<string, string> outputHosts = Utilities.BloodHound.LACheckSessions.AdminSuccess.Distinct().Where(i => hosts.ContainsKey(i)).ToDictionary(i => i, i => hosts[i]);
                    Utilities.SessionInfo.ResolveSIDs(outputHosts, arguments);
                    Utilities.BloodHound.GenerateOutput(outputHosts, arguments);
                }
            }
        }
        public static void EnumerateHost(string host, string ns, string wql, Utilities.Arguments arguments)
        {
            if (arguments.rpc)
            {
                Enums.WMI.Check(host, ns, wql, arguments);
            }
            if (arguments.smb)
            {
                Enums.SMB.Check(host, arguments);
            }
            if (arguments.winrm)
            {
                Enums.WINRM.Check(host, ns, wql, arguments);
            }
            Utilities.Status.currentCount += 1;
        }
    }
}