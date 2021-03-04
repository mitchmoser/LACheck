using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace LACheck
{
    class Program
    {
        static void Main(string[] args)
        {
            var parsedArgs = Utilities.Options.ParseArgs(args);
            Utilities.Arguments arguments = Utilities.Options.ArgumentValues(parsedArgs);

            Utilities.Options.PrintOptions(arguments);
            if (arguments.validate)
            {
                Utilities.Options.ValidateCredentials();
            }

            List<string> hosts = new List<string>();
            if (!String.IsNullOrEmpty(arguments.targets))
            {
                List<string> targets = arguments.targets.Split(',').ToList();
                hosts = hosts.Concat(targets).ToList();
            }
            if (!String.IsNullOrEmpty(arguments.ldap))
            {
                List<string> ldap = Utilities.LDAP.SearchLDAP(arguments.ldap, arguments.verbose);
                hosts = hosts.Concat(ldap).ToList();
            }
            if (!String.IsNullOrEmpty(arguments.ou))
            {
                List<string> ou = Utilities.LDAP.SearchOU(arguments.ou, arguments.verbose);
                hosts = hosts.Concat(ou).ToList();
            }
            if (hosts.Count == 0)
            {
                Console.WriteLine("[!] No hosts specified - use /targets, /ldap, or /ou flags");
                Utilities.Options.Usage();
                Environment.Exit(0);
            }
            //remove duplicate hosts
            hosts = hosts.Distinct().ToList();

            //https://docs.microsoft.com/en-us/windows/win32/wmisdk/wql-operators
            //https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem
            //https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logonsession
            //string wql = "Select * from Win32_LogonSession Where LogonType = 10";
            string wql = "SELECT PartOfDomain FROM Win32_ComputerSystem";
            string ns = @"root\cimv2";

            //https://blog.danskingdom.com/limit-the-number-of-c-tasks-that-run-in-parallel/
            var listOfChecks = new List<Action>();

            foreach (string host in hosts)
            {
                if (arguments.rpc)
                {
                    // Note that we create the Action here, but do not start it.
                    listOfChecks.Add(() => Enums.WMI.Check(host, ns, wql, arguments.logons, arguments.services, arguments.verbose));
                }
                if (arguments.smb)
                {
                    listOfChecks.Add(() => Enums.SMB.Check(host, arguments.logons, arguments.registry, arguments.services, arguments.verbose));
                }
                if (arguments.winrm)
                {
                    listOfChecks.Add(() => Enums.WINRM.Check(host, wql, arguments.verbose));
                }
            }
            //https://devblogs.microsoft.com/pfxteam/parallel-invoke-vs-explicit-task-management/
            var options = new ParallelOptions { MaxDegreeOfParallelism = arguments.threads };
            Parallel.Invoke(options, listOfChecks.ToArray());
            Console.WriteLine("[+] Finished");
        }
    }
}