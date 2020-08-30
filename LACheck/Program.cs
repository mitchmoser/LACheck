using System;
using System.Management;
using System.IO;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Threading;
using WSManAutomation;

using System.Linq;
using System.Xml.Linq;

namespace LACheck
{
    class Program
    {
        static void Main(string[] args)
        {
            var parsedArgs = ParseArgs(args);
            ValidateArguments(parsedArgs);
            
            bool verbose = false;
            if (parsedArgs.ContainsKey("/verbose"))
            {
                verbose = Convert.ToBoolean(parsedArgs["/verbose"][0]);
            }

            bool rpc = false;
            if (parsedArgs.ContainsKey("rpc"))
            {
                rpc = Convert.ToBoolean(parsedArgs["rpc"][0]);
            }

            bool smb = false;
            if (parsedArgs.ContainsKey("smb"))
            {
                smb = Convert.ToBoolean(parsedArgs["smb"][0]);
            }

            bool winrm = false;
            if (parsedArgs.ContainsKey("winrm"))
            {
                winrm = Convert.ToBoolean(parsedArgs["winrm"][0]);
            }

            bool validate = false;
            if (parsedArgs.ContainsKey("/validate"))
            {
                validate = Convert.ToBoolean(parsedArgs["/validate"][0]);
            }
            PrintOptions(parsedArgs, rpc, smb, winrm);
            if (validate)
            {
                ValidateCredentials();
            }

            string[] hosts = { "localhost" };
            if (parsedArgs.ContainsKey("/targets"))
            {
                hosts = parsedArgs["/targets"][0].Split(',');
            }

            //https://docs.microsoft.com/en-us/windows/win32/wmisdk/wql-operators
            //https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem
            //https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logonsession
            //string wql = "Select * from Win32_LogonSession Where LogonType = 10";
            string wql = "SELECT PartOfDomain FROM Win32_ComputerSystem";
            string ns = @"root\cimv2";
            
            foreach (string host in hosts)
            {
                try
                {
                    if (verbose)
                    {
                        Console.WriteLine("[+] Connecting to {0}", host);
                    }
                    //RPC Check
                    if (rpc)
                    {
                        //https://stackoverflow.com/questions/1195896/threadstart-with-parameters
                        Thread newThread = new Thread(() => RPC_Check(host, ns, wql, verbose));
                        newThread.Start();
                    }
                    
                    //SMB Check
                    if (smb)
                    {
                        Thread newThread = new Thread(() => SMB_Check(host, verbose));
                        newThread.Start();
                    }

                    //WinRM Check
                    if (winrm)
                    {
                        //https://stackoverflow.com/questions/1195896/threadstart-with-parameters
                        Thread newThread = new Thread(() => WinRM_Check(host, wql, verbose));
                        newThread.Start();
                    }
                }
                catch (Exception ex)
                {
                    if (verbose)
                    {
                        Console.WriteLine("[!] {0} - {1}", host, ex.Message);
                        continue;
                    }
                }
            }
        }

        static void WinRM_Check(string host, string wql, bool verbose)
        {
            try
            {
                //https://bohops.com/2020/05/12/ws-management-com-another-approach-for-winrm-lateral-movement/
                //https://github.com/bohops/WSMan-WinRM/blob/master/SharpWSManWinRM.cs
                IWSManEx wsman = new WSMan();
                IWSManConnectionOptions options = (IWSManConnectionOptions)wsman.CreateConnectionOptions();
                IWSManSession session = (IWSManSession)wsman.CreateSession(host, 0, options);

                //https://docs.microsoft.com/en-us/windows/win32/winrm/querying-for-specific-instances-of-a-resource
                //https://stackoverflow.com/questions/29645896/how-to-retrieve-cim-instances-from-a-linux-host-using-winrm
                string resource = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/*";
                string dialect = "http://schemas.microsoft.com/wbem/wsman/1/WQL";
                IWSManEnumerator response = session.Enumerate(resource, wql, dialect);
                // Enumerate returned CIM instances.
                string results = "";
                while (!response.AtEndOfStream)
                {
                    string item = response.ReadItem();
                    XDocument doc = XDocument.Parse(item);
                    var resultSet = from e in doc.Elements() select e;

                    foreach (var element in resultSet)
                    {
                        results += element;
                    }
                }
                if (results != "")
                {
                    Console.WriteLine("[WinRM] Admin Succes: {0}", host);
                }
                if (verbose && results == "")
                {
                    Console.WriteLine("[!] WinRM no response for query on {0}", host);
                }
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] WinRM on {0} - {1}", host, ex.Message);
                }
            }

        }

        static void RPC_Check(string host, string ns, string wql, bool verbose)
        {
            try
            {
                ManagementScope scope = new ManagementScope(string.Format(@"\\{0}\{1}", host, ns));
                SelectQuery query = new SelectQuery(wql);
                scope.Connect();
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query))
                {
                    ManagementObjectCollection services = searcher.Get();
                }
                Console.WriteLine("[RPC] Admin Succes: {0}", host);
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] RPC on {0} - {1}", host, ex.Message);
                }
            }
        }
        static void SMB_Check(string host, bool verbose)
        {
            try
            {
                string share = "\\\\" + host + "\\C$";
                System.Security.AccessControl.DirectorySecurity ds = Directory.GetAccessControl(share);
                Console.WriteLine("[SMB] Admin Succes: {0}", host);
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] SMB on {0} - {1}", host, ex.Message);
                }
            }
        }

        static void ValidateCredentials()
        {
            try
            {
                //https://stackoverflow.com/questions/326818/how-to-validate-domain-credentials
                //https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.accountmanagement.principalcontext.validatecredentials
                bool valid = false;
                using (PrincipalContext context = new PrincipalContext(ContextType.Domain))
                {
                    valid = context.ValidateCredentials(null, null);
                }
                if (valid)
                {
                    Console.WriteLine("[+] Credentials Validated on Domain");
                }
                else
                {
                    Console.WriteLine("[!] Credentials Invalid");
                    Environment.Exit(1);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Credential Validation Error: {0}", ex.Message);
                Environment.Exit(1);
            }

        }
        static void Usage()
        {
            string usageString = @"
  _                  _____ _               _    
 | |        /\      / ____| |             | |   
 | |       /  \    | |    | |__   ___  ___| | __
 | |      / /\ \   | |    | '_ \ / _ \/ __| |/ /
 | |____ / ____ \  | |____| | | |  __/ (__|   < 
 |______/_/    \_\  \_____|_| |_|\___|\___|_|\_\

Usage:
    LACheck.exe smb rpc /targets:hostname,fqdn.domain.tld,10.10.10.10 /verbose /validate

Local Admin Checks:
    smb   - Attempts to access C$ share
    rpc   - Attempts WMI query of Win32_ComputerSystem Class provider over RPC
    winrm - Attempts WMI query of Win32_ComputerSystem Class Provider over WinRM Session

Argument:
    /targets  - comma-separated list of hostnames to check. If none provided, localhost will be checked.
    /validate - check credentials against Domain prior to scanning targets (useful during token manipulation)
    /verbose  - print additional logging information
";
            Console.WriteLine(usageString);
        }

        static void PrintOptions(Dictionary<string, string[]> args, bool smb, bool rpc, bool winrm)
        {
            Console.WriteLine("[+] Parsed Aguments:");
            if (!args.ContainsKey("smb"))
            {
                Console.WriteLine("\tsmb: false");
            }
            if (!args.ContainsKey("rpc"))
            {
                Console.WriteLine("\trpc: false");
            }
            if (!args.ContainsKey("winrm"))
            {
                Console.WriteLine("\twinrm: false");
            }
            foreach (string key in args.Keys)
            {
                Console.WriteLine("\t{0}: {1}", key, string.Join(", ", args[key]));
            }

        }
        static void ValidateArguments(Dictionary<string, string[]> args)
        {
            if (args.ContainsKey("help"))
            {
                Usage();
                Environment.Exit(0);
            }
            if (!args.ContainsKey("smb") && !args.ContainsKey("rpc") && !args.ContainsKey("winrm"))
            {
                Console.WriteLine("[!] No check type specified: smb rpc winrm");
                Environment.Exit(0);
            }
        }
        static Dictionary<string, string[]> ParseArgs(string[] args)
        {
            Dictionary<string, string[]> result = new Dictionary<string, string[]>();
            //these boolean variables aren't passed w/ values. If passed, they are "true"
            string[] booleans = new string[] { "smb", "wmi", "winrm", "/verbose" };
            var argList = new List<string>();
            foreach (string arg in args)
            {
                //delimit key/value of arguments by ":"
                string[] parts = arg.Split(":".ToCharArray(), 2);
                argList.Add(parts[0]);

                //boolean variables
                if (parts.Length == 1)
                {
                    result[parts[0]] = new string[] { "true" };
                }
                if (parts.Length == 2)
                {
                    result[parts[0]] = new string[] { parts[1] };
                }
                //Console.WriteLine("Argument: {0}", result[parts[0]]);
                //Console.WriteLine("Value: {0}", result[parts[0]][0]);
            }
            return result;
        }
    }
}