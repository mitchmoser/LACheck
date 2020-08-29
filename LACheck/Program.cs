using System;
using System.Management;
using System.IO;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Threading;

namespace LACheck
{
    class Program
    {
        static void Main(string[] args)
        {
            var parsedArgs = ParseArgs(args);
            PrintOptions(parsedArgs);
            if (parsedArgs.ContainsKey("help"))
            {
                Usage();
                Environment.Exit(1);
            }
            if (!parsedArgs.ContainsKey("smb") && !parsedArgs.ContainsKey("rpc"))
            {
                Console.WriteLine("[!] No check type specified: smb rpc");
                Usage();
                Environment.Exit(1);
            }

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

            if (validate)
            {
                ValidateCredentials();
            }

            string[] hosts = { "localhost" };
            if (parsedArgs.ContainsKey("/targets"))
            {
                hosts = parsedArgs["/targets"][0].Split(',');
            }

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
                    if (smb)
                    {
                        //https://stackoverflow.com/questions/1195896/threadstart-with-parameters
                        Thread newThread = new Thread(() => RPC_Check(host, ns, verbose));
                        newThread.Start();
                    }
                    
                    //SMB Check
                    if (smb)
                    {
                        Thread newThread = new Thread(() => SMB_Check(host, verbose));
                        newThread.Start();
                    }

                    //WinRM Check
                    /*
                    if (winrm)
                    {
                        //https://stackoverflow.com/questions/1195896/threadstart-with-parameters
                        Thread newThread = new Thread(() => WinRM_Check(host, verbose));
                        newThread.Start();
                    }
                    */
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
        /*
        static void WinRM_Check(string host, bool verbose)
        {
            //https://bohops.com/2020/05/12/ws-management-com-another-approach-for-winrm-lateral-movement/
            IWSManEx wsman = new WSMan();
            IWSManConnectionOptions options = (IWSManConnectionOptions)wsman.CreateConnectionOptions();
            //string sessionURL = Globals.protocol + "://" + host + ":" + Globals.port + "/wsman";
            string sessionURL = "https://" + host + ":5985/wsman";
            IWSManSession session = (IWSManSession)wsman.CreateSession(sessionURL, 0, options);
            string resource = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Process";
            string parameters = "<p:Create_INPUT xmlns:p=\"http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_Process\"><p:CommandLine>notepad.exe</p:CommandLine></p:Create_INPUT>";
            string response = session.Invoke("Create", resource, parameters);
        }
        */
        static void RPC_Check(string host, string ns, bool verbose)
        {
            try
            {
                ManagementScope scope = new ManagementScope(string.Format(@"\\{0}\{1}", host, ns));
                //https://docs.microsoft.com/en-us/windows/win32/wmisdk/wql-operators
                //https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem
                //https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logonsession
                //Select * from Win32_LogonSession Where LogonType = 10
                SelectQuery query = new SelectQuery("SELECT PartOfDomain FROM Win32_ComputerSystem");
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
    smb - Attempts to access C$ share
    rpc - Attempts WMI query of Win32_ComputerSystem Class provider

Argument:
    /targets  - comma-separated list of hostnames to check. If none provided, localhost will be checked.
    /validate - check credentials against Domain prior to scanning targets (useful during token manipulation)
    /verbose  - print additional logging information
";
            Console.WriteLine(usageString);
        }

        static void PrintOptions(Dictionary<string, string[]> args)
        {
            Console.WriteLine("[+] Parsed Aguments:");
            foreach (string key in args.Keys)
            {
                Console.WriteLine("\t{0}: {1}", key, string.Join(", ", args[key]));
            }
        }
        static bool ValidateArguments(Dictionary<string, string[]> args)
        {
            if (args.ContainsKey("help"))
            {
                return false;
            }
            if (!args.ContainsKey("smb") && !args.ContainsKey("rpc"))
            {
                Console.WriteLine("[!] No check type specified: smb rpc");
                return false;
            }
            return true;
        }
        static Dictionary<string, string[]> ParseArgs(string[] args)
        {
            Dictionary<string, string[]> result = new Dictionary<string, string[]>();
            //these boolean variables aren't passed w/ values. If passed, they are "true"
            string[] booleans = new string[] { "smb", "wmi", "/verbose" };
            var argList = new List<string>();
            foreach (string arg in args)
            {
                //delimit key/value of arguments by ":"
                string[] parts = arg.Split(":".ToCharArray(), 2);
                argList.Add(parts[0]);

                //boolean variables
                if (parts.Length == 1)
                {
                    result[parts[0]] = new string[] { "True" };
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