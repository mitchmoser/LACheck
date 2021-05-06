using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;


namespace LACheck.Utilities
{
    //default values off all arguments
    public class Arguments
    {
        public bool bloodhound = false;
        public bool edr = false;
        public bool help = false;
        public bool logons = false;
        public bool rpc = false;
        public bool smb = false;
        public bool registry = false;
        public bool services = false;
        public bool validate = false;
        public bool verbose = false;
        public bool winrm = false;
        public int threads = 25;
        public string ldap = null;
        public string ou = null;
        public string socket = null;
        public string targets = null;
        public string user = null;
    }
    class Options
    {
        public static void Usage()
        {
            string usageString = @"
  _                  _____ _               _    
 | |        /\      / ____| |             | |   
 | |       /  \    | |    | |__   ___  ___| | __
 | |      / /\ \   | |    | '_ \ / _ \/ __| |/ /
 | |____ / ____ \  | |____| | | |  __/ (__|   < 
 |______/_/    \_\  \_____|_| |_|\___|\___|_|\_\

Usage:
    LACheck.exe smb rpc /targets:hostname,fqdn.domain.tld,10.10.10.10 /ldap:all /ou:""OU=Special Servers,DC=example,DC=local"" /verbose /bloodhound /user:bob@contoso.lab

Local Admin Checks:
    smb   - Attempts to access C$ share
    rpc   - Attempts WMI query of Win32_ComputerSystem Class provider over RPC
    winrm - Attempts WMI query of Win32_ComputerSystem Class Provider over WinRM Session

Arguments:
    /bloodhound - generate bloodhound-digestible AdminTo and Session collection file
                  output file is zipped and enypted with randomized name and password
    /edr        - check host for EDR (requires smb, rpc, or winrm)
    /logons     - return logged on users on a host (requires smb, rpc, or winrm)
    /registry   - enumerate sessions from registry hive (requires smb)
    /services   - return services running as users (requires smb, rpc, or winrm)
    /socket     - send bloodhound output to TCP socket instead of writing to disk
                  ex: ""127.0.0.1:8080""
    /targets    - comma-separated list of hostnames to check
    /threads    - specify maximum number of parallel threads (default=25)
    /user       - specify username that collection was run under (useful during token manipulation)
    /validate   - check credentials against Domain prior to scanning targets (useful during token manipulation)
    /verbose    - print additional logging information
    /ou         - specify LDAP OU to query enabled computer objects from
                  ex: ""OU=Special Servers,DC=example,DC=local""
    /ldap - query hosts from the following LDAP filters:
         :all - All enabled computers with 'primary' group 'Domain Computers'
         :dc  - All enabled Domain Controllers (not read-only DCs)
         :exclude-dc - All enabled computers that are not Domain Controllers or read-only DCs
         :servers - All enabled servers
         :servers-exclude-dc - All enabled servers excluding Domain Controllers or read-only DCs
";
            Console.WriteLine(usageString);
        }
        public static Dictionary<string, string[]> ParseArgs(string[] args)
        {

            Dictionary<string, string[]> result = new Dictionary<string, string[]>();
            //these boolean variables aren't passed w/ values. If passed, they are "true"
            string[] booleans = new string[] { "/bloodhound", "/edr", "/logons", "/registry", "/services", "smb","winrm", "wmi", "/validate", "/verbose" };
            
            //stores the arguments provided by user
            var argList = new List<string>();

            //iterate through provided arguments and assign values
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
            }
            return result;
        }
        public static Arguments ArgumentValues(Dictionary<string, string[]> parsedArgs)
        {
            Arguments arguments = new Arguments();
            bool userprovided = false;
            if (parsedArgs.ContainsKey("/bloodhound"))
            {
                arguments.bloodhound = Convert.ToBoolean(parsedArgs["/bloodhound"][0]);
            }
            if (parsedArgs.ContainsKey("/edr"))
            {
                arguments.edr = Convert.ToBoolean(parsedArgs["/edr"][0]);
            }
            if (parsedArgs.ContainsKey("/logons"))
            {
                arguments.logons = Convert.ToBoolean(parsedArgs["/logons"][0]);
            }
            if (parsedArgs.ContainsKey("/registry"))
            {
                arguments.registry = Convert.ToBoolean(parsedArgs["/registry"][0]);
            }
            if (parsedArgs.ContainsKey("/services"))
            {
                arguments.services = Convert.ToBoolean(parsedArgs["/services"][0]);
            }
            if (parsedArgs.ContainsKey("rpc"))
            {
                arguments.rpc = Convert.ToBoolean(parsedArgs["rpc"][0]);
            }
            if (parsedArgs.ContainsKey("smb"))
            {
                arguments.smb = Convert.ToBoolean(parsedArgs["smb"][0]);
            }
            if (parsedArgs.ContainsKey("winrm"))
            {
                arguments.winrm = Convert.ToBoolean(parsedArgs["winrm"][0]);
            }
            if (parsedArgs.ContainsKey("/ldap"))
            {
                arguments.ldap = parsedArgs["/ldap"][0];
            }
            if (parsedArgs.ContainsKey("/ou"))
            {
                arguments.ou = parsedArgs["/ou"][0];
            }
            if (parsedArgs.ContainsKey("/socket"))
            {
                arguments.socket = parsedArgs["/socket"][0];
            }
            if (parsedArgs.ContainsKey("/targets"))
            {
                arguments.targets = parsedArgs["/targets"][0];
            }
            if (parsedArgs.ContainsKey("/threads"))
            {
                arguments.threads = Convert.ToInt32(parsedArgs["/threads"][0]);
            }
            if (parsedArgs.ContainsKey("/user"))
            {
                arguments.user = parsedArgs["/user"][0];
                userprovided = true;
            }
            else
            {
                arguments.user = UserPrincipal.Current.UserPrincipalName;
            }
            if (parsedArgs.ContainsKey("/validate"))
            {
                arguments.validate = Convert.ToBoolean(parsedArgs["/validate"][0]);
            }
            if (parsedArgs.ContainsKey("/verbose"))
            {
                arguments.verbose = Convert.ToBoolean(parsedArgs["/verbose"][0]);
            }
            if (parsedArgs.ContainsKey("help"))
            {
                Usage();
                Environment.Exit(0);
            }
            if (!parsedArgs.ContainsKey("smb") && !parsedArgs.ContainsKey("rpc") && !parsedArgs.ContainsKey("winrm"))
            {
                Console.WriteLine("[!] No check type specified: smb rpc winrm");
                Usage();
                Environment.Exit(0);
            }
            if (arguments.bloodhound && !userprovided)
            {
                Console.WriteLine("[!] specify current user with /user flag in 'username@domain.fqdn' format");
                Environment.Exit(0);
            }
            return arguments;
        }
        public static void PrintOptions(Arguments args)
        {
            Console.WriteLine("[+] Parsed Aguments:");
            Console.WriteLine("\trpc: {0}", args.rpc);
            Console.WriteLine("\tsmb: {0}", args.smb);
            Console.WriteLine("\twinrm: {0}", args.winrm);
            Console.WriteLine("\t/bloodhound: {0}", args.bloodhound);
            Console.WriteLine("\t/edr: {0}", args.edr);
            Console.WriteLine("\t/logons: {0}", args.logons);
            Console.WriteLine("\t/registry: {0}", args.registry);
            Console.WriteLine("\t/services: {0}", args.services);
            Console.WriteLine("\t/ldap: {0}", args.ldap);
            Console.WriteLine("\t/ou: {0}", args.ou);
            Console.WriteLine("\t/socket: {0}", args.socket);
            Console.WriteLine("\t/targets: {0}", args.targets);
            Console.WriteLine("\t/threads: {0}", args.threads);
            Console.WriteLine("\t/user: {0}", args.user);
            Console.WriteLine("\t/validate: {0}", args.validate);
            Console.WriteLine("\t/verbose: {0}", args.verbose);
        }
        public static void ValidateCredentials()
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
    }
}
