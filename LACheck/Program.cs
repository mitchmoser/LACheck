using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading.Tasks;
using System.Xml.Linq;
using WSManAutomation; //Add Reference -> windows\system32\wsmauto.dll (or COM: Microsoft WSMan Automation V 1.0 Library)

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
            int threads = 25;
            if (parsedArgs.ContainsKey("/threads"))
            {
                threads = Convert.ToInt32(parsedArgs["/threads"][0]);
            }
            PrintOptions(parsedArgs, rpc, smb, winrm);
            if (validate)
            {
                ValidateCredentials();
            }

            List<string> hosts = new List<string>();
            if (parsedArgs.ContainsKey("/targets"))
            {
                List<string> targets = parsedArgs["/targets"][0].Split(',').ToList();
                hosts = hosts.Concat(targets).ToList();
            }
            if (parsedArgs.ContainsKey("/ldap"))
            {
                List<string> ldap = SearchLDAP(parsedArgs["/ldap"][0].ToLower(), verbose);
                hosts = hosts.Concat(ldap).ToList();
            }
            if (parsedArgs.ContainsKey("/ou"))
            {
                List<string> ou = SearchOU(parsedArgs["/ou"][0].ToLower(), verbose);
                hosts = hosts.Concat(ou).ToList();
            }
            else
            {
                Console.WriteLine("[!] No targets specified - use /targets, /ldap, or /ou flags");
                Usage();
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
                //RPC Check
                if (rpc)
                {
                    // Note that we create the Action here, but do not start it.
                    listOfChecks.Add(() => RPC_Check(host, ns, wql, verbose));
                }   
                //SMB Check
                if (smb)
                {
                    listOfChecks.Add(() => SMB_Check(host, verbose));
                }
                //WinRM Check
                if (winrm)
                {
                    listOfChecks.Add(() => WinRM_Check(host, wql, verbose));
                }
            }
            var options = new ParallelOptions { MaxDegreeOfParallelism = threads };
            Parallel.Invoke(options, listOfChecks.ToArray());
            Console.WriteLine("[+] Finished");
        }
        public static List<string> SearchOU(string ou, bool verbose)
        {
            try
            {
                List<string> ComputerNames = new List<string>();
                string searchbase = "LDAP://" + ou;//OU=Domain Controllers,DC=example,DC=local";
                DirectoryEntry entry = new DirectoryEntry(searchbase);
                DirectorySearcher mySearcher = new DirectorySearcher(entry);
                // filter for all enabled computers
                mySearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");
                mySearcher.SizeLimit = int.MaxValue;
                mySearcher.PageSize = int.MaxValue;
                int counter = 0;
                foreach (SearchResult resEnt in mySearcher.FindAll())
                {
                    string ComputerName = resEnt.GetDirectoryEntry().Name;
                    if (ComputerName.StartsWith("CN="))
                        ComputerName = ComputerName.Remove(0, "CN=".Length);
                    ComputerNames.Add(ComputerName);
                    counter += 1;
                }
                Console.WriteLine("[+] OU Search Results: {0}", counter.ToString());
                mySearcher.Dispose();
                entry.Dispose();

                return ComputerNames;
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] LDAP Error: {0}", ex.Message);
                }
                Environment.Exit(0);
                return null;
            }
        }
        public static List<string> SearchLDAP(string filter, bool verbose)
        {
            try
            {
                List<string> ComputerNames = new List<string>();

                DirectoryEntry entry = new DirectoryEntry();
                DirectorySearcher mySearcher = new DirectorySearcher(entry);

                //https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx
                //https://ldapwiki.com/wiki/Active%20Directory%20Computer%20Related%20LDAP%20Query
                switch (filter)
                {
                    case "all":
                        //All enabled computers with "primary" group "Domain Computers"
                        mySearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");
                        break;
                    case "dc":
                        //All enabled Domain Controllers
                        mySearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=8192))");
                        break;
                    case "exclude-dc":
                        //All enabled computers that are not Domain Controllers
                        mySearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))");
                        break;
                    case "servers":
                        //All enabled servers
                        mySearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*))");
                        break;
                    case "servers-exclude-dc":
                        //All enabled servers excluding DCs
                        mySearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))");
                        break;
                    default:
                        Console.WriteLine("[!] Invalid LDAP filter: {0}", filter);
                        Usage();
                        Environment.Exit(0);
                        break;
                }
                
                mySearcher.SizeLimit = int.MaxValue;
                mySearcher.PageSize = int.MaxValue;
                int counter = 0;
                foreach (SearchResult resEnt in mySearcher.FindAll())
                {
                    string ComputerName = resEnt.GetDirectoryEntry().Name;
                    if (ComputerName.StartsWith("CN="))
                        ComputerName = ComputerName.Remove(0, "CN=".Length);
                    ComputerNames.Add(ComputerName);
                    counter += 1;
                }
                Console.WriteLine("[+] LDAP Search Results: {0}", counter.ToString());
                mySearcher.Dispose();
                entry.Dispose();

                return ComputerNames;
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] LDAP Error: {0}", ex.Message);
                }
                Environment.Exit(0);
                return null;
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
                    Console.WriteLine("[WinRM] Admin Success: {0}", host);
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
                    Console.WriteLine("[!] WinRM on {0} - {1}", host, ex.Message.Trim());
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
                Console.WriteLine("[RPC] Admin Success: {0}", host);
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] RPC on {0} - {1}", host, ex.Message.Trim());
                }
            }
        }
        static void SMB_Check(string host, bool verbose)
        {
            try
            {
                string share = "\\\\" + host + "\\C$";
                System.Security.AccessControl.DirectorySecurity ds = Directory.GetAccessControl(share);
                Console.WriteLine("[SMB] Admin Success: {0}", host);
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] SMB on {0} - {1}", host, ex.Message.Trim());
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
    LACheck.exe smb rpc /targets:hostname,fqdn.domain.tld,10.10.10.10 /ldap:all /ou:""OU=Special Servers,DC=example,DC=local"" /verbose /validate

Local Admin Checks:
    smb   - Attempts to access C$ share
    rpc   - Attempts WMI query of Win32_ComputerSystem Class provider over RPC
    winrm - Attempts WMI query of Win32_ComputerSystem Class Provider over WinRM Session

Arguments:
    /targets  - comma-separated list of hostnames to check. If none provided, localhost will be checked.
    /validate - check credentials against Domain prior to scanning targets (useful during token manipulation)
    /verbose  - print additional logging information
    /threads  - specify maximum number of parallel threads (default=25)
    /ou       - specify LDAP OU to query enabled computer objects from
                ex: ""OU=Special Servers,DC=example,DC=local""
    /ldap - query hosts from the following LDAP filters:
         :all - All enabled computers with 'primary' group 'Domain Computers'
         :dc - All enabled Domain Controllers
         :exclude-dc - All enabled computers that are not Domain Controllers
         :servers - All enabled servers
         :servers-exclude-dc - All enabled servers excluding DCs
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