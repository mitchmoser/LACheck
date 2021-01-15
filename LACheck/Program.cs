using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Text;
using System.Xml.Linq;
using WSManAutomation; //Add Reference -> windows\system32\wsmauto.dll (or COM: Microsoft WSMan Automation V 1.0 Library)

namespace LACheck
{
    class Program
    {
        [DllImport("wtsapi32.dll")]
        static extern IntPtr WTSOpenServer([MarshalAs(UnmanagedType.LPStr)] string pServerName);

        [DllImport("wtsapi32.dll")]
        static extern void WTSCloseServer(IntPtr hServer);

        [DllImport("wtsapi32.dll")]
        static extern Int32 WTSEnumerateSessions(IntPtr hServer,
                                                 [MarshalAs(UnmanagedType.U4)] Int32 Reserved,
                                                 [MarshalAs(UnmanagedType.U4)] Int32 Version,
                                                 ref IntPtr ppSessionInfo,
                                                 [MarshalAs(UnmanagedType.U4)] ref Int32 pCount);

        [DllImport("wtsapi32.dll")]
        static extern void WTSFreeMemory(IntPtr pMemory);

        [DllImport("wtsapi32.dll")]
        static extern bool WTSQuerySessionInformation(IntPtr hServer,
                                                      int sessionId,
                                                      WTS_INFO_CLASS wtsInfoClass,
                                                      out IntPtr ppBuffer,
                                                      out uint pBytesReturned);

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public Int32 SessionID;
            [MarshalAs(UnmanagedType.LPStr)]
            public string pWinStationName;
            public WTS_CONNECTSTATE_CLASS State;
        }
        //https://social.technet.microsoft.com/Forums/windowsserver/en-US/cbfd802c-5add-49f3-b020-c901f1a8d3f4/retrieve-user-logontime-on-terminal-service-with-remote-desktop-services-api
        //https://docs.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfoa
        public struct WTSINFOA
        {
            public const int WINSTATIONNAME_LENGTH = 32;
            public const int DOMAIN_LENGTH = 17;
            public const int USERNAME_LENGTH = 20;
            public WTS_CONNECTSTATE_CLASS State;
            public int SessionId;
            public int IncomingBytes;
            public int OutgoingBytes;
            public int IncomingFrames;
            public int OutgoingFrames;
            public int IncomingCompressedBytes;
            public int OutgoingCompressedBytes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = WINSTATIONNAME_LENGTH)]
            public byte[] WinStationNameRaw;
            public string WinStationName
            {
                get
                {
                    return Encoding.ASCII.GetString(WinStationNameRaw);
                }
            }
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = DOMAIN_LENGTH)]
            public byte[] DomainRaw;
            public string Domain
            {
                get
                {
                    return Encoding.ASCII.GetString(DomainRaw);
                }
            }
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = USERNAME_LENGTH + 1)]
            public byte[] UserNameRaw;
            public string UserName
            {
                get
                {
                    return Encoding.ASCII.GetString(UserNameRaw);
                }
            }
            public long ConnectTimeUTC;
            public DateTime ConnectTime
            {
                get
                {
                    return DateTime.FromFileTimeUtc(ConnectTimeUTC);
                }
            }
            public long DisconnectTimeUTC;
            public DateTime DisconnectTime
            {
                get
                {
                    return DateTime.FromFileTimeUtc(DisconnectTimeUTC);
                }
            }
            public long LastInputTimeUTC;
            public DateTime LastInputTime
            {
                get
                {
                    return DateTime.FromFileTimeUtc(LastInputTimeUTC);
                }
            }
            public long LogonTimeUTC;
            public DateTime LogonTime
            {
                get
                {
                    return DateTime.FromFileTimeUtc(LogonTimeUTC);
                }
            }
            public long CurrentTimeUTC;
            public DateTime CurrentTime
            {
                get
                {
                    return DateTime.FromFileTimeUtc(CurrentTimeUTC);
                }
            }
        }
        public enum WTS_INFO_CLASS
        {
            WTSInitialProgram,
            WTSApplicationName,
            WTSWorkingDirectory,
            WTSOEMId,
            WTSSessionId,
            WTSUserName,
            WTSWinStationName,
            WTSDomainName,
            WTSConnectState,
            WTSClientBuildNumber,
            WTSClientName,
            WTSClientDirectory,
            WTSClientProductId,
            WTSClientHardwareId,
            WTSClientAddress,
            WTSClientDisplay,
            WTSClientProtocolType,
            WTSIdleTime,
            WTSLogonTime,
            WTSIncomingBytes,
            WTSOutgoingBytes,
            WTSIncomingFrames,
            WTSOutgoingFrames,
            WTSClientInfo,
            WTSSessionInfo
        }

        public enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit
        }
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]

        //https://docs.microsoft.com/en-us/windows/win32/api/lmwksta/nf-lmwksta-netwkstauserenum
        //Lists users currently logged onto host
        //includes interactive, service, and batch logons
        static extern int NetWkstaUserEnum(string servername,
                                           int level,
                                           out IntPtr bufptr,
                                           int prefmaxlen,
                                           out int entriesread,
                                           out int totalentries,
                                           ref int resume_handle);

        [DllImport("netapi32.dll")]
        static extern int NetApiBufferFree(IntPtr Buffer);
        const int NERR_SUCCESS = 0;
        const int ERROR_MORE_DATA = 234;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WKSTA_USER_INFO_1
        {
            public string wkui1_username;
            public string wkui1_logon_domain;
            public string wkui1_oth_domains;
            public string wkui1_logon_server;
        }
        static void Main(string[] args)
        {
            var parsedArgs = ParseArgs(args);
            ValidateArguments(parsedArgs);

            bool logons = false;
            if (parsedArgs.ContainsKey("/logons"))
            {
                logons = Convert.ToBoolean(parsedArgs["/logons"][0]);
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

            bool verbose = false;
            if (parsedArgs.ContainsKey("/verbose"))
            {
                verbose = Convert.ToBoolean(parsedArgs["/verbose"][0]);
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

            bool noHosts = true;
            List<string> hosts = new List<string>();
            if (parsedArgs.ContainsKey("/targets"))
            {
                List<string> targets = parsedArgs["/targets"][0].Split(',').ToList();
                hosts = hosts.Concat(targets).ToList();
                noHosts = false;
            }
            if (parsedArgs.ContainsKey("/ldap"))
            {
                List<string> ldap = SearchLDAP(parsedArgs["/ldap"][0].ToLower(), verbose);
                hosts = hosts.Concat(ldap).ToList();
                noHosts = false;
            }
            if (parsedArgs.ContainsKey("/ou"))
            {
                List<string> ou = SearchOU(parsedArgs["/ou"][0].ToLower(), verbose);
                hosts = hosts.Concat(ou).ToList();
                noHosts = false;
            }
            if (noHosts)
            {
                Console.WriteLine("[!] No hosts specified - use /targets, /ldap, or /ou flags");
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
                    listOfChecks.Add(() => SMB_Check(host, logons, verbose));
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

        //http://www.pinvoke.net/default.aspx/netapi32.netwkstauserenum
        public static void GetLoggedOnUsers(string hostname, bool verbose)
        {

            IntPtr bufptr = IntPtr.Zero;
            int dwEntriesread;
            int dwTotalentries = 0;
            int dwResumehandle = 0;
            int nStatus;
            Type tWui1 = typeof(WKSTA_USER_INFO_1);
            int nStructSize = Marshal.SizeOf(tWui1);
            WKSTA_USER_INFO_1 wui1;
            List<string> loggedOnUsers = new List<string>();

            do
            {
                //https://docs.microsoft.com/en-us/windows/win32/api/lmwksta/nf-lmwksta-netwkstauserenum
                //Lists users currently logged onto host
                //includes interactive, service, and batch logons
                nStatus = NetWkstaUserEnum(hostname, 1, out bufptr, 32768, out dwEntriesread, out dwTotalentries, ref dwResumehandle);

                // If the call succeeds,
                if ((nStatus == NERR_SUCCESS) | (nStatus == ERROR_MORE_DATA))
                {
                    if (dwEntriesread > 0)
                    {
                        IntPtr pstruct = bufptr;

                        // Loop through the entries.
                        for (int i = 0; i < dwEntriesread; i++)
                        {
                            wui1 = (WKSTA_USER_INFO_1)Marshal.PtrToStructure(pstruct, tWui1);
                            loggedOnUsers.Add(wui1.wkui1_logon_domain + "\\" + wui1.wkui1_username);
                            pstruct = (IntPtr)((long)pstruct + nStructSize);
                        }

                        //remove duplicate users
                        loggedOnUsers = loggedOnUsers.Distinct().ToList();
                        foreach (string user in loggedOnUsers)
                        {
                            Console.WriteLine("[session] {0} - {1}", hostname, user);
                        }
                    }
                    else
                    {
                        if (verbose)
                        {
                            Console.WriteLine("[!] A system error has occurred : " + nStatus);
                        }
                    }
                }

                if (bufptr != IntPtr.Zero)
                    NetApiBufferFree(bufptr);

            } while (nStatus == ERROR_MORE_DATA);
        }
        public static void GetRDPUsers(string hostname, bool verbose)
        {
            IntPtr serverHandle = IntPtr.Zero;
            List<string> resultList = new List<string>();
            serverHandle = WTSOpenServer(hostname);

            try
            {
                IntPtr sessionInfoPtr = IntPtr.Zero;
                IntPtr userPtr = IntPtr.Zero;
                IntPtr domainPtr = IntPtr.Zero;
                IntPtr wtsinfoPtr = IntPtr.Zero;
                Int32 sessionCount = 0;
                //https://docs.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenumeratesessionsa
                //Retrieves a list of sessions on a Remote Desktop Session Host (RD Session Host) server.
                Int32 retVal = WTSEnumerateSessions(serverHandle, 0, 1, ref sessionInfoPtr, ref sessionCount);
                Int32 dataSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                IntPtr currentSession = sessionInfoPtr;
                uint bytes = 0;
                List<string> sessions = new List<string>();
                string rdpSession = "";

                if (retVal != 0)
                {
                    //collect sessions - may contain duplicates
                    for (int i = 0; i < sessionCount; i++)
                    {
                        WTS_SESSION_INFO si = (WTS_SESSION_INFO)Marshal.PtrToStructure((System.IntPtr)currentSession, typeof(WTS_SESSION_INFO));
                        currentSession += dataSize;

                        WTSQuerySessionInformation(serverHandle, si.SessionID, WTS_INFO_CLASS.WTSUserName, out userPtr, out bytes);
                        WTSQuerySessionInformation(serverHandle, si.SessionID, WTS_INFO_CLASS.WTSDomainName, out domainPtr, out bytes);
                        WTSQuerySessionInformation(serverHandle, si.SessionID, WTS_INFO_CLASS.WTSSessionInfo, out wtsinfoPtr, out bytes);

                        string domain = Marshal.PtrToStringAnsi(domainPtr);
                        string username = Marshal.PtrToStringAnsi(userPtr);
                        var wtsinfo = (WTSINFOA)Marshal.PtrToStructure(wtsinfoPtr, typeof(WTSINFOA));
                        DateTime collecionTime = DateTime.FromFileTimeUtc(wtsinfo.CurrentTimeUTC);
                        DateTime lastInput = DateTime.FromFileTimeUtc(wtsinfo.LastInputTimeUTC);
                        TimeSpan idleTime = collecionTime - lastInput;
                        DateTime lastConnect = DateTime.FromFileTimeUtc(wtsinfo.ConnectTimeUTC);
                        TimeSpan lastSession = collecionTime - lastConnect;


                        // remove preceding "WTS" of status returned from WTS_CONNECTSTATE_CLASS
                        string status = String.Concat(si.State.ToString().Skip(3));
                        rdpSession = String.Format("{0}\\{1} rdp-tcp#{2} {3} Last Connection: {4} Last Input: {5}", domain, username, si.SessionID, status, lastSession.ToString("hh':'mm':'ss"), idleTime.ToString("hh':'mm':'ss"));
                        //if username is not null
                        if (!String.IsNullOrEmpty(Marshal.PtrToStringAnsi(userPtr)))
                        {
                            sessions.Add(rdpSession);
                        }
                        WTSFreeMemory(userPtr);
                        WTSFreeMemory(domainPtr);
                        WTSFreeMemory(wtsinfoPtr);
                    }

                    WTSFreeMemory(sessionInfoPtr);
                }
                //remove duplicate sessions
                sessions = sessions.Distinct().ToList();
                foreach (string session in sessions)
                {
                    Console.WriteLine("[rdp] {0} - {1}", hostname, session);
                }
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] RDP Session Collection Error: {0}", ex.Message);
                }
                WTSCloseServer(serverHandle);
                Environment.Exit(0);
            }
            finally
            {
                WTSCloseServer(serverHandle);
            }

        }

        public static List<string> SearchOU(string ou, bool verbose)
        {
            try
            {
                List<string> ComputerNames = new List<string>();
                string searchbase = "LDAP://" + ou;//OU=Domain Controllers,DC=example,DC=local";
                DirectoryEntry entry = new DirectoryEntry(searchbase);
                DirectorySearcher mySearcher = new DirectorySearcher(entry);
                mySearcher.PropertiesToLoad.Add("samaccountname");
                // filter for all enabled computers
                mySearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");
                mySearcher.SizeLimit = int.MaxValue;
                mySearcher.PageSize = int.MaxValue;
                foreach (SearchResult resEnt in mySearcher.FindAll())
                {
                    string ComputerName = resEnt.GetDirectoryEntry().Name;
                    if (ComputerName.StartsWith("CN="))
                        ComputerName = ComputerName.Remove(0, "CN=".Length);
                    ComputerNames.Add(ComputerName);
                }
                //localhost returns false positives
                ComputerNames.RemoveAll(u => u.Contains(System.Environment.MachineName));
                Console.WriteLine("[+] OU Search Results: {0}", ComputerNames.Count().ToString());
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
                mySearcher.PropertiesToLoad.Add("samaccountname");
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
                foreach (SearchResult resEnt in mySearcher.FindAll())
                {
                    string ComputerName = resEnt.GetDirectoryEntry().Name;
                    if (ComputerName.StartsWith("CN="))
                        ComputerName = ComputerName.Remove(0, "CN=".Length);
                    ComputerNames.Add(ComputerName);
                }
                //localhost returns false positives
                ComputerNames.RemoveAll(u => u.Contains(System.Environment.MachineName));
                Console.WriteLine("[+] LDAP Search Results: {0}", ComputerNames.Count.ToString());
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
        static void SMB_Check(string host, bool logons, bool verbose)
        {
            try
            {
                string share = "\\\\" + host + "\\C$";
                System.Security.AccessControl.DirectorySecurity ds = Directory.GetAccessControl(share);
                Console.WriteLine("[SMB] Admin Success: {0}", host);
                if (logons)
                {
                    GetLoggedOnUsers(host, verbose);
                    GetRDPUsers(host, verbose);
                }
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
    /logons   - return logged on users on a host (requires SMB)
    /targets  - comma-separated list of hostnames to check. If none provided, localhost will be checked.
    /threads  - specify maximum number of parallel threads (default=25)
    /validate - check credentials against Domain prior to scanning targets (useful during token manipulation)
    /verbose  - print additional logging information
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