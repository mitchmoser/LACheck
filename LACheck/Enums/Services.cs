using System;
using System.ComponentModel;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Xml.Linq;
using WSManAutomation; //Add Reference -> windows\system32\wsmauto.dll (or COM: Microsoft WSMan Automation V 1.0 Library)


namespace LACheck.Enums
{
    class Services
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct QueryServiceConfigStruct
        {
            public int serviceType;
            public int startType;
            public int errorControl;
            public IntPtr binaryPathName;
            public IntPtr loadOrderGroup;
            public int tagID;
            public IntPtr dependencies;
            public IntPtr startName;
            public IntPtr displayName;
        }
        public struct ServiceInfo
        {
            public int serviceType;
            public int startType;
            public int errorControl;
            public string binaryPathName;
            public string loadOrderGroup;
            public int tagID;
            public string dependencies;
            public string startName;
            public string displayName;
        }
        private enum SCManagerAccess : int
        {
            GENERIC_ALL = 0x10000000
        }
        private enum ServiceAccess : int
        {
            QUERY_CONFIG = 0x1,
            CHANGE_CONFIG = 0x2,
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr OpenSCManager(
            [MarshalAs(UnmanagedType.LPTStr)] string machineName,
            [MarshalAs(UnmanagedType.LPTStr)] string databaseName,
            int desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr OpenService(
            IntPtr scManager,
            [MarshalAs(UnmanagedType.LPTStr)] string serviceName,
            int desiredAccess);

        [DllImport("advapi32.dll",
        SetLastError = true, CharSet = CharSet.Auto)]
        private static extern int ChangeServiceConfig(
            IntPtr service,
            int serviceType,
            int startType,
            int errorControl,
            [MarshalAs(UnmanagedType.LPTStr)] string binaryPathName,
            [MarshalAs(UnmanagedType.LPTStr)] string loadOrderGroup,
            IntPtr tagID,
            [MarshalAs(UnmanagedType.LPTStr)] string dependencies,
            [MarshalAs(UnmanagedType.LPTStr)] string startName,
            [MarshalAs(UnmanagedType.LPTStr)] string password,
            [MarshalAs(UnmanagedType.LPTStr)] string displayName);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern int QueryServiceConfig(
            IntPtr service,
            IntPtr queryServiceConfig,
            int bufferSize,
            ref int bytesNeeded);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern Boolean ChangeServiceConfig(
            IntPtr hService,
            UInt32 nServiceType,
            UInt32 nStartType,
            UInt32 nErrorControl,
            String lpBinaryPathName,
            String lpLoadOrderGroup,
            IntPtr lpdwTagId,
            [In] char[] lpDependencies,
            String lpServiceStartName,
            String lpPassword,
            String lpDisplayName);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", EntryPoint = "CloseServiceHandle")]
        public static extern int CloseServiceHandle(IntPtr hSCObject);

        //list of user accounts running services to exclude from results
        public static string[] exclusions = { "LOCALSYSTEM", "NT AUTHORITY\\LOCALSERVICE", "NT AUTHORITY\\NETWORKSERVICE" };

        private const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
        private const uint SERVICE_QUERY_CONFIG = 0x00000001;
        private const uint SERVICE_CHANGE_CONFIG = 0x00000002;
        private const uint SC_MANAGER_ALL_ACCESS = 0x000F003F;
        public static void GetServicesSMB(string host, bool verbose)
        {
            try
            {
                ServiceController[] services = ServiceController.GetServices(host);
                foreach (ServiceController service in services)
                {
                    //get user running service
                    ServiceInfo svcInfo = GetServiceInfo(service.ServiceName, host, verbose);
                    if (!String.IsNullOrEmpty(svcInfo.startName) && !exclusions.Contains(svcInfo.startName.ToUpper()))
                    {
                        Console.WriteLine("[service] {0} - {1} Service: {2} State: {3}", host, svcInfo.startName, service.ServiceName, service.Status);
                    }
                }
                
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] {0} - Unable to query services: {1}", host, ex.Message);
                }
            }
        }
        public static void GetServicesWinRM(string host, bool verbose)
        {
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
                //https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service
                string resource = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/*";
                string wql = "SELECT name,displayname,startname,state,systemname FROM Win32_Service WHERE startname IS NOT NULL";
                string dialect = "http://schemas.microsoft.com/wbem/wsman/1/WQL";
                IWSManEnumerator response = winrm.Enumerate(resource, wql, dialect);
                // Enumerate returned CIM instances.
                while (!response.AtEndOfStream)
                {
                    string item = response.ReadItem();
                    XDocument doc = XDocument.Parse(item);
                    string startName = doc.Descendants("StartName").First().Value;
                    // Exclude services running as local accounts
                    if (!exclusions.Contains(startName.ToUpper()))
                    {
                        string systemName = doc.Descendants("SystemName").First().Value;
                        string name = doc.Descendants("Name").First().Value;
                        string state = doc.Descendants("State").First().Value;
                        Console.WriteLine("[service] {0} - {1} Service: {2} State: {3}",
                                           systemName,
                                           startName,
                                           name,
                                           state
                                         );
                    }
                }
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] {0} - Unable to query services over WinRM: {1}", host, ex.Message);
                }
            }
        }
        public static void GetServicesWMI(string host, string ns, bool verbose)
        {
            ManagementScope scope = new ManagementScope(string.Format(@"\\{0}\{1}", host, ns));

            //https://docs.microsoft.com/en-us/windows/win32/wmisdk/wql-operators
            //https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service
            SelectQuery query = new SelectQuery("SELECT name,displayname,startname,state,systemname FROM Win32_Service WHERE startname IS NOT NULL");

            try
            {
                scope.Connect();
                //https://stackoverflow.com/questions/842533/in-c-sharp-how-do-i-query-the-list-of-running-services-on-a-windows-server
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query))
                {
                    ManagementObjectCollection services = searcher.Get();
                    foreach (ManagementObject service in services)
                    {
                        // Exclude services running as local accounts
                        if (!exclusions.Contains(service["StartName"].ToString().ToUpper()))
                        {
                            Console.WriteLine("[service] {0} - {1} Service: {2} State: {3}",
                                               service["SystemName"], 
                                               service["StartName"], 
                                               service["Name"],
                                               service["State"]
                                             );
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] {0} - Unable to query services over WMI: {1}", host, ex.Message);
                }
            }
        }
        //https://bytes.com/topic/c-sharp/answers/227755-servicecontroller-class-startup-type
        public static ServiceInfo GetServiceInfo(string ServiceName, string host, bool verbose)
        {
            ServiceInfo serviceInfo = new ServiceInfo();
            try
            {
                if (ServiceName.Equals(""))
                    throw new NullReferenceException("ServiceName must contain a valid service name.");
                IntPtr scManager = OpenSCManager(host, null, (int)SCManagerAccess.GENERIC_ALL);
                if (scManager.ToInt32() <= 0)
                    throw new Win32Exception();

                IntPtr service = OpenService(scManager, ServiceName, (int)ServiceAccess.QUERY_CONFIG);
                if (service.ToInt32() <= 0)
                    throw new NullReferenceException();

                int bytesNeeded = 5;
                QueryServiceConfigStruct qscs = new QueryServiceConfigStruct();
                IntPtr qscPtr = Marshal.AllocCoTaskMem(0);

                int retCode = QueryServiceConfig(service, qscPtr, 0, ref bytesNeeded);
                if (retCode == 0 && bytesNeeded == 0)
                {
                    throw new Win32Exception();
                }
                else
                {
                    qscPtr = Marshal.AllocCoTaskMem(bytesNeeded);
                    retCode = QueryServiceConfig(service, qscPtr, bytesNeeded, ref bytesNeeded);
                    if (retCode == 0)
                    {
                        throw new Win32Exception();
                    }
                    qscs.binaryPathName = IntPtr.Zero;
                    qscs.dependencies = IntPtr.Zero;
                    qscs.displayName = IntPtr.Zero;
                    qscs.loadOrderGroup = IntPtr.Zero;
                    qscs.startName = IntPtr.Zero;

                    qscs = (QueryServiceConfigStruct)
                    Marshal.PtrToStructure(qscPtr, new QueryServiceConfigStruct().GetType());
                }

                serviceInfo.binaryPathName = Marshal.PtrToStringAuto(qscs.binaryPathName);
                serviceInfo.dependencies = Marshal.PtrToStringAuto(qscs.dependencies);
                serviceInfo.displayName = Marshal.PtrToStringAuto(qscs.displayName);
                serviceInfo.loadOrderGroup = Marshal.PtrToStringAuto(qscs.loadOrderGroup);
                serviceInfo.startName = Marshal.PtrToStringAuto(qscs.startName);

                serviceInfo.errorControl = qscs.errorControl;
                serviceInfo.serviceType = qscs.serviceType;
                serviceInfo.startType = qscs.startType;
                serviceInfo.tagID = qscs.tagID;

                Marshal.FreeCoTaskMem(qscPtr);
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] {0} - Unable to get service information: {1}", host, ex.Message);
                }
            }
            return serviceInfo;
        }
        public static int GetStartType(ServiceController svc, string host, bool verbose)
        {
            ServiceInfo svcInfo = GetServiceInfo(svc.ServiceName, host, verbose);
            /*string startType;
            //https://docs.microsoft.com/en-us/dotnet/api/system.serviceprocess.servicestartmode
            switch (svcInfo.startType)
            {
                case 0:
                    startType = "Boot";
                    break;
                case 1:
                    startType = "System";
                    break;
                case 2:
                    startType = "Automatic";
                    break;
                case 3:
                    startType = "Manual";
                    break;
                case 4:
                    startType = "Disabled";
                    break;
                default:
                    startType = "undefined";
                    break;
            }
            Console.WriteLine("StartType: {0}", startType);
            */
            return svcInfo.startType;
        }
        public static bool RemoteRegistryStatus(string host, bool verbose)
        {
            //Remote Registry needs to be running in order to enumerate registry hives
            //indicate if a reconfiguration of Remote Registry is required
            bool reconfig = false;
            try
            {
                ServiceController remoteRegistry = new ServiceController("Remote Registry", host);
                if (verbose)
                {
                    Console.WriteLine("[!] {0} - {1} Status: {2}", host, remoteRegistry.DisplayName, remoteRegistry.Status);
                }
                if (remoteRegistry.Status == ServiceControllerStatus.Stopped)
                {
                    reconfig = true;
                }
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] {0} - Unable to query services: {1}", host, ex.Message);
                }
            }
            return reconfig;
        }
        public static void StartRemoteRegistry(ServiceController remoteRegistry, string host, bool verbose)
        {
            try
            {
                remoteRegistry.Start();
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] {0} - Unable to start Remote Registry service: {1}", host, ex.Message);
                }
            }
        }
        public static void StopRemoteRegistry(ServiceController remoteRegistry, string host, bool verbose)
        {
            try
            {
                TimeSpan timeout = TimeSpan.FromSeconds(5);
                remoteRegistry.WaitForStatus(ServiceControllerStatus.Running, timeout);
                if (verbose)
                {
                    Console.WriteLine("[!] {0} - Remote Registry running...", host);
                }
                remoteRegistry.Stop();
                if (verbose)
                {
                    Console.WriteLine("[!] {0} - Stopping Remote Registry...", host);
                }
                remoteRegistry.WaitForStatus(ServiceControllerStatus.Stopped, timeout);
                if (verbose)
                {
                    Console.WriteLine("[!] {0} - Remote Registry stopped", host);
                }
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] {0} - Unable to stop Remote Registry service: {1}", host, ex.Message);
                }
            }
        }
        
        //http://peterkellyonline.blogspot.com/2011/04/configuring-windows-service.html
        public static void ChangeStartMode(ServiceController svc, ServiceStartMode mode, string host)
        {
            var scManagerHandle = OpenSCManager(host, null, SC_MANAGER_ALL_ACCESS);
            if (scManagerHandle == IntPtr.Zero)
            {
                throw new ExternalException("Open Service Manager Error");
            }

            var serviceHandle = OpenService(
                scManagerHandle,
                svc.ServiceName,
                SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG);

            if (serviceHandle == IntPtr.Zero)
            {
                throw new ExternalException("Open Service Error");
            }

            var result = ChangeServiceConfig(
                serviceHandle,
                SERVICE_NO_CHANGE,
                (uint)mode,
                SERVICE_NO_CHANGE,
                null,
                null,
                IntPtr.Zero,
                null,
                null,
                null,
                null);

            if (result == false)
            {
                int nError = Marshal.GetLastWin32Error();
                var win32Exception = new Win32Exception(nError);
                throw new ExternalException("[!] Could not change service start type: " + win32Exception.Message);
            }

            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scManagerHandle);
        }
    }
}
