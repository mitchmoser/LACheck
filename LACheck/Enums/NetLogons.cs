using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace LACheck.Enums
{
    class NetLogons
    {
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

                // If the call succeeds...
                if ((nStatus == NERR_SUCCESS) | (nStatus == ERROR_MORE_DATA))
                {
                    if (dwEntriesread > 0)
                    {
                        IntPtr pstruct = bufptr;

                        // ... loop through the entries.
                        for (int i = 0; i < dwEntriesread; i++)
                        {
                            wui1 = (WKSTA_USER_INFO_1)Marshal.PtrToStructure(pstruct, tWui1);
                            loggedOnUsers.Add(wui1.wkui1_logon_domain + "\\" + wui1.wkui1_username);
                            pstruct = (IntPtr)((long)pstruct + nStructSize);
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
            
            //remove duplicate users
            loggedOnUsers = loggedOnUsers.Distinct().ToList();
            foreach (string user in loggedOnUsers)
            {
                Console.WriteLine("[session] {0} - {1}", hostname, user);
            }
        }
    }
}
