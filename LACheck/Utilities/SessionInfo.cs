using System;
using System.Collections.Generic;
using System.Linq;

namespace LACheck.Utilities
{
    class SessionInfo
    {
        /*
         * LACheck enumerates multiple hosts
         * Each host may have multiple sessions
         * Each UserSession object is stored in a list within a ComputerSessions
         * All ComputerSessions objects are stored in a single AllComputerSessions Object
         */
        public class UserSession
        {
            public string username;
            public string domain;
            public string SID;
            /*
            // todo: use other LACheck enumeration in BloodHound format
            public string edr;
            //*/
        }
        public class ComputerSessions
        {
            public string hostname;
            public string computerSID;
            public List<UserSession> sessions = new List<UserSession>();
        }
        public class AllComputerSessions
        {
            public static List<ComputerSessions> computers = new List<ComputerSessions>();
        }
        public static void ResolveSIDs(Dictionary<string, string> hosts, Utilities.Arguments arguments)
        {
            /* Given a dictionary of host:SID pairs
             * Each enumerated host is looped through to resolve a hostname to a SID
             * Each session on the host resolves the user to an enabled user's SID
             * Any user that does not resolve to a SID is removed from the session list
             */
            Dictionary<string, string> users = Utilities.LDAP.GetUserSIDs(arguments);
            List<UserSession> unresolvable = new List<UserSession>();
            foreach (ComputerSessions comp in AllComputerSessions.computers)
            {
                //Console.WriteLine($"---Host: {comp.hostname} SID: {hosts[comp.hostname]}");
                comp.computerSID = hosts[comp.hostname];
                foreach (UserSession sess in comp.sessions)
                {
                    string netbiosuser = $"{sess.domain}\\{sess.username}".ToLower();
                    if (users.Keys.Contains(netbiosuser))
                    {
                        sess.SID = users[netbiosuser];
                        //Console.WriteLine($"---User: {netbiosuser} SID: {sess.SID}");
                    }
                    
                    //enumerated users that don't resolve will be removed
                    else
                    {
                        unresolvable.Add(sess);
                    }
                }
                //remove any enumerated users that don't match keys of enabled users
                foreach (UserSession sess in unresolvable)
                {
                    comp.sessions.Remove(sess);
                }
            }
        }
    }
}
