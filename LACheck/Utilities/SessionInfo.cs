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
            Dictionary<string, string> users = Utilities.LDAP.GetUserSIDs(arguments.verbose);
            List<UserSession> unresolvable = new List<UserSession>();
            foreach (ComputerSessions comp in AllComputerSessions.computers)
            {
                //Console.WriteLine($"---Host: {comp.hostname} SID: {hosts[comp.hostname]}");
                comp.computerSID = hosts[comp.hostname];
                foreach (UserSession sess in comp.sessions)
                {
                    //reconstruct userprincipalname format of username@fqdn missing TLD
                    string partialuserprincipalname = String.Format("{0}@{1}", sess.username, sess.domain).ToLower();
                    
                    //try resolving enumerated users to SIDs of enabled users
                    if (users.Keys.Any(k => k.StartsWith(partialuserprincipalname)))
                    {
                        sess.SID = users[users.Keys.Where(k => k.StartsWith(partialuserprincipalname)).FirstOrDefault()];
                        //Console.WriteLine($"---User {sess.domain}\\{sess.username}:{sess.SID}");
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
