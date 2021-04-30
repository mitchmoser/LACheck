using ICSharpCode.SharpZipLib.Zip;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace LACheck.Utilities
{
    class BloodHound
    {
        public class BloodHoundOutput
        {
            public List<Computer> computers = new List<Computer>();
            public Meta meta;
        }
        public class Computer
        {
            public Props Properties = new Props();
            public string[] AllowedToDelegate = new string[0];
            public string[] AllowedToAct = new string[0];
            public string PrimaryGroupSid = null;
            public List<SessionObj> Sessions = new List<SessionObj>();
            public List<LocalAdminObj> LocalAdmin = new List<LocalAdminObj>();
            public string[] RemoteDesktopUsers = new string[0];
            public string[] DcomUsers = new string[0];
            public string[] PSRemoteUsers = new string[0];
            public string ObjectIdentifier = null;
            public string[] Aces = new string[0];
        }
        public class Props
        {
            /*
            public bool haslaps;
            public bool highvalue;
            public string name;
            public string domain;
            public string objectid;
            public string distinguishedname;
            public string description;
            public bool enabled;
            public bool unconstraineddelegation;
            public string[] serviceprincipalnames;
            public DateTime lastlogontimestamp;
            public DateTime pwdlastset;
            public string operatingsystem;
            */
        }
        public class SessionObj
        {
            public string UserId;
            public string ComputerId;
        }
        public class LocalAdminObj
        {
            public string MemberId;
            public string MemberType = "User";
        }
        public class Meta
        {
            public int count;
            public string type = "computers";
            public int version = 3;
        }
        
        public class LACheckSessions
        {
            public static List<string> AdminSuccess = new List<string>();
        }
        public static void PrintOutput(Dictionary<string, string> hosts, Utilities.Arguments arguments)
        {
            string userSID = Utilities.LDAP.GetUserSID(arguments.user, arguments);
            List<Computer> jsonComputers = new List<Computer>();

            foreach (KeyValuePair<string, string> computer in hosts)
            {
                Computer comp = new Computer();

                string compSID = computer.Value;
                comp.ObjectIdentifier = compSID;

                comp.Sessions = new List<SessionObj>();
                SessionObj s = new SessionObj();

                var hostname = Utilities.SessionInfo.AllComputerSessions.computers.Where(c => c.hostname.Equals(computer.Key));

                //for each session enumerated                
                foreach (Utilities.SessionInfo.ComputerSessions host in hostname)
                {
                    //Console.WriteLine($"***Host {host.hostname}:{host.computerSID}");
                    foreach (Utilities.SessionInfo.UserSession sess in host.sessions)
                    {
                        //Console.WriteLine($"***User {sess.domain}\\{sess.username}:{sess.SID}");
                        s.UserId = sess.SID;
                        s.ComputerId = host.computerSID;
                        comp.Sessions.Add(s);
                    }
                }

                LocalAdminObj admin = new LocalAdminObj();
                //for user LACheck runs as
                if (Utilities.BloodHound.LACheckSessions.AdminSuccess.Contains(computer.Key))
                {
                    admin.MemberId = userSID;
                    comp.LocalAdmin.Add(admin);
                }

                jsonComputers.Add(comp);
            }

            BloodHoundOutput bh = new BloodHoundOutput();
            bh.computers = new List<Computer>();
            foreach (Computer computerBlob in jsonComputers)
            {
                bh.computers.Add(computerBlob);
            }
            bh.meta = new Meta();
            bh.meta.count = bh.computers.Count();

            //string prettyOutput = JsonConvert.SerializeObject(bh, Formatting.Indented);
            //Console.WriteLine(prettyOutput);

            string output = JsonConvert.SerializeObject(bh);

            /* try to write output in multiple places in case of permissions errors
             * 1) current directory
             * 2) C:\Users\<current user>\AppData\Local\Temp\
             * 3) C:\Users\Public\
             */
            List<string> outFileNames = new List<string>();
            outFileNames.Add(Path.GetRandomFileName()); 
            outFileNames.Add(Path.GetTempPath() + Path.GetRandomFileName());
            outFileNames.Add("C:\\Users\\Public\\" + Path.GetRandomFileName());
            
            foreach (string fileName in outFileNames)
            {
                try
                {
                    using (var zipStream = new ZipOutputStream(File.Create(fileName)))
                    {
                        //Set level to 9, maximum compressions
                        zipStream.SetLevel(9);
                        string password = Path.GetRandomFileName().Split('.')[0];
                        zipStream.Password = password;
                        Console.WriteLine($"Compressing zip files to {fileName}");

                        //random name for session collection file within zip archive
                        ZipEntry entry = new ZipEntry(Path.GetRandomFileName());
                        entry.DateTime = DateTime.Now;
                        zipStream.PutNextEntry(entry);

                        //convert json output to byte array
                        byte[] outBytes = Encoding.ASCII.GetBytes(output);
                        zipStream.Write(outBytes, 0, outBytes.Length);
                        zipStream.Finish();
                        zipStream.Close();

                        Console.WriteLine($"Password for Zip file is {password} unzip files manually to upload to interface");
                        break;
                    }
                }
                catch
                {
                    Console.WriteLine($"[!] Unable to write file to {fileName}");
                }
            }
        }
    }
}
