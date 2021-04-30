using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace LACheck.Utilities
{
    class LDAP
    {
        public static string GetComputerSID(string host, bool verbose)
        {
            string SID = null;
            try
            {
                Forest currentForest = Forest.GetCurrentForest();
                GlobalCatalog globalCatalog = currentForest.FindGlobalCatalog();
                DirectorySearcher globalCatalogSearcher = globalCatalog.GetDirectorySearcher();

                globalCatalogSearcher.PropertiesToLoad.Add("objectsid");
                // filter for computer by samaccountname
                //globalCatalogSearcher.Filter = (String.Format("(&(objectCategory=computer)(samaccountname=*{0}*))", host));
                globalCatalogSearcher.Filter = (String.Format("(&(objectCategory=computer)(dnshostname=*{0}*))", host));
                globalCatalogSearcher.SizeLimit = int.MaxValue;
                globalCatalogSearcher.PageSize = int.MaxValue;

                foreach (SearchResult resEnt in globalCatalogSearcher.FindAll())
                {
                    SecurityIdentifier byteSID = new SecurityIdentifier((byte[])resEnt.Properties["objectSid"][0], 0);
                    SID = byteSID.ToString();
                }
                globalCatalogSearcher.Dispose();

                return SID;
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] LDAP Error: {0}", ex.Message);
                }
                return SID;
            }
        }
        public static string GetUserSID(string user, Utilities.Arguments arguments)
        {
            string SID = null;
            try
            {
                Forest currentForest = Forest.GetCurrentForest();
                GlobalCatalog globalCatalog = currentForest.FindGlobalCatalog();
                DirectorySearcher globalCatalogSearcher = globalCatalog.GetDirectorySearcher();

                globalCatalogSearcher.PropertiesToLoad.Add("objectsid");
                // filter for userprincipalname (format = username@domain.fqdn)
                globalCatalogSearcher.Filter = (String.Format("(&(objectCategory=user)(userprincipalname={0}))", user));
                globalCatalogSearcher.SizeLimit = int.MaxValue;
                globalCatalogSearcher.PageSize = int.MaxValue;

                if (globalCatalogSearcher.FindAll().Count <= 0)
                    Console.WriteLine($"[!] Unable to find SID for {user}. This will impact the accuracy of BloodHound's AdminTo information");

                foreach (SearchResult resEnt in globalCatalogSearcher.FindAll())
                {
                    SecurityIdentifier byteSID = new SecurityIdentifier((byte[])resEnt.Properties["objectSid"][0], 0);
                    SID = byteSID.ToString();
                }
                globalCatalogSearcher.Dispose();

                return SID;
            }
            catch (Exception ex)
            {
                if (arguments.verbose)
                {
                    Console.WriteLine("[!] LDAP Error: {0}", ex.Message);
                }
                return SID;
            }
        }
        public static Dictionary<string, string> GetUserSIDs(bool verbose)
        {
            Dictionary<string, string> users = new Dictionary<string, string>();

            Console.WriteLine("[+] Gathering Enabled Users...");
            try
            {
                Forest currentForest = Forest.GetCurrentForest();
                GlobalCatalog globalCatalog = currentForest.FindGlobalCatalog();
                DirectorySearcher globalCatalogSearcher = globalCatalog.GetDirectorySearcher();

                //userprincipalname = samaccountname@domain.fqdn format
                //does not exist for MSAs or built-in Administrator
                globalCatalogSearcher.PropertiesToLoad.Add("userprincipalname");
                //distinguishedname = CN=Administrator,CN=Users,DC=domain,DC=tld format
                globalCatalogSearcher.PropertiesToLoad.Add("distinguishedname");
                globalCatalogSearcher.PropertiesToLoad.Add("samaccountname");
                globalCatalogSearcher.PropertiesToLoad.Add("objectsid");

                //patterns to match domain fields in a distinguishedname
                //example distinguishedname: CN=Administrator,CN=Users,DC=domain,DC=tld
                string domainPattern = @"(?<=DC=)\w*";
                Regex domainRegex = new Regex(domainPattern);

                // filter for all enabled users & managed service accounts
                //globalCatalogSearcher.Filter = ("(&(objectCategory=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");
                globalCatalogSearcher.Filter = ("(&(|(objectclass=msDS-ManagedServiceAccount)(objectCategory=user))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");
                globalCatalogSearcher.SizeLimit = int.MaxValue;
                globalCatalogSearcher.PageSize = int.MaxValue;
                
                foreach (SearchResult resEnt in globalCatalogSearcher.FindAll())
                {
                    string UserName = null;
                    try
                    {
                        //works for standard user accounts - not Administrator or MSAs
                        UserName = resEnt.Properties["userprincipalname"][0].ToString();
                    }
                    catch 
                    {
                        //for Administrator and MSA accounts
                        string distinguishedname = resEnt.Properties["distinguishedname"][0].ToString();
                        string samaccountname = resEnt.Properties["samaccountname"][0].ToString();
                        //join all portions of domain in the distinguishedname
                        // DC=subdomian,DC=domain,DC=tld -> subdomain.domain.tld
                        string domain = String.Join(".", domainRegex.Matches(distinguishedname).Cast<Match>().Select(m => m.Value));
                        UserName = $"{samaccountname}@{domain}".ToLower();
                    }
                    if (!String.IsNullOrEmpty(UserName))
                    {
                        //UserName = resEnt.Properties["userprincipalname"][0].ToString();
                        SecurityIdentifier byteSID = new SecurityIdentifier((byte[])resEnt.Properties["objectSid"][0], 0);
                        string SID = byteSID.ToString();
                        users.Add(UserName, SID);
                        //Console.WriteLine($"---({users.Count.ToString()}) {UserName}:{SID}");
                    }
                }

                Console.WriteLine($"[+] Enabled Users returned: {users.Count.ToString()}");
                globalCatalogSearcher.Dispose();
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] LDAP Error Getting User SIDs: {0}", ex.Message);
                return null;
            }

            return users;
        }
        public static Dictionary<string, string> SearchOU(string ou, bool verbose)
        {
            try
            {
                Dictionary<string, string> hosts = new Dictionary<string, string>();
                string searchbase = "LDAP://" + ou;//OU=Domain Controllers,DC=example,DC=local";
                DirectoryEntry entry = new DirectoryEntry(searchbase);
                DirectorySearcher mySearcher = new DirectorySearcher(entry);
                //mySearcher.PropertiesToLoad.Add("cn");
                mySearcher.PropertiesToLoad.Add("dnshostname");
                mySearcher.PropertiesToLoad.Add("objectsid");
                // filter for all enabled computers
                mySearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");
                mySearcher.SizeLimit = int.MaxValue;
                mySearcher.PageSize = int.MaxValue;
                foreach (SearchResult resEnt in mySearcher.FindAll())
                {
                    
                    //string ComputerName = resEnt.Properties["cn"][0].ToString();
                    string ComputerName = resEnt.Properties["dnshostname"][0].ToString().ToUpper();
                    SecurityIdentifier byteSID = new SecurityIdentifier((byte[])resEnt.Properties["objectSid"][0], 0);
                    string SID = byteSID.ToString();
                    hosts.Add(ComputerName, SID);
                }
                //localhost returns false positives
                hosts.Remove(System.Environment.MachineName);
                Console.WriteLine("[+] OU Search Results: {0}", hosts.Count().ToString());
                mySearcher.Dispose();
                entry.Dispose();

                return hosts;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] LDAP Error: {0}", ex.Message);
                return null;
            }
        }
        public static Dictionary<string, string> SearchLDAP(string filter, bool verbose)
        {
            try
            {
                Dictionary<string, string> hosts = new Dictionary<string, string>();
                string description = "";

                Forest currentForest = Forest.GetCurrentForest();
                GlobalCatalog globalCatalog = currentForest.FindGlobalCatalog();
                DirectorySearcher globalCatalogSearcher = globalCatalog.GetDirectorySearcher();

                //globalCatalogSearcher.PropertiesToLoad.Add("cn");
                globalCatalogSearcher.PropertiesToLoad.Add("dnshostname");
                globalCatalogSearcher.PropertiesToLoad.Add("objectsid");
                //https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx
                //https://ldapwiki.com/wiki/Active%20Directory%20Computer%20Related%20LDAP%20Query
                switch (filter)
                {
                    case "all":
                        description = "all enabled computers with \"primary\" group \"Domain Computers\"";
                        globalCatalogSearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");
                        break;
                    case "dc":
                        description = "all enabled Domain Controllers (not read-only DCs)";
                        globalCatalogSearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=8192))");
                        break;
                    case "exclude-dc":
                        description = "all enabled computers that are not Domain Controllers or read-only DCs";
                        globalCatalogSearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67100867)))");
                        break;
                    case "servers":
                        description = "all enabled servers";
                        globalCatalogSearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*))");
                        break;
                    case "servers-exclude-dc":
                        description = "all enabled servers excluding Domain Controllers or read-only DCs";
                        globalCatalogSearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67100867)))");
                        break;
                    default:
                        Console.WriteLine("[!] Invalid LDAP filter: {0}", filter);
                        Utilities.Options.Usage();
                        Environment.Exit(0);
                        break;
                }

                globalCatalogSearcher.SizeLimit = int.MaxValue;
                globalCatalogSearcher.PageSize = int.MaxValue;
                Console.WriteLine("[+] Performing LDAP query for {0}...", description);
                Console.WriteLine("[+] This may take some time depending on the size of the environment");
                
                foreach (SearchResult resEnt in globalCatalogSearcher.FindAll())
                {
                    //string ComputerName = resEnt.Properties["cn"][0].ToString();
                    string ComputerName = resEnt.Properties["dnshostname"][0].ToString().ToUpper();
                    SecurityIdentifier byteSID = new SecurityIdentifier((byte[])resEnt.Properties["objectSid"][0], 0);
                    string SID = byteSID.ToString();
                    hosts.Add(ComputerName, SID);
                }

                //localhost returns false positives
                hosts.Remove(System.Environment.MachineName);
                Console.WriteLine("[+] LDAP Search Results: {0}", hosts.Count.ToString());
                globalCatalogSearcher.Dispose();

                return hosts;
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
    }
}
