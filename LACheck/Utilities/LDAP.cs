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
        public static Dictionary<string, string> GetNetbiosDomain()
        {

            try
            {
                //example distinguishedname: DC=child,DC=domain,DC=tld
                string domainPattern = @"(?<=DC=)\w*";
                Regex domainRegex = new Regex(domainPattern);
                
                //netbios:fqdn key:value pairs
                Dictionary<string, string> netbiosToDomain = new Dictionary<string, string>();

                Forest currentForest = Forest.GetCurrentForest();
                GlobalCatalog globalCatalog = currentForest.FindGlobalCatalog();
                DirectorySearcher globalCatalogSearcher = globalCatalog.GetDirectorySearcher();

                globalCatalogSearcher.Filter = ("objectClass=domain");
                globalCatalogSearcher.PropertiesToLoad.Add("distinguishedname");
                globalCatalogSearcher.PropertiesToLoad.Add("name");
                globalCatalogSearcher.SizeLimit = int.MaxValue;
                globalCatalogSearcher.PageSize = int.MaxValue;

                foreach (SearchResult resultEntry in globalCatalogSearcher.FindAll())
                {
                    string netbios = resultEntry.Properties["name"][0].ToString().ToUpper();
                    string distinguishedname = resultEntry.Properties["distinguishedname"][0].ToString();

                    // DC=subdomian,DC=domain,DC=tld -> subdomain.domain.tld
                    string domain = String.Join(".", domainRegex.Matches(distinguishedname).Cast<Match>().Select(m => m.Value));
                    Console.WriteLine($"[+] Domain Found: {netbios} = {domain}");
                    netbiosToDomain.Add(netbios, domain);
                }
                globalCatalogSearcher.Dispose();
                globalCatalogSearcher.Dispose();
                return netbiosToDomain;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] LDAP Error: {0}", ex.Message);
                return null;
            }
        }
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
                // filter for userprincipalname (format = samaccountname@domain.fqdn)
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
                //globalCatalogSearcher.PropertiesToLoad.Add("userprincipalname");
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
                globalCatalogSearcher.Filter = ("(&(|(objectclass=msDS-ManagedServiceAccount)(objectCategory=user))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(samaccountname=*)(distinguishedname=*)(objectsid=*))");
                globalCatalogSearcher.SizeLimit = int.MaxValue;
                globalCatalogSearcher.PageSize = int.MaxValue;
                
                foreach (SearchResult resEnt in globalCatalogSearcher.FindAll())
                {
                    string UserName = null;
                    string samaccountname = null;
                    string distinguishedname = null;
                    try
                    {
                        samaccountname = resEnt.Properties["samaccountname"][0].ToString();
                        distinguishedname = resEnt.Properties["distinguishedname"][0].ToString();
                        //join all portions of domain in the distinguishedname
                        // DC=subdomian,DC=domain,DC=tld -> subdomain.domain.tld
                        string domain = String.Join(".", domainRegex.Matches(distinguishedname).Cast<Match>().Select(m => m.Value));
                        UserName = $"{samaccountname}@{domain}".ToLower();
                        
                        if (!String.IsNullOrEmpty(UserName))
                        {
                            try
                            {
                                SecurityIdentifier byteSID = new SecurityIdentifier((byte[])resEnt.Properties["objectSid"][0], 0);
                                string SID = byteSID.ToString();
                                users.Add(UserName, SID);
                                //Console.WriteLine($"---({users.Count.ToString()}) {UserName}:{SID}");
                            }
                            catch
                            {
                                Console.WriteLine($"[!] LDAP Error Retrieving SID for {UserName}. No sessions will be correlated for this user.");
                            }
                        }
                    }
                    catch 
                    {
                        Console.WriteLine($"[!] LDAP Error Retrieving User Information for {samaccountname}. No sessions will be correlated for this user.");
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

                mySearcher.Dispose();
                entry.Dispose();

                //localhost returns false positives
                hosts.Remove(System.Environment.MachineName);
                // remove localhost where domain name is appended which breaks literal string matches
                IEnumerable<string> startsWithHostname = hosts.Keys.Where(currentKey => currentKey.StartsWith(System.Environment.MachineName.ToUpper()));
                foreach (string partialMatch in startsWithHostname.ToList())
                {
                    hosts.Remove(partialMatch);
                }
                Console.WriteLine("[+] OU Search Results: {0}", hosts.Count().ToString());

                return hosts;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] LDAP Error: {0}", ex.Message);
                return null;
            }
        }
        public static Dictionary<string, string> SearchLDAP(string ldap, bool verbose)
        {
            bool searchGlobalCatalog = true;
            string description = null;
            string filter = null;
            
            Dictionary<string, string> hosts = new Dictionary<string, string>();
            
            switch (ldap)
            {
                case "all":
                    description = "all enabled computers with \"primary\" group \"Domain Computers\"";
                    filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");
                    break;
                case "dc":
                    description = "all enabled Domain Controllers (not read-only DCs)";
                    filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=8192))");
                    break;
                case "exclude-dc":
                    description = "all enabled computers that are not Domain Controllers or read-only DCs";
                    filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67100867)))");
                    break;
                case "servers":
                    searchGlobalCatalog = false; //operatingSystem attribute is not replicated in Global Catalog
                    description = "all enabled servers";
                    filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*))");
                    break;
                case "servers-exclude-dc":
                    searchGlobalCatalog = false; //operatingSystem attribute is not replicated in Global Catalog
                    description = "all enabled servers excluding Domain Controllers or read-only DCs";
                    filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67100867)))");
                    break;
                default:
                    Console.WriteLine("[!] Invalid LDAP filter: {0}", filter);
                    Utilities.Options.Usage();
                    Environment.Exit(0);
                    break;
            }
            if (searchGlobalCatalog)
            {
                try
                {
                    Forest currentForest = Forest.GetCurrentForest();
                    GlobalCatalog globalCatalog = currentForest.FindGlobalCatalog();
                    DirectorySearcher globalCatalogSearcher = globalCatalog.GetDirectorySearcher();

                    //globalCatalogSearcher.PropertiesToLoad.Add("cn");
                    globalCatalogSearcher.PropertiesToLoad.Add("dnshostname");
                    globalCatalogSearcher.PropertiesToLoad.Add("objectsid");
                    //https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx
                    //https://ldapwiki.com/wiki/Active%20Directory%20Computer%20Related%20LDAP%20Query
                    globalCatalogSearcher.Filter = filter;
                    globalCatalogSearcher.SizeLimit = int.MaxValue;
                    globalCatalogSearcher.PageSize = int.MaxValue;
                    Console.WriteLine("[+] Performing LDAP query against Global Catalog for {0}...", description);
                    Console.WriteLine("[+] This may take some time depending on the size of the environment");

                    foreach (SearchResult resEnt in globalCatalogSearcher.FindAll())
                    {
                        //sometimes objects with empty attributes throw errors
                        try
                        {
                            //string ComputerName = resEnt.Properties["cn"][0].ToString();
                            string ComputerName = resEnt.Properties["dnshostname"][0].ToString().ToUpper();
                            SecurityIdentifier byteSID = new SecurityIdentifier((byte[])resEnt.Properties["objectSid"][0], 0);
                            string SID = byteSID.ToString();
                            hosts.Add(ComputerName, SID);
                        }
                        catch { /*nothing*/ }
                    }
                    globalCatalogSearcher.Dispose();
                }
                catch (Exception ex)
                {
                    if (verbose)
                    {
                        Console.WriteLine("[!] LDAP Error searching Global Catalog: {0}", ex.Message);
                    }
                }
            }
            else
            {
                Console.WriteLine("not searching global catalog");
                try
                {
                    DirectoryEntry entry = new DirectoryEntry();
                    DirectorySearcher mySearcher = new DirectorySearcher(entry);

                    //globalCatalogSearcher.PropertiesToLoad.Add("cn");
                    mySearcher.PropertiesToLoad.Add("dnshostname");
                    mySearcher.PropertiesToLoad.Add("objectsid");
                    //https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx
                    //https://ldapwiki.com/wiki/Active%20Directory%20Computer%20Related%20LDAP%20Query
                    mySearcher.Filter = filter;
                    mySearcher.SizeLimit = int.MaxValue;
                    mySearcher.PageSize = int.MaxValue;
                    Console.WriteLine("[+] Performing LDAP query against the current domain for {0}...", description);
                    Console.WriteLine("[+] This may take some time depending on the size of the environment");

                    foreach (SearchResult resEnt in mySearcher.FindAll())
                    {
                        //sometimes objects with empty attributes throw errors
                        try
                        {
                            //string ComputerName = resEnt.Properties["cn"][0].ToString();
                            string ComputerName = resEnt.Properties["dnshostname"][0].ToString().ToUpper();
                            SecurityIdentifier byteSID = new SecurityIdentifier((byte[])resEnt.Properties["objectSid"][0], 0);
                            string SID = byteSID.ToString();
                            hosts.Add(ComputerName, SID);
                        }
                        catch { /*nothing*/ }
                    }
                    mySearcher.Dispose();
                }
                catch (Exception ex)
                {
                    if (verbose)
                    {
                        Console.WriteLine("[!] LDAP Error: {0}", ex.Message);
                    }
                }
            }
            //localhost returns false positives
            hosts.Remove(System.Environment.MachineName);
            // remove localhost where domain name is appended which breaks literal string matches
            IEnumerable<string> startsWithHostname = hosts.Keys.Where(currentKey => currentKey.StartsWith(System.Environment.MachineName.ToUpper()));
            foreach (string partialMatch in startsWithHostname.ToList())
            {
                hosts.Remove(partialMatch);
            }

            Console.WriteLine("[+] LDAP Search Results: {0}", hosts.Count.ToString());

            return hosts;
        }
    }
}
