# LACheck
Multithreaded C# .NET Assembly Local Administrative Privilege Enumeration 

### Arguments
```
> ./LACheck.exe help
  _                  _____ _               _
 | |        /\      / ____| |             | |
 | |       /  \    | |    | |__   ___  ___| | __
 | |      / /\ \   | |    | '_ \ / _ \/ __| |/ /
 | |____ / ____ \  | |____| | | |  __/ (__|   <
 |______/_/    \_\  \_____|_| |_|\___|\___|_|\_\

Usage:
    LACheck.exe smb rpc /ldap:servers-exclude-dc /targets:hostname,fqdn.domain.tld,10.10.10.10 /verbose /validate

Local Admin Checks:
    smb   - Attempts to access C$ share
    rpc   - Attempts WMI query of Win32_ComputerSystem Class provider over RPC
    winrm - Attempts WMI query of Win32_ComputerSystem Class Provider over WinRM Session

Arguments:
    /logons   - return logged on users on a host (requires SMB or WMI)
    /registry - enumerate sessions from registry hive (requires SMB)
    /services - return services running as users (requires SMB or WMI)
    /targets  - comma-separated list of hostnames to check. If none provided, localhost will be checked.
    /threads  - specify maximum number of parallel threads (default=25)
    /validate - check credentials against Domain prior to scanning targets (useful during token manipulation)
    /verbose  - print additional logging information
    /ou       - specify LDAP OU to query enabled computer objects from
                ex: "OU=Special Servers,DC=example,DC=local"
    /ldap - query hosts from the following LDAP filters:
         :all - All enabled computers with 'primary' group 'Domain Computers'
         :dc - All enabled Domain Controllers
         :exclude-dc - All enabled computers that are not Domain Controllers
         :servers - All enabled servers
         :servers-exclude-dc - All enabled servers excluding DCs
```
### Execute Assembly
```
execute-assembly /opt/SharpTools/LACheck smb rpc winrm /ldap:servers-exclude-dc /targets:WEB01,DEV02.contoso.com,10.10.10.10 /logons /threads:10 /verbose
```
### Output
```
[*] Tasked beacon to run .NET program: LACheck smb rpc winrm /ldap:servers-exclude-dc /targets:WEB01,DEV02.contoso.com,10.10.10.10 /logons /threads:10 /verbose
[+] host called home, sent: 111705 bytes
[+] received Output
[+] Parsed Aguments:
        rpc: True
        smb: False
        winrm: False
        /logons: True
        /registry: False
        /services: False
        /ldap: servers-exclude-dc
        /ou:
        /targets: WEB01,DEV02.contoso.com,10.10.10.10
        /logons: true
        /validate: true
        /verbose: true
        /threads: 10
[+] Performing LDAP query for all enabled computers that are not Domain Controllers or read-only DCs...
[+] This may take some time depending on the size of the environment
[+] LDAP Search Results: 2
[SMB] Admin Success: WEB01
[session] WEB01 - contoso\devadmin
[session] WEB01 - contoso\devuser
[session] WEB01 - contoso\WEB01$
[session] WEB01 - contoso\devadmin
[session] WEB01 - contoso\devuser
[rdp] WEB01 - contoso\devadmin rdp-tcp#2 Active Last Connection: 00:00:50:26 Last Input: 00:00:00:00
[RPC] Admin Success: WEB01
[WinRM] Admin Success: DESKTOP-118GDCE
[WinRM] Admin Success: DEV02.contoso.com
[!] RPC on DEV02.contoso.com - Access denied.
[!] SMB on DEV02.contoso.com - Attempted to perform an unauthorized operation.
[RPC] Admin Success: 10.10.10.10
[!] SMB on 10.10.10.10 - Attempted to perform an unauthorized operation.
[!] WinRM on 10.10.10.10 - The WinRM client cannot process the request. Default authentication may be used with an IP address under the following conditions: the transport is HTTPS or the destination is in the TrustedHosts list, and explicit credentials are provided. Use winrm.cmd to configure TrustedHosts. Note that computers in the TrustedHosts list might not be authenticated. For more information on how to set TrustedHosts run the following command: winrm help config.
```

### WinRM Authentication
As seen in the above example output, attempting to check WinRM on the host at IP address `10.10.10.10` will error due to the WinRM client not attempting to authenticate to a host via IP address. 

Use hostnames when attempting to check WinRM Access.

### Specifying Targets
The `/targets`, `/ldap`, and `/ou` flags can all be used together or seprately to generate a list of hosts to enumerate.

All hosts returned from these flags are combined and deduplicated before enumeration starts.

# Enumeration Methods
## Performance Summary
| | SMB | WMI | WinRM |
--- | --- | --- | ---
|/logons|fast|fast| - |
|/services|slow|fast| - |
|/registry|slow| - | - 

\- = not implemented

## SMB
### /logons
[NetWkstaUserEnum](https://docs.microsoft.com/en-us/windows/win32/api/lmwksta/nf-lmwksta-netwkstauserenum) returns a list of users with interactive, service and batch logons

[WTSEnumerateSessionsA](https://docs.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenumeratesessionsa) returns a list of RDP sessions on a host

[WTSQuerySessionInformationA](https://docs.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsquerysessioninformationa) retrieves detailed information for each RDP session
### /registry
Iterate through SIDs in `\\Computer\HKEY_USERS\` hive, attempts to access `Volatile Environment` for each SID, and retrieves values from `USERDOMAIN` and `USERNAME` keys.

This method requires the Remote Registry service to be running on a remote host. If it is not:
1. initial start type of the Remote Registry service is recorded
2. start type is changed to `Automatic`
3. Remote Registry service is started
4. registry hives are enumerated
5. Remote Registry service is stopped
6. start type is reverted to its initially recorded value

Due to the potentially multi-step process to enumerate each host, this method may be slower compared to alternative techniques. `smb /logons` is faster
### /services
[ServiceController.GetServices Method](https://docs.microsoft.com/en-us/dotnet/api/system.serviceprocess.servicecontroller.getservices) retrieves a list of services on a host

Each service is queried to determine the user it is configured to run as.

Due to each service having to be queried individually, this method may be slower compared to alternative techniques. `wmi /services` is faster
## WMI
### /logons
[Win32_LoggedOnUser class](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-loggedonuser) returns a list of logged on sessions
[Win32_LogonSession class](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logonsession) returns detailed information for each session

### /services
Queries the [Win32_Service class](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service) to retrieve the name, user, and state of services
