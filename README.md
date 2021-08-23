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
    LACheck.exe smb rpc /targets:hostname,fqdn.domain.tld,10.10.10.10 /ldap:all /ou:"OU=Special Servers,DC=example,DC=local" /verbose /bloodhound /user:bob@contoso.lab

Local Admin Checks:
    smb   - Attempts to access C$ share
    rpc   - Attempts WMI query of Win32_ComputerSystem Class provider over RPC
    winrm - Attempts WMI query of Win32_ComputerSystem Class Provider over WinRM Session

Arguments:
    /bloodhound - generate bloodhound-digestible AdminTo and Session collection file
                  output file is zipped and enypted with randomized name and password
    /dc         - specify domain controller to query (if not ran on a domain-joined host)
    /domain     - specify domain name (if not ran on a domain-joined host)
    /edr        - check host for EDR (requires smb, rpc, or winrm)
    /logons     - return logged on users on a host (requires smb, rpc, or winrm)
    /registry   - enumerate sessions from registry hive (requires smb)
    /services   - return services running as users (requires smb, rpc, or winrm)
    /socket     - send bloodhound output to TCP socket instead of writing to disk
                  ex: ""127.0.0.1:8080""
    /targets    - comma-separated list of hostnames to check
    /threads    - specify maximum number of parallel threads (default=25)
    /user       - specify username that collection was run under (useful during token manipulation)
    /validate   - check credentials against Domain prior to scanning targets (useful during token manipulation)
    /verbose    - print additional logging information
    /ou         - specify LDAP OU to query enabled computer objects from
                  ex: "OU=Special Servers,DC=example,DC=local"
    /ldap - query hosts from the following LDAP filters:
         :all - All enabled computers with 'primary' group 'Domain Computers'
         :dc  - All enabled Domain Controllers (not read-only DCs)
         :exclude-dc - All enabled computers that are not Domain Controllers or read-only DCs
         :servers - All enabled servers
         :servers-exclude-dc - All enabled servers excluding Domain Controllers or read-only DCs
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
        smb: True
        winrm: True
        /bloodhound: False
        /edr: False
        /logons: True
        /registry: False
        /services: False
        /ldap: servers-exclude-dc
        /ou:
        /targets:
        /threads: 10
        /user: svcadmin
        /validate: False
        /verbose: False
[+] Performing LDAP query for all enabled computers that are not Domain Controllers or read-only DCs...
[+] This may take some time depending on the size of the environment
[+] LDAP Search Results: 2
[SMB] Admin Success: WEB01 as svcadmin
[session] WEB01 - contoso\devadmin (svcadmin)
[session] WEB01 - contoso\devuser (svcadmin)
[session] WEB01 - contoso\WEB01$ (svcadmin)
[session] WEB01 - contoso\devadmin (svcadmin)
[session] WEB01 - contoso\devuser (svcadmin)
[rdp] WEB01 - contoso\devadmin rdp-tcp#2 Active Last Connection: 00:00:50:26 Last Input: 00:00:00:00  (svcadmin)
[session] WEB01 - contoso\devadmin  4/20/2021 11:00:05 AM (svcadmin)
[session] WEB01 - contoso\devuser 4/20/2021 1:40:52 PM (svcadmin)
[session] WEB01 - contoso\WEB01$ 4/20/2021 5:51:43 PM (svcadmin)
[session] WEB01 - contoso\devadmin 4/20/2021 09:54:38 AM (svcadmin)
[session] WEB01 - contoso\devuser 4/20/2021 10:14:32 AM (svcadmin)
[WinRM] Admin Success: DESKTOP-118GDCE as svcadmin
[WinRM] Admin Success: DEV02.contoso.com as svcadmin
[!] RPC on DEV02.contoso.com - Access denied.
[!] SMB on DEV02.contoso.com - Attempted to perform an unauthorized operation.
[RPC] Admin Success: 10.10.10.10  as svcadmin
[!] SMB on 10.10.10.10 - Attempted to perform an unauthorized operation.
[!] WinRM on 10.10.10.10 - The WinRM client cannot process the request. Default authentication may be used with an IP address under the following conditions: the transport is HTTPS or the destination is in the TrustedHosts list, and explicit credentials are provided. Use winrm.cmd to configure TrustedHosts. Note that computers in the TrustedHosts list might not be authenticated. For more information on how to set TrustedHosts run the following command: winrm help config.
```

### WinRM Authentication
As seen in the above example output, attempting to check WinRM on the host at IP address `10.10.10.10` will error due to the WinRM client not attempting to authenticate to a host via IP address. 

Use hostnames when attempting to check WinRM Access.

### Specifying Targets
The `/targets`, `/ldap`, and `/ou` flags can all be used together or seprately to generate a list of hosts to enumerate.

All hosts returned from these flags are combined and deduplicated before enumeration starts.

## Bloodhound
LACheck supports writing AdminTo and Session collected into json output that can be uploaded to BloodHound

This output is only meant to augment an existing BloodHound collection with updated Administrative privileges for a single user and Sessions collected from hosts that Administrative privileges have been identified

The `/bloodhound` switch will write a randomly-named encrypted zip file to disk which can be downloaded, extracted, and uploaded to BloodHound

### /user
BloodHound requires resolving users and computers to SIDs. Due to impersonation techniques such as Cobalt Strike's `make_token` and `kerberos_ticket_use`, LACheck may not be able to accurately determine the user context for a collection. The `/user` arguement is required to supply LACheck with the userprincipalname (format = `samaccountname@domain.tld`) of the context it is ran under in order to accurately correlate the collection information.

### /socket
BloodHound output can be sent to a TCP socket instead of being written to disk.

If the TCP connection fails, BloodHound output will be written to disk.

In a Cobalt Strike beacon, TCP connections can be forwarded from a host back to the operator's local machine using `rportfwd_local`:
```
rportfwd_local 8888 127.0.0.1 8888
```
An operator may then pipe the output of the TCP stream to a local file using netcat:
```
nc -lvnp 8888 > computers.json 
```

# Enumeration Methods
## Performance Summary
| | SMB | WMI | WinRM |
--- | --- | --- | ---
|/edr|fast|fast| fast |
|/logons|fast|fast| fast |
|/services|slow|fast| fast |
|/registry|slow| fast | - |

\- = not implemented

## SMB
### /edr
Inspired by [harleyQu1nn's EDR.cna script](https://github.com/harleyQu1nn/AggressorScripts/blob/master/EDR.cna)

[Directory.GetFiles](https://docs.microsoft.com/en-us/dotnet/api/system.io.directory.getfiles) Method returns a list of drivers from:
- \\\\host\C$\windows\system32\drivers
- \\\\host\C$\windows\sysnative\drivers

Drivers are looked up against a list of known drivers used by EDR vendors.

#### Example Output ran as svcadmin user
```
[EDR] WEB01 - Found: CrowdStrike, SentinelOne (svcadmin)
[EDR] DEV02 - no EDR found (svcadmin)
```

### /logons
[NetWkstaUserEnum](https://docs.microsoft.com/en-us/windows/win32/api/lmwksta/nf-lmwksta-netwkstauserenum) returns a list of users with interactive, service and batch logons

[WTSEnumerateSessionsA](https://docs.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenumeratesessionsa) returns a list of RDP sessions on a host

[WTSQuerySessionInformationA](https://docs.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsquerysessioninformationa) retrieves detailed information for each RDP session

#### Example Output ran as svcadmin user
```
[session] WEB01 - contoso\devadmin (svcadmin)
[session] WEB01 - contoso\devuser (svcadmin)
[session] WEB01 - contoso\WEB01$ (svcadmin)
[session] WEB01 - contoso\devadmin (svcadmin)
[session] WEB01 - contoso\devuser (svcadmin)
[rdp] WEB01 - contoso\devadmin rdp-tcp#2 Active Last Connection: 00:00:50:26 Last Input: 00:00:00:00  (svcadmin)
```

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

#### Example Output ran as svcadmin user
```
[registry] WEB01 - contoso\devadmin (svcadmin)
```

### /services
[ServiceController.GetServices Method](https://docs.microsoft.com/en-us/dotnet/api/system.serviceprocess.servicecontroller.getservices) retrieves a list of services on a host

Each service is queried to determine the user it is configured to run as.

Due to each service having to be queried individually, this method may be slower compared to alternative techniques. `wmi /services` is faster

#### Example Output ran as svcadmin user
```
[service] WEB01 - devadmin@consoso.com Service: secretsvc State: Running (svcadmin)
```

## WMI
### /edr
Inspired by [harleyQu1nn's EDR.cna script](https://github.com/harleyQu1nn/AggressorScripts/blob/master/EDR.cna)

[CIM_DataFile class](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/cim-datafile) returns a list of drivers from:
- \\host\C$\windows\system32\drivers
- \\host\C$\windows\sysnative\drivers

Drivers are looked up against a list of known drivers used by EDR vendors.

#### Example Output ran as svcadmin user
```
[EDR] WEB01 - Found: CrowdStrike, SentinelOne (svcadmin)
[EDR] DEV02 - no EDR found (svcadmin)
```

### /logons
[Win32_LoggedOnUser class](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-loggedonuser) returns a list of logged on sessions
[Win32_LogonSession class](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logonsession) returns detailed information for each session

#### Example Output ran as svcadmin user
```
[session] WEB01 - contoso\devadmin  4/20/2021 11:00:05 AM (svcadmin)
[session] WEB01 - contoso\devuser 4/20/2021 1:40:52 PM (svcadmin)
[session] WEB01 - contoso\WEB01$ 4/20/2021 5:51:43 PM (svcadmin)
[session] WEB01 - contoso\devadmin 4/20/2021 09:54:38 AM (svcadmin)
[session] WEB01 - contoso\devuser 4/20/2021 10:14:32 AM (svcadmin)
```

### /registry
Queries the [Win32_UserProfile class](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ee886409(v=vs.85)) to retrieve SIDs for user profiles on a system.

The [EnumKey method of the StdRegProv class](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/regprov/enumkey-method-in-class-stdregprov) retrieves the `\\Computer\HKEY_USERS\` hive and attempts to access `Volatile Environment` for each returned SID to retrieve values from the `USERDOMAIN` and `USERNAME` keys.

#### Example Output ran as svcadmin user
```
[registry] WEB01 - contoso\devadmin (svcadmin)
```

### /services
Queries the [Win32_Service class](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service) to retrieve the name, user, and state of services

#### Example Output ran as svcadmin user
```
[service] WEB01 - devadmin@consoso.com Service: secretsvc State: Running (svcadmin)
```

## WinRM
Each WMI checks is also implemented using [WMI Resources](https://docs.microsoft.com/en-us/windows/win32/winrm/querying-for-specific-instances-of-a-resource) and [WMI Enumeration](https://docs.microsoft.com/en-us/windows/win32/api/wsmandisp/nf-wsmandisp-iwsmansession-enumerate) over WinRM.

This avoids the use of PowerShell runspaces. 
