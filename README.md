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
    /targets  - comma-separated list of hostnames to check. If none provided, localhost will be checked.
    /validate - check credentials against Domain prior to scanning targets (useful during token manipulation)
    /verbose  - print additional logging information
    /threads  - specify maximum number of parallel threads (default=25)
    /ldap - query hosts from the following LDAP filters:
         :all - All enabled computers with 'primary' group 'Domain Computers'
         :dc - All enabled Domain Controllers
         :exclude-dc - All enabled computers that are not Domain Controllers
         :servers - All enabled servers
         :servers-exclude-dc - All enabled servers excluding DCs
```
### Execute Assembly
```
execute-assembly /opt/SharpTools/LACheck smb rpc winrm /ldap:servers-exclude-dc /targets:WEB01,DEV02.contoso.com,10.10.10.10 /verbose /threads:10 /validate
```
### Output
```
[*] Tasked beacon to run .NET program: LACheck smb rpc winrm /ldap:servers-exclude-dc /targets:WEB01,DEV02.contoso.com,10.10.10.10 /verbose /validate
[+] host called home, sent: 111705 bytes
[+] received Output
[+] Parsed Aguments:
        rpc: true
        smb: true
        winrm: true
        /ldap: servers-exclude-dc
        /targets: WEB01,DEV02.contoso.com,10.10.10.10
        /verbose: true
        /threads: 10
[+] Credentials Validated on Domain
[+] LDAP Search Results: 2
[SMB] Admin Success: WEB01
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
