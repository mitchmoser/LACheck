# LACheck
Multithreaded C# .NET Assembly Local Administrative Privilege Enumeration 

### Example Usage
```
$ ./LACheck.exe help
  _                  _____ _               _
 | |        /\      / ____| |             | |
 | |       /  \    | |    | |__   ___  ___| | __
 | |      / /\ \   | |    | '_ \ / _ \/ __| |/ /
 | |____ / ____ \  | |____| | | |  __/ (__|   <
 |______/_/    \_\  \_____|_| |_|\___|\___|_|\_\

Usage:
    LACheck.exe smb rpc /targets:hostname,fqdn.domain.tld,10.10.10.10 /verbose /validate

Local Admin Checks:
    smb   - Attempts to access C$ share
    rpc   - Attempts WMI query of Win32_ComputerSystem Class provider over RPC
    winrm - Attempts WMI query of Win32_ComputerSystem Class Provider over WinRM Session

Argument:
    /targets  - comma-separated list of hostnames to check. If none provided, localhost will be checked.
    /validate - check credentials against Domain prior to scanning targets (useful during token manipulation)
    /verbose  - print additional logging information

execute-assembly /opt/SharpTools/LACheck smb rpc winrm /targets:WEB01,DEV02.contoso.com,10.10.10.10 /verbose /validate
```
### Output
```
[*] Tasked beacon to run .NET program: LACheck smb rpc winrm /targets:WEB01,DEV02.contoso.com,10.10.10.10 /verbose /validate
[+] host called home, sent: 111705 bytes
[+] received Output
[+] Parsed Aguments:
        rpc: true
        smb: true
        winrm: true
        /targets: WEB01,DEV02.contoso.com,10.10.10.10
        /verbose: true
[+] Credentials Validated
[+] Connecting to WEB01
[+] Connecting to DEV02.contoso.com
[+] Connecting to 10.10.10.10
[SMB] Admin Succes: WEB01
[RPC] Admin Succes: WEB01
[WinRM] Admin Succes: DESKTOP-118GDCE
[WinRM] Admin Success: DEV02.contoso.com
[!] RPC on DEV02.contoso.com - Access denied.
[!] SMB on DEV02.contoso.com - Attempted to perform an unauthorized operation.
[RPC] Admin Succes: 10.10.10.10
[!] SMB on 10.10.10.10 - Attempted to perform an unauthorized operation.
[!] WinRM on 10.10.10.10 - The WinRM client cannot process the request. Default authentication may be used with an IP address under the following conditions: the transport is HTTPS or the destination is in the TrustedHosts list, and explicit credentials are provided. Use winrm.cmd to configure TrustedHosts. Note that computers in the TrustedHosts list might not be authenticated. For more information on how to set TrustedHosts run the following command: winrm help config.
```

### WinRM Authentication
As seen in the above example output, attempting to check WinRM on the host at IP address `10.10.10.10` will error due to the WinRM client not attempting to authenticate to a host via IP address. 

Use hostnames when attempting to check WinRM Access.
