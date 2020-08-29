# LACheck
C# .NET Assembly Local Administrative Privilege Enumeration 

### Example Usage
```

  _                  _____ _               _
 | |        /\      / ____| |             | |
 | |       /  \    | |    | |__   ___  ___| | __
 | |      / /\ \   | |    | '_ \ / _ \/ __| |/ /
 | |____ / ____ \  | |____| | | |  __/ (__|   <
 |______/_/    \_\  \_____|_| |_|\___|\___|_|\_\

Usage:
    LACheck.exe smb rpc /targets:host1,fqdn.domain.tld,10.10.10.1 /verbose

    smb - Attempts to access C$ share
    rpc - Attempts WMI query of Win32_ComputerSystem Class provider

execute-assembly /opt/SharpTools/LACheck smb rpc /targets:WEB01,DEV02.contoso.com,10.10.10.1 /verbose /validate
```
### Output
```
[*] Tasked beacon to run .NET program: LACheck smb rpc /targets:WEB01,DEV02.contoso.com,10.10.10.10 /verbose /validate
[+] host called home, sent: 111705 bytes
[+] received Output
[+] Parsed Aguments:
        rpc: True
        smb: True
        /targets: WEB01,DEV02.contoso.com,10.10.10.1
        /verbose: True
[+] Credentials Validated
[+] Connecting to WEB01
[+] Connecting to DEV02.contoso.com
[+] Connecting to 10.10.10.1
[SMB] Admin Succes: WEB01
[RPC] Admin Succes: WEB01
[!] SMB on DEV02.contoso.com - Attempted to perform an unauthorized operation.
[!] RPC on DEV02.contoso.com - Access denied
[SMB] Admin Succes: 10.10.10.10
[!] RPC on 10.10.10.10 - Connection refused
```
