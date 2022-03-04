---
icon: code-square
---

# Windows Tricks

## Run command as User (with creds)

```powershell
$pass = ConvertTo-SecureString "aliceishere" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("disco\\Alice", $pass)

Invoke-Command -ComputerName disco -Credential $cred -ScriptBlock {whoami}
```

## List running process with args

```powershell
WMIC path win32_process get Caption,Processid,Commandline
```

## Scan for hosts and open ports in subnet

```bash
# Scan for Hosts in Subnet
PS > 1..254 | ForEach-Object {Test-Connection -ComputerName "172.16.2.$_" -Count 1 -ErrorAction SilentlyContinue}

# Scan for open Ports
PS > 1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("172.16.2.101",$)) "Port $ is open!"} 2>$null
```

## **PowerShell**

```powershell
# **PowerShell Directory**
c:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

# FIX THE VARIABLE PATH
set PATH=%SystemRoot%\system32;%SystemRoot%;
```

## Search for files

```powershell
Get-Childitem –Path C:\ -Include *filetosearch* -Recurse -ErrorAction SilentlyContinue
```

## Firewall Disable

```powershell
NetSh Advfirewall set allprofiles state off
```

## **Can not run scripts?** Enable it!

```powershell
Set-ExecutionPolicy Unrestricted
Set-ExecutionPolicy Unrestricted -Scope CurrentUser
```

## Add a RDP user

```powershell
net user hacker hacker123 /add
net localgroup Administrators hacker /add
net localgroup "Remote Desktop Users" hacker /ADD
```
