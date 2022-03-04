# Port Forwarding

## Chisel

Example in how to expose port 4444 found in Windows machine to local 9001:

```powershell
# Kali (10.10.14.13)
./chisel server --reverse --port 9001

# Windows
chisel.exe client 10.10.14.13:9001 R:4444:localhost:4444

* Now we can connect to 127.0.0.1 4444 in Kali machine.
```