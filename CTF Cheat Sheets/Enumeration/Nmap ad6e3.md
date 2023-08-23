# Nmap
Basic Nmap usage in CTF.

## Host Discovery

```bash
nmap -sn 10.10.1.1-254 -v -o hosts.txt
netdiscover -r 10.10.10.0/24
```

## Quick All Ports

```bash
# All TCP ports
nmap -p- --min-rate=1000 -T4 10.10.10.x

# Run Service scan in the ports open
nmap -sC -sV -p 80,22,445 -o nmap.txt 10.10.10.x
```

## Rustscan

```python
# https://github.com/RustScan/RustScan
## Basic usage
rustscan -a 127.0.0.1
## Quiet / Range
rustscan -a 127.0.0.1 -q --range 1-10000
```

## UDP

```bash
# Default
sudo nmap -sU -v 192.168.120.144

# Nmap fast check if any of the 100 most common UDP services is running
nmap -sU -sV --version-intensity 0 -n -F -T4 <IP>

# Nmap check if any of the 100 most common UDP services is running and launch defaults scripts
nmap -sU -sV -sC -n -F -T4 <IP>

# Nmap "fast" top 1000 UDP ports
nmap -sU -sV --version-intensity 0 -n -T4 <IP>
```