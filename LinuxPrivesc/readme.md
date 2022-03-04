---
icon: code-square
---
# Linux Privesc

## OS, Kernel & Hostname

```bash
cat /etc/os-release
cat /etc/issue
cat /proc/version
hostname
uname -a
```

## Users

```bash
cat /etc/passwd
id
sudo -l

# See user special groups and list files
groups
find / -group management -ls 2>/dev/null
```

## Network

```bash
netstat -antup
```

## Processes Running

```bash
ps aux
ps aux | grep root

```

## Installed Packages

```bash
dpkg -l (Debian)
rpm -qa (Fedora)
```

## Find SUID

```bash
find / -perm -u=s -type f 2>/dev/null
find /* -user root -perm -4000 -print 2>/dev/null
```

## World writable scripts invoked as root

```bash
find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null
find / -perm -o w -type d 2>/dev/null
```

## World executable folder

```bash
find / -perm -o x -type d 2>/dev/null
```

## World writable and executable folders

```bash
find / \\( -perm -o w -perm -o x \\) -type d 2>/dev/null
```

## Find world-writable files in `/etc`

```bash
find /etc -perm -2 -type f 2>/dev/null
find / -perm -2 -type f 2>/dev/null
```

## World-writable directories

```bash
find / -writable -type d 2>/dev/null
```

[MySQL 4.x/5.x](Linux%20Priv%20d2987/MySQL%204%20x%20%208a1a7.md)

[Kernel Exploit](Linux%20Priv%20d2987/Kernel%20Exp%2014b2d.md)

[Port Forwarding - SSH](Linux%20Priv%20d2987/Port%20Forwa%20c97d0.md)

[Weak Files Permissions](Linux%20Priv%20d2987/Weak%20Files%200ec7a.md)

[Sudo](Linux%20Priv%20d2987/Sudo%2025db8.md)

[Cronjobs](Linux%20Priv%20d2987/Cronjobs%20dc94e.md)

[SSH](Linux%20Priv%20d2987/SSH%206b716.md)

[SUID](Linux%20Priv%20d2987/SUID%2080b3d.md)

[NFS](Linux%20Priv%20d2987/NFS%206b60f.md)

[Big Checklist](Linux%20Priv%20d2987/Big%20Checkl%20f4926.md)