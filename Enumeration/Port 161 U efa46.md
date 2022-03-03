# Port 161 UDP - SNMP

## Basic Enumeration

```bash
snmp-check {IP}
```

## Capture SNMP traffic sent to server

```bash
snmpwalk -c public -v1 <target ip>
snmpwalk -c public -v2c <target ip>
```

### Install SNMP MIBS to make the output readable

```bash
sudo apt-get install snmp-mibs-downloader

1. Edit the configuration and comment the mibs line
nano /etc/snmp/snmp.conf
# mibs

2. Run snmap again
snmpwalk -c public -v2c <target ip> | tee snmp.enum
```

## Crack SNMP Passwords

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt {IP} -w 100
```

## Bruteforce Community String

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 192.168.120.144
192.168.120.144 [public] Linux BOXNAME 4.8-generic…     # community string is 'public'
```