# Port 53 - DNS

## **Banner Grabbing**

DNS does not have a "banner" to grab. The closest equivalent is a magic query for `version.bind. CHAOS TXT` which will work on most BIND nameservers.
You can perform this query using `dig`:

```bash
dig version.bind CHAOS TXT @DNS
```

## Nslookup

```bash
$ nslookup
> SERVER <MACHINE IP> #Select dns server
> 127.0.0.1 #Reverse lookup of 127.0.0.1, maybe...
> <MACHINE_IP> #Reverse lookup of a machine, maybe...
> machine.htb # Test if respond to the machine DNS
```

## Zone Transfer

```bash
dig axfr @<DNS_IP> #Try zone transfer without domain
dig axfr bank.htb @<DNS_IP> #Try zone transfer guessing the domain
fierce --domain <DOMAIN> --dns-servers <DNS_IP> #Will try toperform a zone transfer against every authoritative name server and if this doesn'twork, will launch a dictionary attack
```

### More info

```bash
dig ANY @<DNS_IP> <DOMAIN>     #Any information
dig A @<DNS_IP> <DOMAIN>       #Regular DNS request
dig AAAA @<DNS_IP> <DOMAIN>    #IPv6 DNS request
dig TXT @<DNS_IP> <DOMAIN>     #Information
dig MX @<DNS_IP> <DOMAIN>      #Emails related
dig NS @<DNS_IP> <DOMAIN>      #DNS that resolves that name
dig -x 192.168.0.2 @<DNS_IP>   #Reverse lookup
dig -x 2a00:1450:400c:c06::93 @<DNS_IP> #reverse IPv6 lookup
```

## Finding Subdomains

```bash
$ host megacorp.com
megacorp.com has address 192.168.24.110

$ host -t mx megacorp.com
megacorp.com is handled by 20 mail.megacorp.com
megacorp.com is handled by 30 gym.megacorp.com

$ host -t txt megacorp.com
megacorp.com desctiptive text "Try Harder"
```

### Bruteforce subdomains

```bash
dnsrecon -D subdomains-1000.txt -d <DOMAIN> -n <IP_DNS>
dnscan -d <domain> -r -w subdomains-1000.txt #Bruteforce subdomains in recursive way, https://github.com/rbsec/dnscan
```

## Automated Tools

Tools to automate enumeration Zone Transfer and Domain. Bruteforce to find additional hostnames.

### DNSRecon

```bash
$ dnsrecon -d megacorp.com -t axfr
$ dnsrecon -d megacorp.com -D ~/wordlist.txt -t brt
```

### TheHarvester

```bash
theHarverster -d google.com -b google,twitter,linkedin,bing,yahoo,sublist3r
```

### Sublist3r

```bash
sublist3r -d google.com
```

### Knockpy

```bash
knockpy google.com -w /usr/share/seclists/Discovery/DNS/shubs-stackoverflow.txt
```