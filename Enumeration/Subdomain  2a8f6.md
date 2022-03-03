# Subdomain Enumeration

# OSINT - SSL/TLS Certificates

When an SSL/TLS (Secure Sockets Layer/Transport Layer Security) certificate is created for a domain by a CA (Certificate Authority), CA's take part in what's called "Certificate Transparency (CT) logs". These are publicly accessible logs of every SSL/TLS certificate created for a domain name. The purpose of Certificate Transparency logs is to stop malicious and accidentally made certificates from being used. 

We can use this service to our advantage to discover subdomains belonging to a domain, sites like [https://crt.sh](https://crt.sh/) and [https://transparencyreport.google.com/https/certificates](https://transparencyreport.google.com/https/certificates) offer a searchable database of certificates that shows current and historical results.

- [https://crt.sh](https://crt.sh/)
- [https://transparencyreport.google.com/https/certificates](https://transparencyreport.google.com/https/certificates)

# OSINT - Search Engines

## Google

Search for subdomains and exclude `www`.

```
-site:www.mydomain.com site:*.mydomain.com
```

# DNS Bruteforce

```
dnsrecon -t brt -d mydomain.com
# /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt
```

# OSINT - Sublist3r

```
./sublist3r.py -d mydomain.com
```

# Virtual Hosts

```
# GOBUSTER
gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://shibboleth.htb
# OR FFUF
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.mydomain.com" -u http://MACHINE_IP -fs {SIZE}
```

## TheHarvester

```bash
theHarverster -d google.com -b google,twitter,linkedin,bing,yahoo,sublist3r
```

## Knockpy

```bash
knockpy google.com -w /usr/share/seclists/Discovery/DNS/shubs-stackoverflow.txt
```