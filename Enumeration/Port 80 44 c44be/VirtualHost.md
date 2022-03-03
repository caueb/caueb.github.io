# Virtual Host

## Gobuster
```
gobuster vhost -u machine.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

## FFUF

First figure out the response length of false positives.
```
curl -s -H "Host: nonexistent.example.com" [http://example.com](http://example.com/) | wc -c
```

Bruteforce:

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u [http://example.com](http://example.com/) -H "Host: FUZZ.example.com" -fs <length_of_false_positive>
```

