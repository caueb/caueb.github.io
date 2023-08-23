---
icon: unlock
---
# Cracking

## Search-That-Hash

```bash
# Search-That-Hash
# https://github.com/HashPals/Search-That-Hash
# pip3 install search-that-hash
sth -f hash.txt -w /usr/share/wordlists/rockyou.txt
sth --text "HASH" -w /usr/share/wordlists/rockyou.txt
```

## Hashcat

```bash
# Hashcat examples of hash
hashcat --example-hashes | grep -i -B5 -A5 "MYSQL"

# Usage
hashcat -m 1000 -a 0 julian.hash /usr/share/wordlists/rockyou.txt -O -o cracked-hash.txt

-m 10000  = designates the type of hash we are cracking (NTLM)
-a 0      = designates a dictionary attack
-o        = cracked.txt is the output file for the cracked passwords
```
### Common hashes
| Hash | Mode |
| --- | --- |
| md5 raw | -m 0 |
| md5crypt | -m 500 |
| md5(apr) | -m 1600 |
| sha512crypt | -m 1800 |
| wordpress | -m 400 |
| DES(unix) | -m 1500 |
| Mysql4.0/5 | -m 300 |
| NTLM | -m 1000 |

### Custom wordlist
Create a custom wordlist based on words and hashcat rules.
```bash
# Create a file with key-words
$ cat mywordlist.txt
password
2020
secret

# Use Hashcat to merge the words and add characters
hashcat --force --stdout mywordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

## John The Ripper

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashtocrack.txt

# John automatically detects the hash, but we can specify:
--format=md5crypt
--format=raw-md5
--format=Raw-SHA256

# MYSQL
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=Raw-SHA256
```

## Linux passwords

```bash
unshadow /etc/passwd /etc/shadow > mypasswd.txt
john --wordlist=/usr/share/wordlists/rockyou.txt mypasswd.txt
```

## Crack Files

### ZIP files

```bash
zip2john <zi­pfi­le> > output.txt 
john --wordlist=/usr/share/wordlists/rockyou.txt output.txt

# Using Fcrackzip
fcrackzip -u backup­s.zip -D -p /usr/s­har­e/w­ord­lis­ts/­roc­kyo­u.txt -v
```

### SSH (id_rsa)

```bash
/usr/share/john/ssh2john.py id_rsa > hash.john
john --wordlist=/usr/share/wordlists/rockyou.txt hash.john
```

### PDF

```bash
pdfcrack -f infrastructure.pdf -w /usr/share/wordlists/rockyou.txt
```

### PGP MESSAGE & KEY

Identification & Syntax

```bash
# PGP MESSAGE HEADER LOOKS LIKE
-----BEGIN PGP MESSAGE-----

# PGP PRIVATE KEY HEADER LOOKS LIKE
-----BEGIN PGP PRIVATE KEY BLOCK-----
```

Import the PGP PRIVATE KEY into our machine:

```bash
gpg --import eddie.gpg
# Sometimes asks for a password, then crack it!
```

Crack:

```bash
gpg2john eddie.gpg
john eddiepgp.hash --wordlist=/usr/share/wordlist/rockyou.txt
```

After importing the private key, we can use it to decode PGP messages:

```bash
# Decode command
gpg -d passbolt.message.gpg
```

### PFX
Using John (FASTER):
```
$ pfx2john staff.pfx > staff.pfx.out
$ john staff.pfx.out --wordlist=/usr/share/wordlists/rockyou.txt
```

Using pkcs12:
```bash
# Install tool
$ git clone https://github.com/crackpkcs12/crackpkcs12.git
$ cd crackpkcs12/
$ ./configure
$ make
$ cd src/
$ ./crackpkcs12

# Cracking PFX
$ ./crackpkcs12 -v -d /usr/share/wordlists/rockyou.txt staff.pfx
```
Now we can import the `.pfx` certificate using the password on Firefox to access internal resources.
