# BloodHound

## Install

```bash
# DOWNLOAD
1. git clone BloodHound Github repository
2. Download Linux executable from releases

# START / RUN

1. Start neo4j
neo4j console

2. Access the URL provided
Default creds:
user: neo4j
password: neo4j

## Reset neo4j password
locate neo4j | grep auth
rm /usr/share/neo4j/data/dbms/auth

3. Start BloodHound
/opt/BloodHound/BloodHound-linux-z64/# ./BloodHound --no-sandbox

3.1 Connect to neo4j server with the creds

3.2 Run SharpHound.exe in the target machine
.\SharpHound.exe -c all

3.3 Import the extracted data in BloodHound (Drag and Drop)
```

## Usage

```bash
1. Search for user owned
2. Mark as OWNED
3. QUERY: Shortest path from OWNED Principals
   QUERY: Find Shortest Paths to Domain Admins
```