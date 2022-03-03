# Git Repository

## Clone Repository

```bash
git clone http://git.canape.htb/simpsons.git
```

*Or if that simpsons.git file wasn’t exposed we could use wget to get the job done.*

```bash
wget --mirror -I .git 10.10.10.70/.git/
```

## Git Dumper

We can use Git-Dumper in case Git-Clone is showing forbidden.

```bash
# https://github.com/arthaud/git-dumper
git-dumper http://website.com/.git newdirectory/
```

## GitTools

This tool can be used to extract `.git` from local directory as well.

```powershell
/opt/GitTools/Extractor/extractor.sh backup/ git_dump/
```

## Git Commands

### See files

```bash
git checkout -- .
```

### See Commit Log history

```bash
git log
```

### Check difference with the commit hash

```bash
git diff <HASH>
```