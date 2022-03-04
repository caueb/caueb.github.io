# Port 80/443 - Web

## Banner Grabbing

```bash
# PORT 80
nc -v domain.com 80 
GET / HTTP/1.0

# PORT 443
openssl s_client -connect domain.com:443
GET / HTTP/1.0
```

## Check WAF

```jsx
wafw00f google.com
```

## Default pages with interesting info

```bash
- /robots.txt
- /sitemap.xml
- /crossdomain.xml
- /clientaccesspolicy.xml
- /.well-known/
- Check also comments in the main and secondary pages.
```

## Scrape website words

Create a wordlist with the words used in the website.

```bash
cewl -w customwordlist.txt -d 5 http://10.10.110.100:65000/wordpress/ -m 5
```
