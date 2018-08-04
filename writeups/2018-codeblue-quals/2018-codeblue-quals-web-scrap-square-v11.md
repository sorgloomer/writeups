2018 CodeBlue CTF quals - Scrap Square V1.1
===========================================

Same as before, but now the username length was restricted to 80 charcters.

TL;DR
-----

Registered a user:

    h<img name=admin id=8eezt9vc><script type=module src=/static/raw/8eezt9vc/b.js>

Created a scap:

    import '/static/javascripts/periodically-watch-scrap-body-and-report-scrap-automatically-with-banword.js'
    delete window.admin
    delete window.banword

And reported:

    http://v11.scsq.task.ctf.codeblue.jp:3000/scraps/orw4eu3b/c?/x/..\..\..

Details
-------

Look at what we didn't use last time:

 1. Scrap titles show up in the URL as a filename
 2. No injection in scrapts, still there is filtering:
    1. `/[^0-9a-zA-Z '.]/` is checked for scrap title
    2. `[^0-9a-zA-Z '.\n\r/-]` is checked for scrap body

This looks like some nice js programming challenge with a restricted character set of
`[0-9a-zA-Z '.\n\r/-]`.

Including the js file with the long filename in the username is unfeasible given the new length
constraint, so let's look for ways to include them from a script! `importScripts` only work
from WebWorkers, but es6 `import` statements are here! Fortunately all the scripts assign
global variables using `window.x = ...`, so they work when imported as a module too! We still
have to somehow deactivate `config.js` somehow, and the good-old XSS-auditor trick doesn't
work anymore, so lets just keep using a comment. That makes an exploit username of:

    <img name=admin id=8eezt9vc><script type=module src=/static/raw/8eezt9vc/.js><!--

... *which is 81 chars,* which exceeds the limit by one... This cannot be a coincidence, we
are missing something.

Deactivating `config.js` way #2
-------------------------------

    delete window.admin
    delete window.banword

Javascript modules load asynchronously, because they can potentially reference any number of
other modules which need to be processed before the entry module does, and the main thread
mustn't be blocked for that much time. For this reason our injected script runs after
`config.js` did, deleting the "wrong" values. Fortunately it doesn't delete dom elements by
their id. After this, we don't need the 4 character comment `<!--` in our exploit, and now
it fits into the length restriction.

The flag was again on the admin-s dashboard. Nice chall, kudos.
