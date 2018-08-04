2018 CodeBlue CTF quals - Scrap Square V1.0
===========================================

The sources for this chalenge were published from the beginning as well, which
is great. Even the sources for the admin browser which opened the reports we
sent them, which is awesome. IMHO this kind of openness benefits us all.

TL;DR
-----

Registered a user:

    hege<form name=admin id=8eezt9vc><script src=/static/javascripts/report-scrap.js></script><script src=/static/javascripts/load-scrap.js></script><script src=/static/javascripts/periodically-watch-scrap-body-and-report-scrap-automatically-with-banword.js></script><!--

And reported:

    http://v10.scsq.task.ctf.codeblue.jp:3000/scraps/orw4eu3b/c?/x/..\..\..

Short story long
----------------

Because of the admin sources, we knew from the beginning that we are looking for
an XSS. The application itself is a social-media style webapp with registration,
login, new scrap, viewing/editing scraps, and reporting. All scraps are global
visible if you know the link. So let's see what we've found:

 1. Scrap titles show up in the URL as a filename
 2. CSP: `default-src: 'self'`, plus bootstrap and recaptcha
 3. No injection in scrapts, still there is filtering:
    1. `/[^0-9a-zA-Z '.]/` is checked for scrap title
    2. `[^0-9a-zA-Z '.\n\r/-]` is checked for scrap body
 4. Scrap bodies are loaded via ajax, with some custom url parsing
 5. There is a script tag commented out, which does some kind of auto-reporting
 6. You can craft a request that reports to any user, not just admin

Still searching for the vulnerable parameter? Well, we were too. A quick grep in
the `.pug` templates:

    $ grep -r "!=" .
    ./index.pug:     a.scraps-item(href=`scraps/${session.user.uid}/${file}`)!= file
    ./layout.pug:    p!= error
    ./scrap.pug:     p!= `${user.name}'s scraps'`
    ./scrap.pug:     div.modal-body!= captcha

The only relevant html injetion is in the username `(-.-')`. That means registering
a new user for every hypothesis. So because of the strict CSP, we went for leaking
info from the admin using in-app mechanics, the reporting feature itself looks like
a good candidate, because of this suspicious looking file, which is commented out
by default:
`static/periodically-watch-scrap-body-and-report-scrap-automatically-with-banword.js`.

Exploit wireframe
-----------------

 - Enable auto-reporting by including a script tag for `periodically-watch-...-banword.js`.
 - Change the reporting target from admin to on of our users (more on this later)
 - Exploit the vulnerable url parsing and include the logged-in users own dashboard in
   the scrap, so that it gets reported back to us

Changing the report target
--------------------------

The report js function sent a report to `window.admin.id`. `config.js` defined it:

    // config.js
    window.admin = {
      id: 'admin'
    }
    window.banword = 'give me flag'

Awesome, so using the good old `<p id=admin>` trick runs into some issues: we need to
disable `config.js`, and need to find a way around the conflict that the id of our
tag must be both `admin` (so it gets on the dom as `admin`), and our userid (so the
report is sent to us). Getting rid of `config` was done by a comment `<!--` which
purged half the dom and the other scripts, so we have to readd them. Turns out some
dom elements are available on `window` not just by their `id` attribute but their
`name` attribute too. So the new setting was injected by
`<form name=admin id=ouruserid>`.

Exploiting the vulnerable url parsing for ajax
----------------------------------------------

    // load-scrap.js

    const urls = location.href.split('/')
    const user = urls[urls.length - 2]
    const title = urls[urls.length - 1]
    ...
    $.get(`/static/raw/${user}/${title}`)
    ...

We added some data in search parameter, hash works just as fine. Suppliying `?../../..`
to traverse to the dashboard was tricky because of the `.split('/')` part, but bypassed
using `?/../..\..` instead. This way the ajax loads the root dashboard page.

The flag was on the admin-s dashboard as a scrap with an un-guessable url.

