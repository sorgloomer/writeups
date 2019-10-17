2019 Hitcon CTF quals - EmojiiVM
================================

https://ctf2019.hitcon.org/

Writeup by Tamás Hegedűs - !SpamAndHex


TL;DR
-----

Wrote an assembler that can push arbitrary ints and (almost) handles labels and
jumps. Then went ahead and assembled the nested loops. Did not implement proper
division, used a nice modulo-based hack to emulate divison by 10.


The challenge
-------------

We were given a native vm that used utf8 encoded emojis as its opcodes. The
architecture is stack based. There is no division nor pushing arbitrary ints.
There are opcodes for pushing ints between `0-10`. The task was to print a
formatted multiplication table up to 10*10.


Division by 10
--------------

Works when `x < 100`

```
def div10(x):
    return (x - x % 10) * 109 % 11

for i in range(120):
    print(i, div10(i))
```


Source
------

```python3
import socket
import subprocess


def main():
    main2()
    main3()


def main3():
    with open("src/emojivm_reverse/misc.src", "rb") as f:
        data = f.read()
    run_remote(data)


def run_remote(data):
    r = Remote("3.115.122.69", 30261)
    r.recv_until(b"-mb25 ")
    chall = r.recv_until(b"\n")
    print("Challenge:", chall)
    token = myexec("hashcash -mb25 " + chall.decode("utf-8")).strip()
    print("Token:", token)
    r.send(token + b"\n")
    r.recv_until(b"file size:")
    r.send(str(len(data)).encode("utf=8") + b"\n")
    r.recv_until(b"emoji file:")
    r.send(data)
    print(r.recv_all())


def main2():
    # r = Remote("3.115.122.69", 30261)
    code = f"""
    
    {push_number(64)}
    NEW
    PUSH_EMOJI 1
    PUSH_EMOJI 0
    PUSH_EMOJI 0
    ST
        :loop0
        PUSH_EMOJI 1
        PUSH_EMOJI 1
        PUSH_EMOJI 0
        ST
            :loop1
            PUSH_EMOJI 0
            PUSH_EMOJI 0
            LD
            {print_digit()}
            {print_text(" * ")}
            PUSH_EMOJI 1
            PUSH_EMOJI 0
            LD
            {print_digit()}
            {print_text(" = ")}
            PUSH_EMOJI 0
            PUSH_EMOJI 0
            LD
            PUSH_EMOJI 1
            PUSH_EMOJI 0
            LD
            MUL
            PUSH_EMOJI 2
            PUSH_EMOJI 0
            ST
            
            {push_number(11)}
            PUSH_EMOJI 10
            PUSH_EMOJI 2
            PUSH_EMOJI 0
            LD
            MOD
            PUSH_EMOJI 2
            PUSH_EMOJI 0
            LD
            SUB
            {push_number(109)}
            MUL
            MOD
            PUSH_EMOJI 3
            PUSH_EMOJI 0
            ST

            PUSH_EMOJI 3
            PUSH_EMOJI 0
            LD
            :before_tens
            PUSH_LABEL before_tens +29
            JMP_IF_FALSE
            PUSH_EMOJI 3
            PUSH_EMOJI 0
            LD
            {print_digit()}
            :after_tens
            
            
            PUSH_EMOJI 10
            PUSH_EMOJI 2
            PUSH_EMOJI 0
            LD
            MOD
            {print_digit()}

            {print_newline()}
            PUSH_EMOJI 1
            PUSH_EMOJI 0
            LD
            PUSH_EMOJI 1
            ADD
            PUSH_EMOJI 1
            PUSH_EMOJI 0
            ST
            PUSH_EMOJI 1
            PUSH_EMOJI 0
            LD
            PUSH_EMOJI 10
            SUB
            PUSH_LABEL loop1
            JMP_IF
        PUSH_EMOJI 0
        PUSH_EMOJI 0
        LD
        PUSH_EMOJI 1
        ADD
        PUSH_EMOJI 0
        PUSH_EMOJI 0
        ST
        PUSH_EMOJI 0
        PUSH_EMOJI 0
        LD
        PUSH_EMOJI 10
        SUB
        PUSH_LABEL loop0
        JMP_IF
    EXIT
    """

    with open("src/emojivm_reverse/misc.src", "wb") as f:
        f.write(compile(code).encode("utf-8"))
    myexec("/vagrant/emojivm /vagrant/misc.src > /vagrant/misc.out")
    with open("src/emojivm_reverse/misc.out", "r") as f:
        print(f.read())


def myexec(sh):
    return subprocess.check_output(
        ["vagrant", "ssh", "-c",  sh],
        cwd="src/emojivm_reverse"
    )


def print_digit():
    return code_from_lines([
        "PUSH_EMOJI 4",
        "PUSH_EMOJI 0",
        "ST",
        "PUSH_EMOJI 0",
        "PUSH_EMOJI 4",
        "PUSH_EMOJI 0",
        "LD"
    ] + make_number(ord("0")) + ["ADD", "FLUSH"])


def push_number(n):
    return code_from_lines(make_number(n))


def print_text(text):
    return code_from_lines(make_print(text))


def print_newline():
    return code_from_lines(make_number(0) + make_number(10) + ["FLUSH"])


def make_number(n):
    if n < 0:
        raise Exception("Negatives are not implemented")
    if n <= 10:
        return [f"PUSH_EMOJI {n}"]
    resp = make_number(10) + make_number(n // 10) + ["MUL"]
    if n % 10:
        resp.extend(make_number(n % 10) + ["ADD"])
    return resp


def pad(arr, l):
    return arr + ["NOP"] * (l - len(arr))


def make_print(text):
    result = []
    result.extend(make_number(0))
    for b in reversed(text.encode("utf-8")):
        result.extend(make_number(b))
    result.append("FLUSH")
    return result


def code_from_lines(lines):
    return "".join([l + "\n" for l in lines])


class Remote(object):
    def __init__(self, host, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))

    def send(self, data):
        self.socket.sendall(data)

    def recv_until(self, separator, strip=True):
        result = bytearray()
        while True:
            r = self.socket.recv(1)
            if not r:
                return bytes(result)
            result.extend(r)
            if result.endswith(separator):
                return bytes(result)[:-len(separator)] if strip else bytes(result)

    def recv_all(self):
        result = bytearray()
        while True:
            r = self.socket.recv(4096)
            if not r:
                return bytes(result)
            result.extend(r)


def keep_before(s, subs):
    return s.split(subs, 1)[0]


def compile(code):
    lines = code.split("\n")
    result = []
    labels = {}

    for line in lines:
        line = keep_before(line, "#").strip()
        if not line:
            continue
        op, *args = line.split()
        if op.startswith(":"):
            labels[op[1:]] = len(result)
            print("LABEL", op[1:], len(result))
        elif op == "PUSH_LABEL":
            delta = int(index_or_default(args, 1, "0"))
            addr = labels[args[0]] + delta
            print("PUSH_LABEL", args, addr)
            result.append(compile(code_from_lines(make_number(addr))))
        else:
            result.append(inst_dict[op])
            if op == 'PUSH_EMOJI':
                result.append(emoji_dict[args[0]])
    return "".join(result)


def index_or_default(items, i, default=None):
    if i < 0 or i >= len(items):
        return default
    return items[i]


inst_dict = {
    "NOP": "🈳",
    "ADD": "➕",
    "SUB": "➖",
    "MUL": "❌",
    "MOD": "❓",
    "XOR": "❎",
    "AND": "👫",
    "IS_LESS": "💀",
    "IS_EQ": "💯",
    "JMP": "🚀",
    "JMP_IF": "🈶",
    "JMP_IF_FALSE": "🈚",
    "PUSH_EMOJI": "⏬",
    "POP": "🔝",
    "LD": "📤",
    "ST": "📥",
    "NEW": "🆕",
    "FREE": "🆓",
    "READ": "📄",
    "POP_OBJ": "📝",
    "FLUSH": "🔡",
    "POP_INT64": "🔢",
    "EXIT": "🛑",
}

emoji_dict = {
    "0": "😀",
    "1": "😁",
    "2": "😂",
    "3": "🤣",
    "4": "😜",
    "5": "😄",
    "6": "😅",
    "7": "😆",
    "8": "😉",
    "9": "😊",
    "10": "😍",
}


if __name__ == "__main__":
    main()
```