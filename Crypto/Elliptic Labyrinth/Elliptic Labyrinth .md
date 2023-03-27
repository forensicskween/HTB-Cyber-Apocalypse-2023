# Elliptic Labyrinth


************Category************: Crypto

****************Points:**************** 1000

************************Difficulty:************************ medium

## Description

As you navigate through the labyrinth inside the tomb, you encounter GPS inaccuracies that make it difficult to determine the correct path to the exit. Can you overcome the technical issues and use your instincts to find your way out of the maze?

## Walkthrough

First, I recommend sage to run this challenge appropriately (I always test out challenges before trying to solve them). 

### Code Analysis

This is an Elliptic Curve challenge, with a random prime and random parameters. The function  ‘**get_random_point**’ is the only thing really going on, and it returns a random point on the curve. 

There are three choices in the menu:

1. Retrieve the values of p, a, b. Except the bits of a and b are truncated. The amount by which it is truncated is ‘random’,  it’s any number in range (170,341). 
2. Print a random point on the curve
3. Get the encrypted flag. The flag is encrypted with AES-CBC. The key is the sha256 hash of ( a^b%p ) in bytes. So to decrypt the flag, we need to find the values of a, b, and p.

## Exploit

This is actually a very straight forward challenge. If we have the coordinates of two points on the curve, and the value of p, we can retrieve the values of **a** and **b**.

```python
import json
from hashlib import sha256
from Crypto.Util.number import getPrime, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pwn import *

host,port = '188.166.152.84',int(32079)
conn = remote(host,port)
conn.sendlineafter(b"> ", b'1')
params = conn.recvline()
p = eval(json.loads(params.strip())['p'])

conn.sendlineafter(b"> ", b'2')
p1 = conn.recvline()
A = json.loads(p1.strip())

conn.sendlineafter(b"> ", b'2')
p2 = conn.recvline()
B = json.loads(p2.strip())

conn.sendlineafter(b"> ", b'3')
ciph = conn.recvline()
ciph = json.loads(ciph.strip())
```

With those values, we can do a [parameter recovery attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ecc/parameter_recovery.py). 

```python
def attack(p, x1, y1, x2, y2):
    """
    Recovers the a and b parameters from an elliptic curve when two points are known.
    :param p: the prime of the curve base ring
    :param x1: the x coordinate of the first point
    :param y1: the y coordinate of the first point
    :param x2: the x coordinate of the second point
    :param y2: the y coordinate of the second point
    :return: a tuple containing the a and b parameters of the elliptic curve
    """
    a = pow(x1 - x2, -1, p) * (pow(y1, 2, p) - pow(y2, 2, p) - (pow(x1, 3, p) - pow(x2, 3, p))) % p
    b = (pow(y1, 2, p) - pow(x1, 3, p) - a * x1) % p
    return int(a), int(b)

x1,y1 = eval(A['x']),eval(A['y'])
x2,y2 = eval(B['x']),eval(B['y'])

a,b=attack(p, x1, y1, x2, y2)
```

Now, we just need to decrypt the ciphertext to get the flag!

```python
enc,iv = bytes.fromhex(ciph['enc']),bytes.fromhex(ciph['iv'])
key = sha256(long_to_bytes(pow(a, b,p))).digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(enc),16)

print(pt.decode())
#HTB{d3fund_s4v3s_th3_d4y!}

```

************Flag:************ HTB{d3fund_s4v3s_th3_d4y!}