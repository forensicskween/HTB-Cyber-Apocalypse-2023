# Small StEps

************Category************: Crypto

****************Points:**************** 425

************************Difficulty:************************ very easy

## Description

As you continue your journey, you must learn about the encryption method the aliens used to secure their communication from eavesdroppers. The engineering team has designed a challenge that emulates the exact parameters of the aliens' encryption system, complete with instructions and a code snippet to connect to a mock alien server. Your task is to break it.

## Walkthrough

### Code Analysis

This is RSA encryption, with a small exponent, and large-ish primes:

```python
class RSA:

    def __init__(self):
        self.q = getPrime(256)
        self.p = getPrime(256)
        self.n = self.q * self.p
        self.e = 3

    def encrypt(self, plaintext):
        plaintext = bytes_to_long(plaintext)
        return pow(plaintext, self.e, self.n)
```

The main vulnerability to exploit, is that it’s a small exponent, with a small message. The fourth line of the script confirms this:

```python
assert len(FLAG) == 20
```

It checks that the length of the message is less than 20. Considering this is textbook RSA, if **m^e < n** , meaning if the message raised to the power of the exponent is less than the modulus, then we can do a cube root attack. 

### Exploit

We can use the gmpy2 library to find the cube root of the encrypted flag:

```python
from pwn import *
import gmpy2

host,port = '165.232.98.59',31758
conn = remote(host,port)

conn.sendlineafter(b'> ', b'E')
conn.recvuntil(b'N: ')
N = int(conn.recvline().strip().decode())
conn.recvuntil(b'The encrypted flag is: ')
enc = int(conn.recvline().strip().decode())

dec = gmpy2.iroot(enc,3)[0]

assert dec**3 < N

flag = bytes.fromhex(hex(dec)[2:])
print(flag.decode())
#HTB{5ma1l_E-xp0n3nt}
```

The assertion, ‘assert dec[0]**3 < int(N)’, verifies that the message raised to 3 is indeed smaller than N. 

**************Flag:************** HTB{5ma1l_E-xp0n3nt}