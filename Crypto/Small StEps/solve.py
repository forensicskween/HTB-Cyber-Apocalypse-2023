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