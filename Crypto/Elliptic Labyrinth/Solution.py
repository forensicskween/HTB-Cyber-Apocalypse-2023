import json
from hashlib import sha256
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from pwn import *

host,port = '188.166.152.84',int(32079)

def get_parameters(host,port):
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
    return p,A,B,ciph


def attack(p, x1, y1, x2, y2):
    a = pow(x1 - x2, -1, p) * (pow(y1, 2, p) - pow(y2, 2, p) - (pow(x1, 3, p) - pow(x2, 3, p))) % p
    b = (pow(y1, 2, p) - pow(x1, 3, p) - a * x1) % p
    return int(a), int(b)



def decrypt_values(host,port):
    p,A,B,ciph = get_parameters(host,port)
    x1,y1 = eval(A['x']),eval(A['y'])
    x2,y2 = eval(B['x']),eval(B['y'])
    a,b=attack(p, x1, y1, x2, y2)
    enc,iv = bytes.fromhex(ciph['enc']),bytes.fromhex(ciph['iv'])
    key = sha256(long_to_bytes(pow(a, b,p))).digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(enc),16)
    print(pt.decode())
    #HTB{d3fund_s4v3s_th3_d4y!}

decrypt_values(host,port)