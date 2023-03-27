# Multipage Recyclings

************Category************: Crypto

****************Points:**************** 1000

************************Difficulty:************************ easy

## Description

As your investigation progressed, a clue led you to a local bar where you met an undercover agent with valuable information. He spoke of a famous astronomy scientist who lived in the area and extensively studied the relic. The scientist wrote a book containing valuable insights on the relic's location, but encrypted it before he disappeared to keep it safe from malicious intent. The old man disclosed that the book was hidden in the scientist's house and revealed two phrases that the scientist rambled about before vanishing.

## Walkthrough

Another AES challenge. Again, the cipher mode is ECB, with the same key being reused. The main encryption function is as follows:

```python
def encrypt(self, message):
        iv = os.urandom(16)
        ciphertext = b''
        plaintext = iv
        blocks = self.blockify(message, 16)
        for block in blocks:
            ct = self.cipher.encrypt(plaintext)
            encrypted_block = self.xor(block, ct)
            ciphertext += encrypted_block
            plaintext = encrypted_block
        return ciphertext

```

Basically, the iv is encrypted with AES-ECB, then it is **xored** with the plaintext block. This new block is then reused as an iv. The main vulnerabilities are in the main/leak functions:

1. The message is repeated four times,  given that it gets xored at some point, it will be easy to recover the flag.

```python
message = pad(FLAG * 4, 16)
```

1. More importantly, the script performs a leak after encrypting the flag:

```python
def leak(self, blocks):
        r = random.randint(0, len(blocks) - 2)
        leak = [self.cipher.encrypt(blocks[i]).hex() for i in [r, r + 1]]
        return r, leak

[...]
ciphertext = aes.encrypt(message)
ciphertext_blocks = aes.blockify(ciphertext, 16)
r, leak = aes.leak(ciphertext_blocks)
```

The leak encrypts the block with AES-ECB again. Remember that in the encrypt function, each encrypted blocks is encrypted with AES-ECB, and is xored with the next block of plaintext. We can simply split the ciphertext into blocks and xor it with the leaked blocks

## Solution

```python
from pwn import xor

ct = bytes.fromhex('bc9bc77a809b7f618522d36ef7765e1cad359eef39f0eaa5dc5d85f3ab249e788c9bc36e11d72eee281d1a645027bd96a363c0e24efc6b5caa552b2df4979a5ad41e405576d415a5272ba730e27c593eb2c725031a52b7aa92df4c4e26f116c631630b5d23f11775804a688e5e4d5624')
r = 3
phrases = ['8b6973611d8b62941043f85cd1483244', 'cf8f71416111f1e8cdee791151c222ad']
leaks = [bytes.fromhex(i) for i in phrases]

ciphertext_blocks = [ct[i:i + 16] for i in range(0, len(ct), 16)]

plaintext_blocks = [xor(i,c) for i,c in zip(ciphertext_blocks[r+1:r+3], leaks)]
#[b'_w34k_w17h_l34kz', b'}HTB{CFB_15_w34k']
#we can reverse it to get the correct string

flag = b''.join(plaintext_blocks[::-1])
print(flag.decode())
#}HTB{CFB_15_w34k_w34k_w17h_l34kz
```

************Flag:************ HTB{CFB_15_w34k_w34k_w17h_l34kz}