from pwn import xor

ct = bytes.fromhex('bc9bc77a809b7f618522d36ef7765e1cad359eef39f0eaa5dc5d85f3ab249e788c9bc36e11d72eee281d1a645027bd96a363c0e24efc6b5caa552b2df4979a5ad41e405576d415a5272ba730e27c593eb2c725031a52b7aa92df4c4e26f116c631630b5d23f11775804a688e5e4d5624')
r = 3
phrases = ['8b6973611d8b62941043f85cd1483244', 'cf8f71416111f1e8cdee791151c222ad']
leaks = [bytes.fromhex(i) for i in phrases]

ciphertext_blocks = [ct[i:i + 16] for i in range(0, len(ct), 16)]
plaintext_blocks = [xor(i,c) for i,c in zip(ciphertext_blocks[r+1:r+3], leaks)]

flag = b''.join(plaintext_blocks[::-1])
print(flag.decode())
