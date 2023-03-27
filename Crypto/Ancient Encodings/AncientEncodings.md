# Ancient Encodings

**********Category:********** Crypto

**********Difficulty:********** very easy

**********Points:********** 350

### Description

Your initialization sequence requires loading various programs to gain the necessary knowledge and skills for your journey. Your first task is to learn the ancient encodings used by the aliens in their communication.

### Walkthrough

The encode function is the only function performed on the flag: 

```python
def encode(message):
    return hex(bytes_to_long(b64encode(message)))
```

The flag is base64 encoded, converted to a long integer, and then converted to a hexadecimal number in string format. 

### Decryption

There are two options: 
1. Python automatically converts hexadecimal numbers to long integers if they are declared without strings, so we can skip the hex decoding part. Then, we would need to convert the long integer into bytes and base64 decode it. 

```python
from Crypto.Util.number import long_to_bytes
import base64

flag = 0x53465243657a467558336b7764584a66616a4231636d347a655639354d48566664326b786246397a5a544e66644767784e56396c626d4d775a4446755a334e665a58597a636e6c33614756794d33303d
flag = long_to_bytes(flag)
flag = base64.b64decode(flag)
print(flag.decode())
#HTB{1n_y0ur_j0urn3y_y0u_wi1l_se3_th15_enc0d1ngs_ev3rywher3}
```

2. Automatically convert the hex to bytes, by declaring the flag variable without the ‘0x’ prefix. Then, same thing, base64 decode it. 

```python
import base64

flag = '0x53465243657a467558336b7764584a66616a4231636d347a655639354d48566664326b786246397a5a544e66644767784e56396c626d4d775a4446755a334e665a58597a636e6c33614756794d33303d'[2:]
flag = bytes.fromhex(flag)
flag = base64.b64decode(flag)
print(flag.decode())
#HTB{1n_y0ur_j0urn3y_y0u_wi1l_se3_th15_enc0d1ngs_ev3rywher3}
```

**********Flag:********** HTB{1n_y0ur_j0urn3y_y0u_wi1l_se3_th15_enc0d1ngs_ev3rywher3}