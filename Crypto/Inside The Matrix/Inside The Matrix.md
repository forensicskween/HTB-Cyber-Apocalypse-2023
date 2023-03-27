# Inside The Matrix


************Category************: Crypto

****************Points:**************** 1000

************************Difficulty:************************ easy

## Description

As you deciphered the Matrix, you discovered that the astronomy scientist had observed that certain stars were not real. He had created two 5x5 matrices with values based on the time the stars were bright, but after some time, the stars stopped emitting light. Nonetheless, he had managed to capture every matrix until then and created an algorithm that simulated their generation. However, he could not understand what was hidden behind them as he was missing something. He believed that if he could understand the stars, he would be able to locate the secret tombs where the relic was hidden.

## Walkthrough

First, I recommend sage to run this challenge appropriately (I always test out challenges before trying to solve them). 

### Code Analysis

**********************class Book:**********************

```python
class Book:

    def __init__(self):
        self.size = 5
        self.prime = None

    def parse(self, pt: bytes):
        pt = [b for b in pt]
        return matrix(GF(self.prime), self.size, self.size, pt)

    def generate(self):
        key = os.urandom(self.size**2)
        return self.parse(key)

    def rotate(self):
        self.prime = random_prime(2**6, False, 2**4)

    def encrypt(self, message: bytes):
        self.rotate()
        key = self.generate()
        message = self.parse(message)
        ciphertext = message * key
        return ciphertext, key
```

**main function:**

First, everything is initialised like this:

```python
#assert len(FLAG) == 25
#[...]
book = Book()
ciphertext, key = book.encrypt(FLAG)
page_number = 1

```

Then, we are given three options:

1. **[L]ook at page:**

This prints the ciphertext, the key and the page_number. The ciphertext and the key are printed as matrices.

```python
print(ciphertext, key, page_number)
```

1. **[T]urn page**

This will encrypt the flag again, but won’t print anything:

```python
ciphertext, key = book.encrypt(FLAG)
page_number += 2
```

1.  **[C]heat**

This will print the ciphertext and the key as lists:

```python
print(f"\n{list(ciphertext)}\n{list(key)}\n")
```

Each time the ****************book.encrypt**************** function is passed:

- the prime is **reset**
- a new key consisting of 25 random bytes is generated and passed to a matrix over FiniteField of the prime
- the message is passed to a matrix over FiniteField of the prime
- the cipher text is calculated as key*message

### Solution

I used a bruteforce attack in Sage, because for the life of me I cannot understand how the math behind it works. 

### 1. We ask the server to re-generate ciphertexts, so that we have enough values to compare and brute-force.

```python
import string
from pwn import *

allprimes = [17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61]
host,port='159.65.81.51',int(31121)
valid = ['H','T','B','{','}']

def parse_res(res):
    res = [eval(i) for i in res[1:-2].decode().split('\n')]
    return res[0],res[1]

all_tests=[]
p=remote(host,port)
for _ in range(200):
    p.recvuntil("> ")
    p.sendline("T")
    p.recvuntil("> ")
    p.sendline("C")
    res = p.recvuntil("\n\n")
    ct,key = parse_res(res)
    all_tests.append((list(ct),list(key)))

```

### 2. Functions for bruteforce

There are three functions I used to bruteforce the values. 

The main one is ************************************check_matrix_quick:************************************

```python
def check_matrix_quick(ct,k):
 all_mats_test=[]
 for prime in allprimes:
  matrixct = matrix(GF(prime), 5, 5, ct)
  matrixk = matrix(GF(prime), 5, 5, k)
  if tuple(list(matrix(ct)[0])) == tuple(list(matrixct)[0]):
   if tuple(list(matrix(k)[0]))  ==  tuple(list(matrixk)[0]):
       try:
        mat_out = matrixct/matrixk
        pp = check_prime(list(mat_out)[0])
        if pp == prime:
         bruted = brute_mat(prime,list(mat_out))
         if bruted:
            good=0
            zippio=list(zip(valid,bruted[0:4]+bruted[-1:]))
            for i,c in zippio:
               if i in c:
                  good +=1
            if good == 5:
               all_mats_test.append(bruted)
       except:
           pass
 return all_mats_test

```

This function takes each ciphertext-key pair, and assigns to a matrix for each possible primes. If the first round of check passes, we divide the ciphertext with the key, so that we get the **original matrix.**

Then, for the divided matrix, we re-check the prime (function **check_prime**), by comparing to known plaintext values (the integer representation of ‘HTB{’):

```python
def check_prime(divided_mat):
    check_crs = divided_mat[0:4]
    pt_chrs = (72, 84, 66, 123)
    primex = 0
    for i,c in zip(check_crs,pt_chrs):
        for prime in allprimes:
            if c%prime == i:
                primex=prime
            else:
                pass
    return primex
```

If this check returns true, and matches the prime we previously checked, we then brute force the matrix again, this time checking every integer representation of ‘ascii.printable’ characters  mod prime, and comparing it to the value in the divided matrix. If it matches, then it will append the char as a potential value. It’s essential to check every possible option, because more than one value can be true. 

```python
def brute_mat(primex,divided_mat):
    divided_mat = [item for sublist in divided_mat for item in sublist]
    found = []
    for c in divided_mat:
     cmap=[]
     for i in [ord(i) for i in string.printable]:
        if i%primex == c:
                cmap.append(chr(i))
     found.append(cmap)
    return found
```

Finally, if the brute_mat function comes back True (ie - it’s not empty), we check the output a final time:
if the first fourth characters match ‘HTB{’, and the last character matches ‘}’, then we can safely say that we checked all potential options. 

Every single output of the ‘check_matrix_quick’ function, which essentially is a bunch of steps to arrive to the the ‘**brute_mat**’ function, will be appended to a list. 

The ******************brute_mat****************** function returns a list of list of potential characters at each position of the matrix. I found that the fastest way to retrieve the flag was to make a new list, at every position. 

Basically, we brute-forced 200 ciphertext-key pairs. Every single combination tested returned a ****************************list of list of potential characters for each position in the matrix****************************. This is an example of one of the brute-forced outputs:

```python
[['H', 'w'], ['%', 'T'], ['B', 'q'], ['L', '{'], ['=', 'l'], ['0', '_'], ['0', '_'], ['\r', '<', 'k'], ['0', '_'], ['@', 'o'], ['E', 't'], ['0', '_'], ['7', 'f'], ['\n', '9', 'h'], ['3', 'b'], ['0', '_'], ['D', 's'], ['E', 't'], ['4', 'c'], ['C', 'r'], ['D', 's'], ['!', 'P'], ['!', 'P'], ['!', 'P'], ['N', '}']]
```

So the first item in each of these lists is the first character of the flag, etc etc… To clean things up, we can group all bruteforced lists by character position, then check each position for the characters that occurs the most. With around 200 values, it’s a precise way of doing it. Thus, the final code is:

```python
def brute_all_matrices(all_tests):
   valid_brutes=[]
   plain_text = []
   for i in range(len(all_tests)):
       testct=all_tests[i][0]
       testk=all_tests[i][1]
       x = check_matrix_quick(testct,testk)
       if len(x) == 1:
         valid_brutes.append(x[0])
   for i in range(25):
     flat_vals = [item for sublist in [val[i] for val in valid_brutes] for item in sublist]
     max_char = max(flat_vals,key=flat_vals.count)
     plain_text.append(max_char)
   return ''.join(plain_text)

flag = brute_all_matrices(all_tests)
print(flag)
#HTB{l00k_@t_7h3_st4rs!!!}
```

```python
sage --python solve.sage
```

**************Flag:************** HTB{l00k_@t_7h3_st4rs!!!}