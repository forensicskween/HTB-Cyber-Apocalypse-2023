import string
from pwn import *
from sage.all import *

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

