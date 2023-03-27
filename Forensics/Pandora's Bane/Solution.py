
from my_vals import *
import subprocess
from pwn import xor
import shutil
import glob
import os

def sub_process(fname,i):
    command = ['ilspycmd', '-o', str(i), '-p', fname]
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()

def parse(my_vars):
    os.mkdir('shells')
    for i in range(len(my_vars)):
        fname = 'shells/' + str(i) + '.exe'
        with open(fname, 'wb') as of:
            of.write(my_vars[i])
        os.mkdir('shells/'+str(i))
        sub_process(fname,'shells/'+str(i))
        shutil.rmtree('shells/' + str(i) + '/Properties')
        for file in glob.glob('shells/'+str(i) + '/*/**' ,recursive=True):
            if file.endswith('.cs'):
                dat = open(file,'r').read()
                if 'shellcode' in dat:
                    pt = dat.replace('\t','').replace('\n','')
                    shellcode_idx = pt.find('shellcode')
                    end_arr = pt[shellcode_idx:].find('}')
                    shellcode = pt[shellcode_idx:shellcode_idx+end_arr]
                    shellcode = eval(shellcode[shellcode.find('{')+1:])
                    key_idx = pt[shellcode_idx+end_arr:].find('{') 
                    key_end = pt[shellcode_idx+end_arr+key_idx:].find('}')
                    key = eval(pt[shellcode_idx+end_arr+key_idx:shellcode_idx+end_arr+key_idx+key_end][1:])
                    enced = xor(shellcode,key)
                    if b'HTB' in enced:
                        print(enced[enced.find(b'HTB'):])
                    else:
                        print(enced) 

my_vars = [i for i in my_vars if i!= b'']
parse(my_vars)

