import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import gzip 

sets = [b'%eFlP%"', b'%VhIy%"', b'%eUFw%"']

def parse_to_dict(data, sets):
	dictout = {}
	for setid in sets:
		new_dat = [i for i in data if i[0:7] == setid]
		keys = [i[7:17].decode() for i in new_dat]
		vals=[i[18:].replace(b'"',b'').decode() for i in new_dat]
		dictout.update(dict(zip(keys, vals)))
	return dictout


def parse_eval(data):
	not_sets = [i for i in data if i[0:7] not in sets]
	eval_strings = [i.decode() for i in not_sets if b'%' in i]
	evaled_=[]
	for eval_string in eval_strings:
		evaled = [dict_out[i] for i in eval_string.split('%') if i != '']
		evaled_.append(''.join(evaled))
	return evaled_


def decrypt(in_string):
	enc = base64.b64decode(in_string[3:])
	key = base64.b64decode('0xdfc6tTBkD+M0zxU7egGVErAsa/NtkVIHXeHDUiW20=')
	iv = base64.b64decode('2hn/J717js1MwdbbqMn7Lw==')
	cipher = AES.new(key,AES.MODE_CBC, iv)
	dec = unpad(cipher.decrypt(enc),16)
	decompressed = gzip.decompress(dec)
	with open('out.exe','wb') as outfile:
	 	outfile.write(decompressed)


def dump_exe(fname):
	with open(fname,'rb') as inf:
		data = [i.strip() for i in inf.readlines()]
	dict_out = parse_to_dict(data, sets)
	in_string = [i for i in data if i[0:3] == b':: '][0]
	commands = parse_eval(data)
	print(commands[2].replace(';','\n'))
	decrypt(in_string)



dump_exe('windows.bat')



