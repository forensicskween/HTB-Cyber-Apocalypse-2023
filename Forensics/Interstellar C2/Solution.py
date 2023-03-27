import base64
from Crypto.Cipher import AES 
from Crypto.Util.Padding import unpad
import re
import filetype
import os 
import gzip

def isBase64(sb):
    try:
        if isinstance(sb, str):
                # If there's any unicode here, an exception will be thrown and the function will return false
                sb_bytes = bytes(sb, 'ascii')
        elif isinstance(sb, bytes):
                sb_bytes = sb
        else:
                raise ValueError("Argument must be string or bytes")
        return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
    except Exception:
            return False


def parse_file(fname):
	with open(fname,'rb') as inf:
		data = inf.read()
	return data

def decrypt(enc, key):
  if isBase64(enc):
    enc = base64.b64decode(enc)
  iv = enc[0:16]
  key = base64.b64decode(key)
  cipher = AES.new(key, AES.MODE_CBC, iv)
  out = cipher.decrypt(enc[16:])
  if isBase64(out[:-16]):
    out = base64.b64decode(out[:-16])
  return out


def do_primer(primer_file):
  key = "DGCzi057IDmHvgTVE2gm60w8quqfpMD+o8qCBGpYItc="
  enc_primer = parse_file(primer_file)
  primer_val= decrypt(enc_primer, key)
  val2 = re.findall(b"RANDOMURI19901(.*)10991IRUMODNAR", primer_val)
  val3 = re.findall(b"URLS10484390243(.*)34209348401SLRU", primer_val)
  val4 = re.findall(b"KILLDATE1665(.*)5661ETADLLIK", primer_val)
  val5 = re.findall(b"SLEEP98001(.*)10089PEELS", primer_val)
  val6 = re.findall(b"JITTER2025(.*)5202RETTIJ", primer_val)
  val7 = re.findall(b"NEWKEY8839394(.*)4939388YEKWEN", primer_val)
  val8 = re.findall(b"IMGS19459394(.*)49395491SGMI", primer_val)
  randomURI = val2[0]
  stringURLS = val3[0]
  killDate = val4[0]
  sleep = val5[0]
  jitter = val6[0]
  key2 = val7[0]
  stringIMGS = val8[0]
  return randomURI, stringURLS, killDate, sleep, key2, stringIMGS, jitter

def parse_image_strings(stringIMGS):
  _re = re.compile(b"(?<=\")[^\"]*(?=\")|[^\" ]+")
  _newImgs = re.findall(_re,stringIMGS.replace(b',',b''))
  _newImgs = [i for i in _newImgs if i!=b'']
  _newImgs = [base64.b64decode(i) for i in _newImgs]
  return _newImgs


def parse_imagefile(data,key,imgs_data,fn):
  fn = fn.split('(')[-1].replace(')','')
  indexes = len([i for i in imgs_data if i in data][0])
  len_random_string = 1500 - indexes
  enc_data = data[indexes+len_random_string:]
  dec_data = decrypt(enc_data,key)
  uncompressed = gzip.decompress(dec_data)
  if isBase64(uncompressed):
    uncompressed = base64.b64decode(uncompressed)
  guess = filetype.guess(uncompressed)
  if not guess:
    ext = 'txt'
  else:
    ext = guess.extension
  with open('decrypted/' + fn + '.'+ ext, 'wb') as of:
     of.write(uncompressed)




def decrypt_inf(encf,key2):
  cmds = []
  text = decrypt(encf, key2)
  if text.lower().startswith(b'multicmd'):
    text2 = text.replace(b'multicmd',b'')
    array2 = text2.split(b"!d-3dion@LD!-d")
    array2 = [i for i in array2 if i != b'']
    for val in array2:
      taskid = val[0:5]
      cmd = val[5:]
      if cmd.lower().startswith(b'exit'):
        print("its an exit")
      if cmd.lower().startswith(b'loadmodule'):
        s = cmd.replace(b'loadmodule',b'')
        deced = base64.b64decode(s)
        ext = filetype.guess(deced).extension
        #Exec(stringBuilder.ToString(), taskid, key)
        fname = 'decrypted/module_' + taskid.decode() + '.' + str(ext)
        with open(fname,'wb') as of:
          of.write(deced)
      if cmd.lower().startswith(b'run-dll-background') or cmd.lower().startswith(b'run-exe-background'):
        #rAsm(cmd)
        s = cmd.replace(b'run-dll-background')
        deced = base64.b64decode(s)
        ext = filetype.guess(deced).extension
        fname = 'decrypted/background_exe' + taskid.decode() + '.' + str(ext)
        with open(fname,'wb') as of:
          of.write(deced)
  else:
    cmds.append(text)
  return cmds


def get_good_files():
  fnames = os.listdir()
  bad = [b'<head', b'<body', b'STATUS 200\n', b'OK\n']
  os.mkdir('decrypted')
  good = []
  for fn in fnames:
    encbuf = parse_file(fn)
    if not any(b in encbuf for b in bad):
      good.append(fn)
  return good

def decrypt_c2():
  good = get_good_files()
  primer_file = [i for i in good if 'Theda' in i][0]
  good.pop(good.index(primer_file))
  randomURI, stringURLS, killDate, sleep, key2, stringIMGS, jitter = do_primer(primer_file)
  imgs_data = parse_image_strings(stringIMGS)
  done = []
  for fn in good:
    encbuf = parse_file(fn)
    if encbuf[0:4] == b'\x89PNG':
      parse_imagefile(encbuf,key2,imgs_data,fn)
    else:
     done.append(decrypt_inf(encbuf, key2))


