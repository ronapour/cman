# repo: github.com/ronapour; copyright: GPLv3

import sys
import json
import re
import zlib

def run():
  arn = sys.argv
  nArn = len(arn)

  if nArn != 3:
    usage("wrong number of arguments provided: %s (expected 2)"%(nArn),arn[0])
    sys.exit(1)

  fnameSource = arn[1]
  fnameDest = arn[2]

  perr("START: %s -> %s"%(fnameSource, fnameDest))

  wmBuf = None
  with open(fnameSource, 'rb') as fSource:
    wmBuf = fSource.read()
  assert wmBuf!=None

  LICMAP = {}
  clBuf = cleanWMs(wmBuf, LICMAP)
  assert len(wmBuf)==len(clBuf), [len(wmBuf), len(clBuf)]

  perr(">> STATS:")
  for lic in LICMAP:
    print(">> %5s instances of %s"%(LICMAP[lic],lic))

  with open(fnameDest, 'xb') as fSave:
    fSave.write(clBuf)

  mm = ("DONE: %s -> %s"%(fnameSource, fnameDest))
  perr(mm)
  perr('-'*len(mm))

def usage(message, nm):
  perr(message)
  perr("usage: %s <input.pdf> <output.pdf>"%(nm))
  perr("-----")
  perr("NOTE: <output.pdf> must be a \"new\" (i.e., non-existent) file so \n"+
       "      as to not overwrite anything by accident.")

def cleanWMs(wmBuf,LICMAP):
  off = 0
  cleanChunks = []
  for m in re.finditer(BRX_WATMSUS,wmBuf):
    watStart, watEnd = m.start(0), m.end(0)

    cleanChunks.append(wmBuf[off:watStart])
    off = watStart

    cleaned, licText = tryDeWat(m)
    if licText==None:
      assert cleaned==None
      cleanChunks.append(wmBuf[off:watEnd])
      off = watEnd
      continue

    assert cleaned!=None
    # perr("# LIC: %s"%(repr(decodeLic(licText))))

    lic = decodeLic(licText)
    if lic in LICMAP: LICMAP[lic]+=1
    else: LICMAP[lic]=1

    actual = m.group(0)
    assert len(cleaned)==len(actual) # deja-vu

    cleanChunks.append(cleaned)
    off = watEnd

  if off<len(wmBuf): cleanChunks.append(wmBuf[off:])
  
  return b''.join(cleanChunks)

def tryDeWat(m):
  gg = m.groups()
  assert len(gg)==5 # technically unnecessary

  c1, c2_Length, c3, c4_Contents, c5 = gg

  raw = c4_Contents
  if raw[0:2]==b'\r\n': raw=raw[2:]
  elif raw[0:1]==b'\n': raw=raw[1:]
  else:
    raise Exception(
      "stream bytes must start with either a '\\n' or a '\\r\\n' (but not a single '\\r')"
    )

  # TODO: sloppy; could well be a \r\n, a \r, or a \n; but we are sure it's always a \n
  #       in our particular case so let's pretend we don't care (yes, we must really use /Length)
  assert raw[-1:]==b'\n'
  raw = raw[:-1]

  rawWantedLen = int(c2_Length)
  rawActualLen = len(raw)
  assert rawWantedLen == rawActualLen

  dBuf = zlib.decompress(raw)

  lm = re.match(BRX_LIC,dBuf)
  if lm==None: return None,None

  licAsHex = re.sub(BRX_WHANY,b'',lm.group(2))
  licAsEnc = bytes.fromhex(licAsHex.decode('latin-1','strict'))
  # perr("# LIC [%s]"%(decodeLic(licAsEnc)))

  dBufLicless = b''
  dBufLicless += lm.group(1)
  lmLen = len(lm.group(0))
  while len(dBufLicless)<lmLen: dBufLicless+=b' '
  assert len(dBufLicless)==lmLen

  clean = b''

  clean += c1
  
  cBuf = (zlib.compress(dBufLicless))
  cLen = len(cBuf)
  assert cLen<=rawActualLen, [cLen, rawActualLen]

  c2_Length_new = str(cLen).encode('latin-1','strict')
  while len(c2_Length_new) < len(c2_Length):
    c2_Length_new = b' ' + c2_Length_new
  assert len(c2_Length_new)==len(c2_Length)

  clean += c2_Length_new
  clean += c3

  c4_Contents_new = b'\n'+cBuf+b'\n'
  clean += c4_Contents_new

  clean += c5

  wantedLength = len(m.group(0))
  while len(clean) < wantedLength:
    clean += b' '

  assert len(clean)==wantedLength, "len(clean)"

  return clean, licAsEnc

def decodeLic(licAsEnc):
  return b''.join(CHMAP[licAsEnc[e*2:(e*2)+2]] for e in range((len(licAsEnc)+1)>>1))

def perr(message):
  print(message, file=sys.stderr)

BRX_WATMSUS = re.compile(
  b'(<<[ \\r\\n]*/Filter[ \\r\\n]*/FlateDecode[ \\r\\n]*/Length[ \\r\\n]+)'+
  b'([0-9]*)'+
  b'([ \\r\\n]*>>[ \\r\\n]*stream)'+
  b'(.*?)'+
  b'(endstream)', re.S
)

BRX_LIC = re.compile(b'([ \\r\\n]*Q.*)<([^>]*)>[ \\r\\n]*Tj',re.S)

BRX_WHANY = re.compile(b'[ \\r\\n]+')

# spewed by another nasty script I wrote for the purpose
CHMAP = {
  (b'\x00'+(nm.to_bytes())): (ch.to_bytes()) for nm,ch in zip(
    b'\x03\x11\x13\x15\x17\x18\x1f!#$(*/6DFGHIJKLOPQRSUVWX\\]',
    b' .0245<>@AEGLSacdefghilmnoprstuyz'
  )
}


if __name__ != '__main__': raise Exception("exec!")

try: run()
except Exception as err:
  raise err
  perr("there were errors: \n%s\n"%(repr(err)))
  sys.exit(1)
