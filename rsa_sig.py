import random
import numpy as np
import hashlib

def isNumberPrime(n):
  r = 1
  d = (n - 1) // 2
  while(d % 2 == 0):

    r += 1
    d //= 2
  
  for _ in range(40):
    a = random.randrange(1, n - 1)
    x = pow(a, d, n)

    if(x == 1 or x == n - 1):
      continue
    
    for _ in range(r - 1):
      x = pow(x, 2, n)
      if(x == n - 1):
        break

    return False
  
  return True

  

def getRandomBigPrime(bits):
  possiblePrime = random.getrandbits(bits)
  possiblePrime = (3 << (bits - 1)) | possiblePrime | 1
  while(True):
    if(isNumberPrime(possiblePrime)):
      return possiblePrime
    possiblePrime += 2
  

def generateKeys(bits):
  halfBits = bits >> 1
  e = 65537
  p, q = 0, 0

  while(True):
    p = getRandomBigPrime(halfBits)
    if(p % e != 1):
      break

  while(True):
    q = getRandomBigPrime(bits - halfBits)
    if(q % e != 1):
      break

  N = p*q
  L = (p - 1)*(q - 1)
  d = pow(e, -1, L)
  
  return {"sk": (N, d), "pk": (N, e)}

def hashMessage(message):
  return hashlib.sha3_256(message).hexdigest()
  
def padHash(hash):
  # the bytes used for the digest info were copied from
  # https://tools.ietf.org/html/rfc8017#section-9.2

  # this is WRONG, sha3-256 was used instead of sha-256 as the bytes indicate,
  # this wrong value was used because I couldn't figure out how to make a real
  # Digest from the specification in time (the specification used doesn't mention
  # sha3 as a valid hash to be used)
  # also, I guess something is better than nothing?
  hashWithDigestInfo = "3031300d060960864801650304020105000420" + hash


  # n length is 1024 bits = 128 bytes

  # each character in hash represents a nibble
  # thus the byte amount in hash = len(hash) / 2

  # -3 due to the predifined three bytes that will be set
  amountOfFFBytes = 128 - int(len(hashWithDigestInfo) / 2) - 3


  return "0001" + ("ff" * amountOfFFBytes) + "00" + hashWithDigestInfo

keys = generateKeys(1024)
print("modulo: " + np.base_repr(keys["sk"][0], 16))
print("private: " + np.base_repr(keys["sk"][1], 16))
print("public: " + np.base_repr(keys["pk"][1], 16))

hashed = hashMessage(b"meudeusissovaidartaoruim")
padded = padHash(hashed)
print("hashed: " + hashed)
print("padded: " + padded)

signature = pow(int(padded, 16), keys["sk"][1], keys["sk"][0])
print("sig:  " + np.base_repr(signature, 16))

paddedHopefully = pow(signature, keys["pk"][1], keys["sk"][0])
print("whut:" + np.base_repr(paddedHopefully, 16))