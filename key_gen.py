import random
import numpy as np


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
  possiblePrime = (3 << (bits - 2)) | possiblePrime | 1
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

  # This is VERY unlikely to ever happen, but this check brings me peace
  if(p == q):
    return generateKeys(bits)

  N = p*q
  L = (p - 1)*(q - 1)
  d = pow(e, -1, L)
  
  return {"sk": (N, d), "pk": (N, e)}


def writeKeys(keys, fileName="rsa-priv"):
  with open(fileName, "w") as keyFile:
    keyFile.write("rsa-priv-mod:" + np.base_repr(keys["sk"][0], 16) + "\n")
    keyFile.write("rsa-priv-key:" + np.base_repr(keys["sk"][1], 16) + "\n")


def readPrivKey(fileName):
  try:
    with open(fileName, "r") as keyFile:
      modulus = keyFile.readline().split("rsa-priv-mod:")[1]
      privExponent = keyFile.readline().split("rsa-priv-key:")[1]

      return (int(modulus, 16), int(privExponent, 16))
  except:
    print("Run this program with the option --gen-keys to generate keys before signing!")
    return
