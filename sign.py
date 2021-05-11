import math
import random
import numpy as np
import hashlib


def hashFileContents(fileName):
  try:
    sha3Obj = hashlib.sha3_256()
    with open(fileName, "rb") as messageFile:
      sha3Obj.update(messageFile.read())
    return sha3Obj.hexdigest()
  except:
    print("Couldn't find a file named '" + fileName + "'")
    return


def padHash(hash, desiredBitLength):
  # the bytes used for the digest info were copied from
  # https://tools.ietf.org/html/rfc8017#section-9.2

  # this is WRONG, sha3-256 was used instead of sha-256 as the bytes indicate,
  # this wrong value was used because I couldn't figure out how to make a real
  # Digest from the specification in time (the specification used doesn't mention
  # sha3 as a valid hash to be used)
  # also, I guess something is better than nothing?
  hashWithDigestInfo = "3031300d060960864801650304020105000420" + hash


  # each character in hash represents a nibble
  # thus the byte amount in hash = len(hash) / 2

  # -3 due to the predifined three bytes that will be set
  amountOfFFBytes = int(desiredBitLength / 8) - int(len(hashWithDigestInfo) / 2) - 3

  return "0001" + ("ff" * amountOfFFBytes) + "00" + hashWithDigestInfo


def MGF1(mgfSeed, maskLen):
  T = ""
  hLen = 256 >> 3
  counter = 0

  while len(T) < maskLen:
    C = np.base_repr(counter, 16)
    C = "0" * (8 - len(C)) + C

    sha3Obj = hashlib.sha3_256((mgfSeed + C).encode())

    T = T + sha3Obj.hexdigest()

    counter += 1
  
  return T[:maskLen]


def OAEP(M, L=0, k=1024):
  mLen = len(M) >> 1
  hLen = 256 >> 3
  k = k >> 3 # k in bits shifted by 3 to be in bytes and times 2 to get to hexadecimal characters number

  sha3Obj = hashlib.sha3_256(np.base_repr(L, 16).encode())
  lHash = sha3Obj.hexdigest()

  PS = "00" * (k - mLen - 2*hLen - 2)
  DB = lHash + PS + "01" + M
  
  seed = np.base_repr(random.getrandbits(hLen << 3), 16)

  dbMask = MGF1(seed, k - hLen - 1)

  maskedDB = np.base_repr(int(DB, 16) ^ int(dbMask, 16), 16)

  seedMask = MGF1(maskedDB, hLen)

  maskedSeed = np.base_repr(int(seed, 16) ^ int(seedMask, 16), 16)

  EM = "00" + maskedSeed + maskedDB

  return EM


def invertOAEP(EM, L=0, k=1024):
  EM = "00" + np.base_repr(EM, 16)
  hLen = 256 >> 3
  k = k >> 3

  if(len(EM) != 256):
    return "0"

  maskedDB = EM[(hLen + 1) * 2:]

  seedMask = MGF1(maskedDB, hLen)

  maskedSeed = EM[2:(hLen + 1) * 2]

  seed = np.base_repr(int(maskedSeed, 16) ^ int(seedMask, 16), 16)

  dbMask = MGF1(seed, k - hLen - 1)

  DB = np.base_repr(int(maskedDB, 16) ^ int(dbMask, 16), 16)

  # special case because sha3_256 was used, mLen is ALWAYS 256 bits long
  mLen = 256 >> 3
  M = DB[-mLen * 2:]

  return M



def writeMessageSignature(fileNameToSign, messageSignature, modulus, useOAEP):
  with open(fileNameToSign, "w") as messageSign:
    messageSign.write("use-oeap:" + str(int(useOAEP)) + "\n")
    messageSign.write("key-mod:" + np.base_repr(modulus, 16) + "\n")
    messageSign.write("msg-sign:" + np.base_repr(messageSignature, 16) + "\n")


def readMessageSignature(fileNameOfSign):
  try:
    with open(fileNameOfSign, "r") as messageSign:
      useOAEP = bool(int(messageSign.readline().split("use-oeap:")[1]))
      modulus = messageSign.readline().split("key-mod:")[1][:-1]
      signature = messageSign.readline().split("msg-sign:")[1][:-1]

      if(len(modulus) != 256 or len(signature) != 256):
        return (useOAEP, (1, 1))

      return (useOAEP, (int(modulus, 16), int(signature, 16)))
  except:
    print("The file named '" + fileNameOfSign + "' doesn't exist, run this with --sign before verifying")
    return
