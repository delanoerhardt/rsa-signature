import random
import numpy as np
import hashlib

import sys

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


def hashFileContents(fileName):
  sha3Obj = hashlib.sha3_256()
  with open(fileName, "rb") as messageFile:
    sha3Obj.update(messageFile.read())
  return sha3Obj.hexdigest()


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


def writeKeys(keys, fileName="rsa-priv"):
  with open(fileName, "w") as keyFile:
    keyFile.write("rsa-priv-mod:" + np.base_repr(keys["sk"][0], 16) + "\n")
    keyFile.write("rsa-priv-key:" + np.base_repr(keys["sk"][1], 16) + "\n")


def readPrivKey(fileName):
  with open(fileName, "r") as keyFile:
    modulus = keyFile.readline().split("rsa-priv-mod:")[1]
    privExponent = keyFile.readline().split("rsa-priv-key:")[1]

    return (int(modulus, 16), int(privExponent, 16))


def writeMessageSignature(fileNameToSign, messageSignature, modulus):
  with open(fileNameToSign, "w") as messageSign:
    messageSign.write("key-mod:" + np.base_repr(modulus, 16) + "\n")
    messageSign.write("msg-sign:" + np.base_repr(messageSignature, 16) + "\n")


def readMessageSignature(fileNameOfSign):
  with open(fileNameOfSign, "r") as messageSign:
    modulus = messageSign.readline().split("key-mod:")[1]
    signature = messageSign.readline().split("msg-sign:")[1]

    return (int(modulus, 16), int(signature, 16))

def printHelp():
  print("Usage")
  print("    python " + sys.argv[0] + " [option] [X]")
  print("Options:")
  print("--gen-keys  Generate 'rsa-priv' file with the private key that")
  print("            will be used to sign documents")
  print("--sign      Signs the document with the private key present")
  print("            in the file 'rsa-priv' for a file named X,")
  print("            generates a file named X.sign containing the")
  print("            signature and public modulus")
  print("--verify    Check whether the signature for the file named")
  print("            X present on the file named X.sign is valid")
  print("-h --help   Pints this message")
  print("\nIf no file name is given, the program defaults to 'message'")
  print("and thus generates a signature file named 'message.sign'\n")


def main():
  if(len(sys.argv) <= 1):
    printHelp()
    return

  generateKeysOnly = False
  verifySignature = False

  fileNameToSign = "message" # example file

  for option in sys.argv[1:]:
    if(option == "--help" or option == "-h"):
      printHelp()
      return
    elif(option == "--gen-keys" or option == "-g"):
      generateKeysOnly = True
    elif(option == "--sign" or option == "-s"):
      verifySignature = False
    elif(option == "--verify" or option == "-v"):
      verifySignature = True
    else:
      fileNameToSign = option

  privKeyFileName = "rsa-priv"

  if(generateKeysOnly):
    keys = generateKeys(1024)
    writeKeys(keys)
    return
  
  if(not verifySignature):
    privKey = 0
    try:
      privKey = readPrivKey(privKeyFileName)
    except:
      print("Run this program with the option --gen-keys to generate keys before signing!")
      return
      
    hashedMessage = 0
    try:
      hashedMessage = hashFileContents(fileNameToSign)
    except:
      print("Couldn't find a file named '" + fileNameToSign + "'")
      return 

    paddedMessage = padHash(hashedMessage, 1024)
    messageSignature = pow(int(paddedMessage, 16), privKey[1], privKey[0])
    writeMessageSignature(fileNameToSign + ".sign", messageSignature, privKey[0])

  else:
    hashedMessage = 0
    try:
      hashedMessage = int(hashFileContents(fileNameToSign), 16)
    except:
      print("Couldn't find a file named '" + fileNameToSign + "'")
      return

    modAndSign = 0
    try:
      modAndSign = readMessageSignature(fileNameToSign + ".sign")
    except:
      print("The file named '" + fileNameToSign + ".sign' doesn't exist, run this with --sign before verifying")
      return

    hashedMessageFromSignature = pow(modAndSign[1], 65537, modAndSign[0]) & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    
    if(hashedMessage == hashedMessageFromSignature):
      print("Signature is valid for the message")
    else:
      print("Message signature doesn't match!")

main()