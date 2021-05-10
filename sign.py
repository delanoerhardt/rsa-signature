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


def writeMessageSignature(fileNameToSign, messageSignature, modulus):
  with open(fileNameToSign, "w") as messageSign:
    messageSign.write("key-mod:" + np.base_repr(modulus, 16) + "\n")
    messageSign.write("msg-sign:" + np.base_repr(messageSignature, 16) + "\n")


def readMessageSignature(fileNameOfSign):
  try:
    with open(fileNameOfSign, "r") as messageSign:
      modulus = messageSign.readline().split("key-mod:")[1]
      signature = messageSign.readline().split("msg-sign:")[1]

      return (int(modulus, 16), int(signature, 16))
  except:
    print("The file named '" + fileNameOfSign + "' doesn't exist, run this with --sign before verifying")
    return
