import sign
import key_gen
import numpy as np

import sys

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
  print("--no-oaep   Uses a padding algorithm more like the one")
  print("            described on the original RFC")
  print("-h --help   Pints this message")
  print("\nIf no file name is given, the program defaults to 'message'")
  print("and thus generates a signature file named 'message.sign'\n")


def main():
  if(len(sys.argv) <= 1):
    printHelp()
    return

  generateKeysOnly = False
  verifySignature = False
  useOAEP = True

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
    elif(option == "--no-oaep" or option == "-n"):
      useOAEP = False
    else:
      fileNameToSign = option

  privKeyFileName = "rsa-priv"

  if(generateKeysOnly):
    keys = key_gen.generateKeys(1024)
    key_gen.writeKeys(keys)
    return
  
  if(not verifySignature):
    privKey = key_gen.readPrivKey(privKeyFileName)
    
    hashedMessage = sign.hashFileContents(fileNameToSign)
    
    if(useOAEP):
      paddedMessage = sign.OAEP(hashedMessage)
    else:
      paddedMessage = sign.padHash(hashedMessage, 1024)

    messageSignature = pow(int(paddedMessage, 16), privKey[1], privKey[0])
    
    sign.writeMessageSignature(fileNameToSign + ".sign", messageSignature, privKey[0], useOAEP)

    print("File '" + fileNameToSign + "' was signed successfully")
  else:
    hashedMessage = int(sign.hashFileContents(fileNameToSign), 16)

    (signUseOAEP, modAndSign) = sign.readMessageSignature(fileNameToSign + ".sign")

    valid = False

    if(signUseOAEP):
      EM = pow(modAndSign[1], 65537, modAndSign[0])
      hashFromSign = sign.invertOAEP(EM)
      valid = hashedMessage == int(hashFromSign, 16)
    else:
      hashedMessageFromSignature = pow(modAndSign[1], 65537, modAndSign[0]) & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
      valid = hashedMessage == hashedMessageFromSignature
    
    if(valid):
      print("Signature is valid for the message")
    else:
      print("Message signature doesn't match!")

main()