
'''
This software was developed by employees of the National Institute of 
Standards and Technology (NIST), an agency of the Federal Government. 
Pursuant to title 17 United States Code Section 105, works of NIST 
employees are not subject to copyright protection in the United States 
and are considered to be in the public domain. Permission to freely 
use, copy, modify, and distribute this software and its documentation 
without fee is hereby granted, provided that this notice and disclaimer 
of warranty appears in all copies.

THE SOFTWARE IS PROVIDED 'AS IS' WITHOUT ANY WARRANTY OF ANY KIND, 
EITHER EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, 
ANY WARRANTY THAT THE SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY 
IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, 
AND FREEDOM FROM INFRINGEMENT, AND ANY WARRANTY THAT THE DOCUMENTATION 
WILL CONFORM TO THE SOFTWARE, OR ANY WARRANTY THAT THE SOFTWARE WILL BE 
ERROR FREE. IN NO EVENT SHALL NASA BE LIABLE FOR ANY DAMAGES, INCLUDING, 
BUT NOT LIMITED TO, DIRECT, INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES, 
ARISING OUT OF, RESULTING FROM, OR IN ANY WAY CONNECTED WITH THIS SOFTWARE, 
WHETHER OR NOT BASED UPON WARRANTY, CONTRACT, TORT, OR OTHERWISE, WHETHER 
OR NOT INJURY WAS SUSTAINED BY PERSONS OR PROPERTY OR OTHERWISE, AND 
WHETHER OR NOT LOSS WAS SUSTAINED FROM, OR AROSE OUT OF THE RESULTS OF, 
OR USE OF, THE SOFTWARE OR SERVICES PROVIDED HEREUNDER.
'''




import sys, os, hashlib, base64 
psalts = "ps"  # alternates for + and / are (p)lus, (s)lash.
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Signature import PKCS1_v1_5

''' hasher.py '''

#Given an address, a private key and an algorithm
#return the hash of the address using the key and the algorithm.

def hash_the_address(addr, priv):

  h = SHA1.new(addr)
  key = RSA.importKey(open(priv).read())
  signer = PKCS1_v1_5.new(key)
  signature = signer.sign(h)
  return base64.b64encode(signature)


def old_hash_the_address(addr, priv):
  digest = hashlib.sha1(addr).digest()
  rsa = m2.RSA.load_key(priv)
  sig = rsa.sign(digest)
  return base64.b64encode(sig, psalts)

def old_digest_the_address(addr, priv, alg):
  digest = hashlib.sha1(addr).digest()
  rsa = m2.RSA.load_key(priv)
  sig = rsa.sign(digest, alg)
  sog = base64.b64encode(sig, psalts)
  return sog

#Given an address, a signature, a public key and an algorithm
#return the value after verifying the decoded signature using the key and algorithm

def verify_the_address(addr, sig, allregs):
  theregs = open(allregs).read()
  regadds = theregs.split('\n')
  for add in regadds:
    bits = add.split("&")
    if addr == bits[0].lower() and sig.find(bits[2]) >= 0:
      return True
  return False

if __name__ == "__main__":
  priv = "../.domainkeys/rsa.private"
  regs = "registered.txt"

  try:
    addr = sys.argv[1]
  except: sys.exit("Usage: python hasher.py <an address>")

  sign = hash_the_address(addr, priv)
  print "Signature: ", sign
  verf = verify_the_address(addr, sign, regs)
  print "Verification: ", verf

