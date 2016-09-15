
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



import sys, hashlib, dns, gnupg, time, dns.resolver, base64, tempfile
import subprocess as sub
tempg = "/tmp/gpgop"
tempgg = "/tmp/gpgop.gpg"
tempgasc = "/tmp/gpgop.asc"

'''
Stephen Nightingale
HAD-Pilot project, NIST
night@nist.gov

compiled and extended from modules initiated by 
Daniel Lessoff
HAD-Pilot project, NIST
Jun-Aug 2014

These are common methods for pgpmail, the openpgp mail client.
'''

#A place to put stuff from the config file:
class FileParams:
  def __init__(self, myconfig):
    f = open(myconfig)
    lines = iter(f.readlines())
    f.close()

    self.sender = next(lines).strip()
    self.keyid = next(lines).strip()
    self.mailfile = next(lines).strip()

#Get file contents and return as a list:
def filein(afn):
    fpt = open(afn)
    aster = fpt.readlines()
    fpt.close()
    return aster

#Print the elements of a list:
def printbuffer(bufe):
  for el in bufe:
    print "\t%s" % (el)

#Print the elements of a dictionary:
def printdict(dicto):
  print "%d elements in mashes" % (len(dicto))
  for key in dicto:
    if isinstance(dicto[key], list):
      print "%s =" % (key)
      printbuffer(dicto[key])
    else:
      print "\t%s = %s" % (key, dicto[key])



#Return the command arguments:
def parseInput(herald):
  raw = raw_input(herald)
  return raw.split(" ")


#What keys are currently in our keystore?
def populateKeys(fp):
    fp.mykey = listkeys_result(gippy['gpg_list_keys']([]))


#Print the keys from the keystore:
def listKeys(fp):
    print "\n%s Keys in my Store:" % (timestring())
    for keyfob in fp.mykey:
        print "\t%s = %s" % (keyfob['keyid'], addrOnly(keyfob['uids']))
    print

#Strip out the address part of the uid:
def addrOnly(blob):
    blobs = blob.split('<')
    blurbs = blobs[1].split('>')
    return blurbs[0]


#Return key fingerprint for this client, else None:
def fingerAdder(fp, adder):
    fingerprint = None
    for keyfob in fp.mykey:
        if keyfob['uids'].find(adder) >= 0:
            #fingerprint = keyfob['fingerprint']
            fingerprint = keyfob['keyid']
    return fingerprint

#String to print todays date:
def presdate():
    localtime=time.localtime()
    return time.strftime("%m/%d/%Y",localtime)

#String to print the current time:
def prestime():
    localtime=time.localtime()
    return time.strftime("%H:%M:%S",localtime)

#Date and time string:
def timestring():
    return prestime() + " on " + presdate() + "."

#Get file contents and return as a string:
def filetostring(afn):
    fpt = open(afn)
    aster = fpt.readlines()
    thester = "".join(aster)
    fpt.close()
    return thester

#Write out a string to the given filename:
def stringtofile(data, afn):
  fd = open(afn, 'w')
  fd.write(data)
  fd.close()

#Invoke the nano editor and return its input:
def nano_input():
    f = tempfile.NamedTemporaryFile(mode='w+t',delete=False)
    n = f.name
    f.close()
    sub.call(['nano',n])
    with open(n) as f: return str(f.read())

#Generate the sha224 hash of the given input:
def write_hash(mhash, source, thash):
    if source in mhash:
      mhash[source].append(thash)
    else:
      mhash[source] = [thash]

#Get the PGP key cert for the given address and import into local keystore:
def getdns(address, arnum):
  addparts = address.split('@')
  hashaddress = hashlib.sha224(addparts[0]).hexdigest()+'._openpgpkey.'+addparts[1]
  #try:
  rlist = dns.resolver.query(hashaddress, arnum)
  print "Rlist:"
  print rlist.rrset
  #except:
  #  print "Not found in DNS: %s" % (hashaddress)
  #  return False

  print "\nAddress:\n"+hashaddress
  for rdata in rlist:
    print "\nData:\n"+str(rdata)+"\n"
    try: something = base64.b64decode(str(rdata))
    except: 
      print "Corrupted data, won't import to gpg keys."
      return False
    stringtofile(something, tempgg)
  rkey = gippy['gpg_import_keys'](tempgg)
  return True



#Confirm that mykey is the one used to verify:
def saign(astring, fp):
  print "saign: Stuff  to be Signed is:\n%s" % (astring)


#Get client key from DNS or return None:
def import_key(myrecipient, fp, arnum):
    rkey = 0; body = ""
    try:
        addrparts = myrecipient.split('@')
        hashaddress = hashlib.sha224(addrparts[0]).hexdigest()+'._openpgpkey.'+addrparts[1]
        body = "The DNS query string we used to look up your public key is: \n%s\n" % (hashaddress)
        print "DNS query string from %s\nis: %s" % (myrecipient, hashaddress)
        rlist = dns.resolver.query(hashaddress, arnum)
        for rdata in rlist:
            last = str(rdata)
            something = base64.b64decode(str(rdata))
            print "rlist: \n%s\n" % (last)
        rkey = gippy['gpg_import_keys'](something)
        print "Key imported from DNS: %s" % (rkey)
        body += "Key imported from DNS: %s\n" % (rkey)
    except:
        print "Could not import key from DNS into keystore: %s" % (sys.exc_info()[0])
        body = body + "Could not import key from DNS into keystore: %s\n" % (sys.exc_info()[0])
        rkey = 0
    return (rkey, body)

#Store client key in keystore:
def import_this_key(themess, fp):
    keyme = extractKeyFromMessage(themess)
    print "Key in Message is:\n%s" % (keyme)
    rkey = gippy['gpg_import_keys'](keyme)
    print "Import status: %s" % (rkey)
    return rkey


'''
A set of wrappers for gpg options.
'''

upg = "/usr/bin/gpg"
gippy = { \
          'gpg_list_keys' : lambda noarg: gpg_command([upg, '--list-keys']), \
          'gpg_delete_keys' : lambda gonkey: gpg_command([upg, '--delete-keys', gonkey]), \
          'gpg_import_keys' : lambda inkey: gpg_command([upg, '--import', inkey]), \
          'gpg_export_keys' : lambda finger: gpg_command([upg, "--armor", "--export", finger]), \
          'gpg_sign' : lambda signargs: gpg_command([upg, '--yes', '-a', '--sign', signargs[1]]), \
          'gpg_verify' : lambda fileto: gpg_command([upg, '--yes', '--verify', fileto[0]]), \
          'gpg_encrypt' : lambda encargs: gpg_command([upg, '--yes', '-a', '-r', encargs[0], '--encrypt', encargs[1]]), \
          'gpg_decrypt' : lambda fileto: gpg_command([upg, '--yes', '--decrypt', fileto[0]])\
        }



def gpg_command(cmd):
    try:
        proc = sub.Popen(cmd, shell=False, stdout=sub.PIPE)
        val = proc.communicate()[0]
    except:
        val = "gpg subprocess call failed: %s" % (cmd)
    return val

def listkeys_result(astring):
    thelist = []; adict = {}
    strings = astring.split('\n')
    for el in strings:
        if el.find('pub') == 0:
            (adict['keyid'], adict['date']) = keypubdate(el.strip())
            continue
        if el.find('uid') == 0:
            adict['uids'] = extractmail(el.strip())
            adict['fingerprint'] = "extractthis"
            continue
        if el.find('sub') == 0:
            (adict['skeyid'], adict['sdate']) = keypubdate(el.strip())
            continue
        if el.strip() == "":
            if len(adict) > 0:
                thelist.append(adict)
                adict = {}
            continue
    return thelist

def keypubdate(anel):
    ''' pub  2048R/FCEE5181  2014-9-10 '''
    kid = ""; dat = ""
    el = anel.replace('\t', ' ')
    parts = el.split('/')
    morts = parts[1].split(' ')
    kid = morts[0]
    dat = morts[1]
    return (kid, dat)

def extractmail(anel):
    ''' uid   J S Nightingale <j_s_nightingale@yahoo.co.uk> '''
    el = anel[3:]
    el = el.strip()
    return el


if __name__ == "__main__":
    print gippy[sys.argv[1]](sys.argv[2:])

