
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



import sys, os, time, dinsget
from ipcalc import Network
#ipcalc from PyPi:  https://pypi.python.org/pypi/ipcalc


#################################################################################################
#checkhost is the top function in spf, which does the dns lookups, then a syntactic and a semantic
#check, to return the spf processing result.
#checkhost, syntactic, semantic, are here.  DNS loookups come from imported dinsget.
#################################################################################################

#Checkhost is not recursive
#It returns result, reason and record:
def checkhost(ip, mf, hl):
  result = "none"; reas = "No SPF record."; work = ""

  spflookup = dinsget.domain_curse(hl)
  if len(spflookup) > 0 and len(spflookup) < 11:
    ix = 0
    for el in spflookup:
      work += "\tSyntax Results for: %s " % (el[0])
      (valid, reas, jobbie) = syntactic(el)
      work += jobbie
      if not valid:
        result = "permerror"
  else:
    if len(spflookup) > 10:
      reas = "Too many DNS lookups: SPF processing limit stipulates max 10."
      work += "%s\n" % (reas)     #Syntactic warnings.
      result = "permerror"
    valid = False

  #Early Bailout
  #return (result, reas, spflookup, work)

  if valid and result != "permerror":
    (result, reas, spflookup, jobsem) = semantic(ip, mf, hl, spflookup, spflookup[0][0])
    work += jobsem

  allels = []; 
  for alldns in spflookup:
    allels.append("%s == '%s'" % (alldns[0], None if (alldns[1] == None) else alldns[1] ))

  return (result, reas, "#".join([el for el in allels]), work)


#Validate the ipaddr and helo domain against the spf record:

def semantic(ipaddr, mailfrom, helo, spflookup, spfroot):
  result = "none"; reas = "No Result."; localwork = "\n"

  spfdict = listodict(spflookup)
  if spfroot in spfdict.keys():
    reck = spfdict[spfroot]
  else:
    return ("permerror", "included %s is not an SPF record." % (spfroot), spflookup, localwork)

  try: mex = reck.split(" ")
  except: 
    reas = "included %s is not a complete SPF record." % (spfroot)
    localwork += "%s\n" % (reas)
    return ("permerror", reas, spflookup, localwork)

  if ipaddr.find(".") >= 0:
    addtype = "ip4"
  elif ipaddr.find(":") >= 0:
    addtype = "ip6"
  else:
    addtype = "unknown"

  for mek in mex[1:]:  #ignore v=spf1

    if mek == '':
      continue

    if len(mek) > 3 and mek[:4].find("all") >= 0:
      #This mech determines the result for the current record:
      result = mekresult(mek)
      reas = "%s triggered: No match for this domain." % (mek)
      localwork += "%s\n" % (reas)
      return (result, reas, spflookup, localwork)


    elif mek.startswith("redirect"):
      mekparts = mek.split("=")

      #don't follow recursive references in the txt record!:
      if mekparts[1] == spfroot:
        reas = "SPF record '%s' has a recursive reference in %s" % (spfroot, mekparts[1])
        localwork += "%s\n" % (reas)
        return ("permerror", reas, spflookup, localwork)

      localwork += "\tRedirecting to Domain: %s\n" % (mekparts[1])
      return semantic(ipaddr, mailfrom, mekparts[1], spflookup, mekparts[1])
             #redirect result is main result; permerror possibility stomped out in syntax check.

    elif mek.find("include") >= 0:
      if mek.startswith("i"):
        mek = "+" + mek
      outcome = mek[0]
      mekparts = mek.split(":")

      #don't follow recursive references in the txt record!:
      if mekparts[1] == spfroot:
        reas = "SPF record '%s' has a recursive reference in %s" % (spfroot, mekparts[1])
        localwork += "%s\n" % (reas)
        return ("permerror", reas, spflookup, localwork)

      (result, reas, spflookup, newwork) = semantic(ipaddr, mailfrom, mekparts[1], spflookup, mekparts[1])
      localwork += newwork
      localwork += "\n\tInterim Result for %s: %s, Reason: %s\n" % (mekparts[1], result, reas)
      if result == "pass" or result == "permerror":
        return (result, reas, spflookup, localwork)
      else:
        continue

    elif mek.find("ip4:") >= 0:

      if addtype == "ip6":
        continue

      mekparts = mek.split(":")
      try: (mask, range) = mekparts[1].split("/")
      except: mask = mekparts[1]; range = 32 
      if ipaddr in Network(mask, range):
        reas = "\n\tSPF Match: (%s in %s)." % (ipaddr, mek)
        localwork += "%s\n" % (reas)
        return ("pass", reas, spflookup, localwork)
      else:
        localwork += "\tNo Match: (%s in %s)\n" % (ipaddr, mek)
        continue

    elif mek.find("ip6:") >= 0:

      if addtype == "ip4":
        continue

      mekparts = mek.split(":", 1)
      try: (mask, range) = mekparts[1].split("/")
      except: mask = mekparts[1]; range = 128
      if ipaddr in Network(mask, range):
        reas = "SPF Match: (%s in %s)." % (ipaddr, mek)
        localwork += reas
        return (result, reas, spflookup, localwork)
      else:
        localwork += "\tNo Match: (%s in %s)\n" % (ipaddr, mek)
        continue

    elif mek == "mx" or (len(mek) > 2 and mek[:3].find("mx")) >= 0:
      (limitres, mxd, dualcidr) = parsemechanism(mek, helo)
      (mach, matchstring, spflookup, mxwork) = matchmx(ipaddr, mxd, spflookup, int(dualcidr))
      localwork += mxwork
      if mach == "pass":
        return (limitres, matchstring, spflookup, localwork)
      else:
        continue


    elif mek == "a" or (len(mek) > 1 and mek[:2].find("a")) >= 0:
      (limitres, mxd, dualcidr) = parsemechanism(mek, helo)
      (mach, matchstring, spflookup, awork) = matcha(ipaddr, mxd, spflookup, int(dualcidr))
      localwork += awork
      if mach == "pass":
        return (limitres, matchstring, spflookup, localwork)
      else:
        continue


    elif mek == "ptr" or (len(mek) > 3 and mek[:4].find("ptr")) >= 0:
      localwork += "WARNING: RFC 7208 says DO NOT USE the ptr mechanism (%s).\n" % (mek)
      continue

    #The 'exists' mechanism is used to construct arbitrarily complex domains.
    #Not implemented here, for the time being:
    elif mek.find("exists") >= 0:
      return ("none", "%s mechanism not implemented." % (mek), spflookup, localwork)

    else:
      localwork += "\tUnprocessed mechanism: %s\n" % (mek)

  return (result, reas, spflookup, localwork)


#Do a syntactic check on the spf record:


def syntactic(spfrec):
  goodmex = ['a', '+a','mx', '+mx', 'ptr', '+ptr']
  (domn, reck) = spfrec   #spfrec is a tuple, length 2 of (domain, spfrecord)
  validity = True; reason = "Good Syntax."; workit = ""

  if reck == None:
    reason = "No Record."
    workit += "%s\n" % (reason)
    return (validity, reason, workit)

  if not reck.startswith("v=spf1"):
    reason = "An spf record must start with v=spf1"
    workit += "%s\n" % (reason)
    validity = False
    return (validity, reason, workit)

  if reck.find("+all") > 0:
    reason = "+all is a spam vector"
    workit += "%s\n" % (reason)
    validity = False
    return (validity, reason, workit)

  mex = reck.split(" ")
  lenmex = len(mex)
  mix = 1 

  for mek in mex[1:]:

    if mek == None:
      mix += 1
      continue

    if mek.startswith("redirect"):
      try:
        mekparts = mek.split("=")
        assert (len(mekparts) == 2)
        domparts = mekparts[1].split(".")
        assert (len(domparts) >= 2)
      except:
        reason = "\t\t%s: redirect mechanism: bad syntax." % (mek)
        workit += "%s\n" % (reason)
        validity = False

    elif mek.find("include") >= 0:
      try:
        mekparts = mek.split(":")
        assert (len(mekparts) == 2)
        domparts = mekparts[1].split(".")
        assert (len(domparts) >= 2)
      except:
        reason = "\t\t%s: include mechanism: bad syntax." % (mek)
        workit += "%s\n" % (reason)
        validity = False

    elif mek.find("ip4") >= 0:
      try:
        mekparts = mek.split(":")
        assert (len(mekparts) == 2)
        domparts = mekparts[1].split(".")
        assert (len(domparts) >= 4)
      except:
        reason = "\t\t%s: ip4 mechanism: bad syntax." % (mek)
        workit += "%s\n" % (reason)
        validity = False

    elif mek.find("ip6") >= 0:
      try:
        mekparts = mek.split(":", 1)
        assert (len(mekparts) == 2)
        domparts = mekparts[1].split(":")
        assert (len(domparts) >= 4)
      except:
        reason = "\t\t%s: ip6 mechanism: bad syntax." % (mek)
        workit += "%s\n" % (reason)
        validity = False

    elif mek.find("all") >= 0:
      try:
        assert (mek.startswith("-") or mek.startswith("~") or mek.startswith("?"))
        if mix < (lenmex - 1):
          reason = "WARNING: 'all' mechanism found before end of record. (%s)" % (reck)
          workit += "%s\n" % (reason)
          break
      except:
        reason = "\t\t%s: all mechanism: bad syntax." % (mek)
        workit += "%s\n" % (reason)
        validity = False

    elif mek.startswith("-a") or mek.startswith("~a") or mek.startswith("?a"):
      reason = "\t\t%s: a mechanism bad syntax" % (mek)
      workit += "%s\n" % (reason)
      validity = False
    elif mek.startswith("-mx") or mek.startswith("~mx") or mek.startswith("?mx"):
      reason = "\t\t%s: mx mechanism bad syntax" % (mek)
      workit += "%s\n" % (reason)
      validity = False
    elif mek.startswith("-ptr") or mek.startswith("~ptr") or mek.startswith("?ptr"):
      reason = "\t\t%s: ptr mechanism bad syntax" % (mek)
      workit += "%s\n" % (reason)
      validity = False

    else:
      if mek.find(':') > 0:
        meklets = mek.split(':')
        mek = meklets[0]
      if not inlist(mek, goodmex):
        reason = "Unknown mechanism: '%s'" % (mek)
        workit += "%s\n" % (reason)

    mix += 1

  if validity:
    workit += "%s\n" % ("Good Syntax.")

  return (validity, reason, workit)

      
#################################################################################################
#Supporting functions for spf below.
#Inc:listodict,printdict,mekresult,qualifier,matcha,matchmx,cidr_slice,parsemechanism,parsemek
#################################################################################################

#return True if el is a member of list inclu, else False.
def inlist(el, inclu):
	try:
		for member in inclu:
			if el == member: return True
	except: pass   #Handle empty lists.
	return False

#end def inlist(el, inclu).


#Listodict turns a list of tuples [(a, b), (c, d), ...] into a dictionary dict[a] = b:
def listodict(inlist):
  outdict = {}

  for el in inlist:
    outdict[el[0]] = el[1]

  return outdict

#Good old print dictionary:
def printdict(adict):
  for key in adict:
    print "\t%s = %s" % (key, adict[key])


#map the qualified all mechanism into an spf result:
def mekresult(mek):
  if mek.find("all") > 0:
    return qualifier(mek[0])
  else:
    return "permerror"

#map the +-~? qualifier into an spf result:
def qualifier(mekq):
  if mekq == '+': return "pass"
  if mekq == '-': return "fail"
  if mekq == '~': return "softfail"
  if mekq == '?': return "neutral"


#Check if the mx mechanism matches:
def matchmx(ipad, hulu, spflookup, arrange):
  result = "fail"; matchstring = "Empty list."; inwork = ""

  mxlookup = dinsget.domain_list(hulu, "mx")
  mxkey = "mx: " + hulu 
  spflookup.append((mxkey, '&'.join([el for el in mxlookup])))

  if len(mxlookup) == 0:
    return("fail", "Empty mx record: %s" % (mxkey), spflookup, inwork)

  for mxrec in mxlookup:
    (result, matchstring, spflookup, innwork) = matcha(ipad, mxrec, spflookup, arrange)
    inwork += innwork
    if result == "pass":
      reez = "\tMatch: (%s == mx:%s)\n" % (ipad, mxrec)
      inwork += reez
      return (result, matchstring, spflookup, inwork)
    else:
      reez = "\tNo Match: (%s in mx:%s)\n" % (ipad, mxrec)
      inwork += reez

  return (result, matchstring, spflookup, inwork)


#Check if the a mechanism matches:
def matcha(ipaddr, holo, spflookup, arrange):

  wok = ""
  mxip = dinsget.domain_list(holo, "a")
  akey = "a: " + holo
  spflookup.append((akey, '&'.join([el for el in mxip])))

  if len(mxip) == 0:
    wok = "\ta: result=fail, addr=(empty)\n"
    return("fail", "Empty a record: %s" % (akey), spflookup, wok)

  #try:
  for aadd in mxip:

    if any(c.isalpha() for c in aadd):
      continue

    if ipaddr in Network(aadd, arrange):
      result = "pass"
      reas = "\tMatch: (%s == a:%s)\n" % (ipaddr, aadd)
      wok = wok + reas
      return (result, reas, spflookup, wok)
    else:
      result = "fail"
      reas = "\tNo Match: (%s in a:%s)\n" % (ipaddr, aadd)
      wok = wok + reas
  #except:
  #  result = "fail"
  #  reas = "Bad record: %s does not match a:%s\n" % (ipaddr, aadd)
  #  wok = wok + reas

  return (result, reas, spflookup, wok)


#mx or a mechanisms may have a cidr range, parse it out:
def cidr_slice(mxdom, hel):
  dulce = 32

  if mxdom:
    matchin = mxdom
  else:
    matchin = hel

  if matchin.find("/") >= 0:
    (mxd, dulce) = matchin.split('/', 1)
  else:
    mxd = matchin

  return (mxd, dulce)


#Whole mechanism parse:
def parsemechanism(amek, hlo):
  mxdomain = None

  (qmek, mxdomain) = parsemek(amek)
  limitres = qualifier(qmek[0])
  (mxd, dualcidr) = cidr_slice(mxdomain, hlo)

  return (limitres, mxd, dualcidr)


#Parse mechanism and return qualified mech and domain if there is one:
def parsemek(amek):
  qmek = ""; mxdom = ""

  if not amek[0] in ['+', '-', '~', '?']:
    amek = '+' + amek
  if amek.find(':') > 0:
    (qmk, mxdom) = amek.split(':')
  else:
    qmk = amek

  return (qmk, mxdom)

#Add pretty whitespace to the '#' separated spf record string"
def formatSPFRecords(splee):
  interm = ""

  if splee.find("#") > 0:
    sprex = splee.split("#")
    for el in sprex:
      interm += "\t%s\n" % el
    if len(sprex) > 10:
      interm += "\tWARNING: Too Many Lookups for SPF! Max is 10!\n"
  else:
    if len(splee) > 0:
      interm += "\t%s\n" % splee

  return interm



#################################################################################################
#Main Method: if hadspf.py is to be called standalone.
#For each line in the testinput file, get the ip,mailfrom,helo inputs:
#Call checkhost and print the results.
#################################################################################################

if __name__ == "__main__":

  ix = 1 

  for line in open(sys.argv[1]):
    line = line.strip()
    if line == "":
      sys.exit()

    sysargv = line.split(' ')
    interim = "\n[%d]: spf args: ip=%s from=%s dom=%s\n" % (ix, sysargv[0], sysargv[1], sysargv[2])
    ipadd = sysargv[0]
    mailfrom = sysargv[1]
    helo = sysargv[2]
    os.write(2, "\nSPF lookup for %s:" % (helo))
    (mek, ree, splee, inter) = checkhost(ipadd, mailfrom, helo)
    interim += inter
    interim += formatSPFRecords(splee)
    final = "FinalResult: %s(%s)\tResult=%s,\tReason=%s\n" % (helo, ipadd, mek, ree)
    interim += final
    print interim; os.write(2, "[%d]: %s" % (ix, final))

    ix += 1
    if len(sys.argv) == 3 and ix > int(sys.argv[2]): 
      break
    else:
      time.sleep(1) #Prevent DOS attack on the DNS.


