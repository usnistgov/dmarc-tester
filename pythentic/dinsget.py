
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



#!/usr/bin/python

import sys ; sys.path.insert(0, '..')
import DNS

def main(args):
  nin = args[1]; qin = args[2]

  DNS.ParseResolvConf()
  r = DNS.DnsRequest(name=nin,qtype=qin)
  a=r.req()
  a.show()

#Return the first TXT record value from a given domain:
#Use this for dkim, dmarc and general txt records.
def domain(nin, qin="txt"):

  if nin == "":
    return "Empty domain for SPF lookup: '%s'" % (nin)

  if nin.find('!') >= 0:
    nins = nin.split('!', 1)
    nin = nins[0]

  DNS.ParseResolvConf()
  try:
    if nin[-1] == ".":
      nin = nin[:-1]
    r = DNS.DnsRequest(name=nin, qtype=qin)
    a = r.req()
    # el is a list or a string:
    for el in a.answers:
      x = el['data']
      if isinstance(x, list):
        return x[0]
      elif isinstance(x, tuple):
        return x[1]
      else:
        return x
  except:
    return "Corrupted SPF lookup for '%s'" % (nin)

#Return the list of all TXT record values from a given domain:
#use this for spf.
def domain_list(nin, qin="txt"):
  listodoms = []
  DNS.ParseResolvConf()
  try:
    if nin[-1] == ".":
      nin = nin[:-1]
    r = DNS.DnsRequest(name=nin, qtype=qin)
    a = r.req()
    # el is a list or a string:
    for el in a.answers:
      x = el['data']
      if isinstance(x, list):
        listodoms.extend(x)
      elif isinstance(x, tuple):
        listodoms.append(x[1])
      else:
        listodoms.append(x)
  except:
    print "Corrupted lookup for %s" % (nin)

  return listodoms


#Return the tuple of recursive domains and their domain names for spf (if redirect and include):
#Ignore non-spf txt records.
#Only recursively dive the first spf record.
def domain_curse(nin):
  txtlist = []; newrex = []
  cursrex = domain_list(nin)
  for onetxt in cursrex:
    if onetxt.startswith("v=spf1"):
      txtlist.append(onetxt)
      break;  #only look for one spf record, at the mo.
    
  if len(txtlist) == 0:
    return newrex

  newrex = [(nin, txtlist[0])]

  if newrex[0][0] == "" or newrex[0][1] == "":
    return  newrex

  try: 
    meks = newrex[0][1].split(' ')
  except: 
    print "TXT record syntax error: %s" % (newrex)
    return newrex

  for el in meks:
    if el.startswith('redirect'):
      doms = el.split('=')
      if doms[1].strip() == nin:
        continue #Silently ignore recursive refs.
      else:
        newrex.extend(domain_curse(doms[1]))
    elif el.find('include') >= 0:
      doms = el.split(':')
      if doms[1] == nin:
        continue #Silently ignore recursive refs.
      else:
        newrex.extend(domain_curse(doms[1]))

  return newrex


#This gets the recursive list of spf domains:
def domain_spf(nin):
  spflist = domain_curse(nin)
  if spflist == None:
    return None
  else:
    allrex = '#'.join([el[1] for el in spflist])
    return allrex


#This gets the dkim record in one joined up string.
#It also works for a simple dmarc record:
def domain_dkim(nin):
  dkimlist = domain_list(nin)
  if dkimlist == []:
    return ""
  else:
    allrex = ''.join(dkimlist)
    return allrex


#Return the dkim record, where the domain is constructed from the DKIM-Signature:
def dkimdomain(dksig):
  if dksig == "":
    return None

  dom = ""; sel = ""
  largs = dksig.split('\n')
  darg = "".join(largs)
  args = darg.split(';')
  for arg in args:
    arg = arg.strip()
    if arg.startswith('s='):
      selparts = arg.split('=')
      sel = selparts[1]
    if arg.startswith('d='):
      domparts = arg.split('=')
      dom = domparts[1]

  return(domain("%s._domainkey.%s" % (sel, dom)))
  

#Return the rua or ruf address for the dmarc record of a given domain:
def dmarc_reportee(dom, rtype):

  if dom.find('_dmarc') < 0:
    dmdom = "%s.%s" % ("_dmarc", dom)
  else:
    dmdom = dom

  dmrec = domain(dmdom)
  return reporter(dmrec, rtype)


def reporter(arec, atype):
  reportee = ""
  try:
    parts = arec.split(';')
    for part in parts:
      pared = part.strip()
      if pared.find(atype) >= 0:
        reportee = pared.split('=')[1]
        reportee = reportee.replace(".", "@", 1)
  except:
    reportee = ""
  return reportee


if __name__ == "__main__":
  qt = "txt"
  dksig = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\
        d=gmail.com; s=20120113;\
        h=mime-version:date:message-id:subject:from:to:content-type;\
        bh=ZcyaoWtXMU43F27MmwVGC8gCM6OvQe0gp2HhCZXMP9s=;\
        b=TNB4LqUCQk3hstgKs5pU4EH88Z/jCd2eVN0cvlT/XazkTkwPu3maLtyPZjaldbFone\
         eQO8otPKsLOE6ugrMRJmo4W6/uB/3KneRECDBlcpK5KTARcEf2R3wO3Es5DSwXazVw60\
         WkZj04dzDgwql/kkdREnM9vmTuM87DmJcRHQM6NM2PBLpauUsT6MfK9ZehE7PP9D589j\
         MusC3eC9Cj1ppBL95UWFBz9D8No2jd6PI2wS2hJ9hlZeHsof9sriTLAdh1jTe83IDX3R\
         prrDAaBXyLDPTLqhmb++6Oo53HFeMpbK6Gq2FX3/rC8VR/qmbmFKYPkw9Kq4+/io3ukh\
         DGYA=="

  if sys.argv[1] == "spf":
    for nin in open(sys.argv[2]):
      nin = nin.strip()
      spells = nin.split(" ")
      rezel = domain_curse(spells[2])
      for el in rezel:
        print el[0], ":"
        print "\t", el[1]

  elif sys.argv[1] == "dkim":
    for nin in open(sys.argv[2]):
      try:
        nin = nin.strip()
        print domain_dkim(nin)
      except: continue

  elif sys.argv[1] == "dmarc":
    print domain(sys.argv[2], qt)

  elif sys.argv[1] == "txt":
    print domain(sys.argv[2], qt)

  else:
    print domain(sys.argv[2], qt)


