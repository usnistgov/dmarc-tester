
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




import sys, os
import logging, dkim # for get_txt and rfc822_parse
from dkim import rfc822_parse 
import commons as com

#DNS lookups with dinsget:
import dinsget

class Dmarc:

  '''
    This is where DMARC policy is applied.
    __init__(dval, rfc5321, rfc5322, fromdom, message)
    OneFromDomain(headers)
    CalltoDNS(fulldomin)
    ValidateRecord(dmarc_record)
    ApplyPolicy(spfres, dkimres)
    ApplyLocalPolicy()
    ApplyDMARCPolicy()

  #Harness to test validation of existing dmarc records:
  def __init__(self, dmrec):
    self.dmrec = dmrec
    self.dr = Dmarker()
    self.valid = self.ValidateRecord(self.dmrec)

  '''
  def __init__(self, dval, rfc5321, rfc5322, message):
    if dval and dval.endswith("."): dval = dval[:-1]
    if rfc5321.endswith("."): rfc5321 = rfc5321[:-1]
    if rfc5322.endswith("."): rfc5322 = rfc5322[:-1]
    self.dvalue = dval
    self.RFC5321MailFrom = rfc5321
    self.RFC5322From = rfc5322
    self.dmdomain = "_dmarc." + self.RFC5321MailFrom
    (self.headers, self.body) = rfc822_parse(message)
    #DMARC rejig:
    self.dmrec = dinsget.domain(self.dmdomain)
    self.dr = Dmarker()
    self.politext = ""
    (self.valid, self.narrat) = self.ValidateRecord(self.dmrec)


  def getDMARCInterim(self):
    return "%s\n\n%s" % (self.narrat, self.politext)

  def getDMARCdomain(self):
    return  self.dmdomain



  def OneFromDomain(self):
    fromage = []; ofd = ""
    for hdr in self.headers:
      if hdr[0].lower() == "from":
        fromage.append([hdr[0], hdr[1]])
        ofd = ofd + "%s: %s" % (hdr[0], hdr[1])

    if len(fromage) == 1:
      return (True, ofd)

    for i in range(len(fromage)):
      if i == len(fromage) - 1:  #don't run off the end.
        return (True, ofd)

      if fromage[i] != fromage[i+1]:
        ofd += "dmarc.OneFromDomain: FAIL: %s and %s" % (fromage[i], fromage[i+1])
        return (False, ofd)


  def ValidateRecord(self, dmarc_record):

    ''' Make sure the DMARC record is syntactically correct and stash
        its values away. '''

    rez = True; narra = "" 
    if dmarc_record == None:
      self.disp = "Dmarc record missing."
      narra += "%s\n" % (self.disp)
      return (False, narra)

    if dmarc_record.find("spf1") >= 0:
      narra += "SPF record: '%s' should not be in dmarc domain.\n" % (dmarc_record)
      rez = False
      return (rez, narra)
    
    if dmarc_record.find(';') < 0:
      narra += "DMARC record must be semi-colon separated.\n"
      return (False, narra)


    if dmarc_record.endswith(';'):
      dmarc_record = dmarc_record[:-1]

    dimes = dmarc_record.split(";")
    if len(dimes) == 0:
      narra += "Empty dmarc record for %s\n" % (self.dmdomain)
      return (False, narra)

    elif dimes[0].find("DMARC1") < 0:
      narra += "%s is 1st element in improperly constituted dmarc record.\n" % (dimes[0])
      rez = False
      #continue to pick nits in rest of record.
    else:
      narra += "%s : good.\n" % (dimes[0])


    for i in range(len(dimes)):

      dimes[i] = dimes[i].strip()
      nickels = dimes[i].split("=", 1)
      if len(nickels) < 2:
        narra += "'%s' invalid dmarc element.\n" % (dimes[i])
        rez = False
        continue

      policy = nickels[0].lower()

      if policy == 'v':
        continue #v=DMARC1 already dealt with.

      if policy == "adkim":
        self.dr.adkim = nickels[1].lower()
        if self.dr.adkim == 'r' or self.dr.adkim == 's':
          narra += "%s : good.\n" % (dimes[i])
        else:
          narra += "%s : bad (valid values are 'r' and 's').\n" % (dimes[i])
          rez = False
        continue

      elif policy == "aspf":
        self.dr.aspf = nickels[1].lower()
        if self.dr.aspf == 'r' or self.dr.aspf == 's':
          narra += "%s : good.\n" % (dimes[i])
        else:
          narra += "%s : bad (valid values are 'r' and 's').\n" % (dimes[i])
          rez = False
        continue

      elif policy == "p" or policy == "sp":
        spol = nickels[1].lower()
        if spol == "none" or spol == "quarantine" or spol == "reject":
          narra += "%s : good.\n" % (dimes[i])
        else:
          narra += "%s : bad (valid values are 'none' or 'quarantine' or 'reject').\n" % (dimes[i])
          rez = False

        if policy == "p": self.dr.p = spol
        else: self.dr.sp = spol
        continue

      elif policy == "pct":
        if not nickels[1].isdigit():
          narra += "%s : bad. (valid value is an int in range 0 to 100).\n" % (dimes[i])
          rez = False

        elif int(nickels[1]) > 100:
          narra += "%s : bad. (valid value is an int in range 0 to 100).\n" % (dimes[i])
          rez = False

        if rez:
          narra += "%s : good.\n" % (dimes[i])
        continue

      elif policy == "rf":
        self.dr.rf = nickels[1].split(",")
        for arf in self.dr.rf:
          if arf == "afrf" or arf == "iodef":
            narra += "%s : good\n" % (dimes[i])
          else:
            narra += "%s : bad: (valid values are 'afrf' or 'iodef').\n" % (dimes[i])
            rez = False
        continue

      elif policy == "ri":
        if not nickels[1].isdigit():
          narra += "%s : bad: (valid value is an integer. Ideally a reasonable multiple or fraction of 86400).\n" % (dimes[i])
          rez = False
          continue

        self.dr.ri = int(nickels[1])
        if self.dr.ri < 1800:
          narra += "WARNING: %d is too unreasonably frequent for a reporting interval.\n" % (self.dr.ri)
        else:
          narra += "%s : good.\n" % (dimes[i])
        continue

      elif policy == "rua":
        self.dr.rua = nickels[1].split(',')
        for rua in self.dr.rua:
          if rua.find('.') < 1:
            narra += "%s : bad, (valid value is a  mailto address (or list of ...) like: 'mailto:user@domain.tld').\n" % (dimes[i])
            rez = False
            continue
        if rez:
          narra += "%s : good.\n" % (dimes[i])
        continue

      elif policy == "ruf":
        self.dr.ruf = nickels[1].split(',')
        for rua in self.dr.ruf:
          if rua.find('.') < 1:
            narra += "%s : bad, (valid value is a  mailto address (or list of ...) like: 'mailto:user@domain.tld').\n" % (dimes[i])
            rez = False
            continue
        if rez:
          narra += "%s : good.\n" % (dimes[i])
        continue

      elif policy == "fo":
        self.dr.foes = nickels[1].split(":")
        if len(self.dr.foes) == 0:
          narra += "%s: bad: (valid value is a list of colon separated arguments {0|1:d:s}\n" % (dimes[i])
          rez = False
          continue
        for foo in self.dr.foes:
          if foo != '0' and foo != '1' and foo != 'd' and foo != 's':
            narra += "%s: bad: (valid values are {0|1:d:s} ).\n" % (dimes[i])
            rez = False
        if rez:
          narra += "%s : good.\n" % (dimes[i])
        continue

      else:
        narra += "%s: unknown dmarc element.\n" % (dimes[i])
        rez = False

    #Now what is missing from the dmarc record:
    if rez:

      if self.dr.p == "":
        narra += "The 'p' argument must be present in a well-formed dmarc record.\n"
        rez = False

      if self.dr.rua and self.dr.pct == "":
        narra += "NOTE: 100%% feedback assumed for %s.\n" % (self.dr.rua)

      if self.dr.ruf and self.dr.rf == "":
        narra += "NOTE: afrf assumed for %s.\n" % (self.dr.ruf)

      if self.dr.adkim == "":
        narra += "NOTE: relaxed alignment assumed for adkim.\n"

      if self.dr.aspf == "":
        narra += "NOTE: relaxed alignment assumed for aspf.\n"

      if self.dr.rf != "" and len(self.dr.rua) == 0:
        narra += "NOTE: rf argument only useful if rua also present.\n"

    return (rez, narra)


  def getDMARCrecord(self): return self.dmrec
 


  #Local Policy:
  #  if spf fails, reject the message and send a report to the "originator".
  #  if DKIM fails, reject the message and send a report to the "originator".
  #  local Policy applies when:
  #  - there is no dmarc record.
  #  - the dmarc record is invalid.
  #  - the dmarc record is valid and p=none.
  #  DMARC policy applies when:
  #  -  the dmarc record is valid AND
  #  -  p=quarantine OR p=reject.

  def ApplyPolicy(self, spfres, dkimres, spfrec, dkimrec, thesubj):

    ''' Apply Local Policy or DMARC policy as befits. '''

    self.spfres = spfres; self.dkimres = dkimres
    self.spfrecord = spfrec; self.dkimrecord = dkimrec
    response = ""; politex = ""

    #There is no DMARC record, apply local policy:
    if self.dmrec == "" or self.dmrec == None:
      response = "Applying Local Policy because no DMARC record."
      politex += "%s\n" % (response)
      return self.ApplyLocalPolicy(response, self.spfres, self.dkimres, spfrec, dkimrec, thesubj)

    #There is a DMARC record but it is not valid:
    if not self.valid:
      response = "Applying Local Policy because DMARC record exists but is invalid."
      politex += "%s\n" % (response)
      return self.ApplyLocalPolicy(response, self.spfres, self.dkimres, spfrec, dkimrec, thesubj)

    #There is a DMARC record and it is valid:
    if self.dr.p == "none":
      response = "Applying Local Policy because DMARC record exists and is good but DMARC policy equals 'none'."
      politex += "%s\n" % (response)
      return self.ApplyLocalPolicy(response, self.spfres, self.dkimres, spfrec, dkimrec, thesubj)

    #p=quarantine, apply DMARC policy:
    if self.dr.p == "quarantine":
      response = "Applying DMARC Policy because DMARC policy equals 'quarantine'"
      politex += "%s\n" % (response)
      return self.ApplyDMARCPolicy(self.dr.p, response, self.spfres, self.dkimres, self.spfrecord, self.dkimrecord)

    #p=reject, apply DMARC policy:
    if self.dr.p == "reject":
      response = "Applying DMARC Policy because DMARC policy equals 'reject'."
      politex += "%s\n" % (response)
      return self.ApplyDMARCPolicy(self.dr.p, response, self.spfres, self.dkimres, self.spfrecord, self.dkimrecord)

    #Not sure what's going on: default to Local Policy:
    response = "Applying Local Policy as the default because all policy tests fail."
    politex += "%s\n" % (response)
    return self.ApplyLocalPolicy(response, self.spfres, self.dkimres, spfrec, dkimrec, thesubj)


  def ApplyLocalPolicy(self, resp, spfres, dkimres, spfrec, dkimrec, thesubj):
    # spfres values: "pass" or not
    # dkimres values: True or False

    action = "Deliver"; politex = ""
    subjlist = ["spf", "dkim", "dmarc", "register", "feedback", "forensic", "test"]

    #Now apply actual policy:
    # SHOULD NOT be used in the absence of SPF ...
    if spfrec and spfres == "pass":
        response = "%s: SPF passed so DMARC Authenticates." % (resp)
        politex += "%s\n" % (response)
        return ("Deliver", response, self.dmrec, politex)

    # SHOULD NOT be used in the absence of DKIM ...
    if dkimrec and dkimres:
        response = "%s: DKIM passed so DMARC Authenticates." % (resp)
        politex += "%s\n" % (response)
        return ("Deliver", response, self.dmrec, politex)

    #Both DKIM and SPF failed, Reject the message if it's a test, Discard it otherwise:
    if withinlist(subjlist, thesubj):
      response = "%s: Both SPF and DKIM failed." % (resp)
      politex += "%s\n" % (response)
      return ("Reject", "%s: Both SPF and DKIM failed" % (resp), self.dmrec, politex)
    else:
      action = "Discard"
      disp = "Message discarded because the Subject line is not a proper test subject"
      politex += "%s\n" % (disp)
      return (action, disp, self.dmrec, politex)



  def ApplyDMARCPolicy(self, dmdisp, resp, spfres, dkimres, spfrec, dkimrec):
    #Check alignment, then SPF True OR DKIM True for delivery:
    dmpnarra = ""; politex = ""

    (onedom, ofdres) = self.OneFromDomain()
    if not onedom:
      response = "Multiple From domains exist, DMARC fails."
      politex += "%s\n" % (response)
      return ("Reject", response, self.dmrec, politex)

    #Split off the user from 5322From:
    if self.RFC5322From.find('@') >= 0:
      (User5322, From5322) = self.RFC5322From.split('@')
    else:
      From5322 = self.RFC5322From
    if From5322.endswith('.'):
      From5322 = From5322[-1]

    #dmarc spec, 4.2.2 SPF-authenticated Identifiers:
    if self.dr.aspf == "s":
      if not self.exact(self.RFC5321MailFrom, From5322):
        response = "SPF and envelope IDs misaligned: '%s' != '%s'." % (self.RFC5321MailFrom, From5322)
        politex += "%s\n" % (response)
        return ("Reject", response, self.dmrec, politex)
    elif self.dr.aspf == "r":
      if not self.orgmatch(self.RFC5321MailFrom, From5322):
        response = "SPF and envelope IDs misaligned: '%s' != '%s'." % (self.RFC5321MailFrom, From5322)
        politex += "%s\n" % (response)
        return ("Reject", response, self.dmrec, politex)

    #dmarc spec, 4.2.1 DKIM-authenticated Identifiers:
    if self.dr.adkim == "s":
      if not self.exact(self.dvalue, From5322):
        response = "DKIM and From IDs misaligned: '%s' != '%s'." % (self.dvalue, From5322)
        politex += "%s\n" % (response)
        return ("Reject", response, self.dmrec, politex)
    elif self.dr.adkim == "r":
      if not self.orgmatch(self.dvalue, From5322):
        response = "DKIM and From IDs misaligned: '%s' != '%s'." % (self.dvalue, From5322)
        politex += "%s\n" % (response)
        return ("Reject", response, self.dmrec, politex)

    #Now apply actual policy:
    # SHOULD NOT be used in the absence of SPF ...
    if spfrec and spfres == "pass":
        response = "Message Authenticated because SPF passed."
        politex += "%s\n" % (response)
        return ("Deliver", response, self.dmrec, politex)

    # SHOULD NOT be used in the absence of DKIM ...
    if dkimrec and dkimres:
        response = "Message Authenticated because DKIM passed."
        politex += "%s\n" % (response)
        return ("Deliver", response, self.dmrec, politex)

    #Both DKIM and SPF failed, so Reject the message:
    response = "Both SPF and DKIM failed, Message Fails DMARC."
    politex += "%s\n" % (response)
    return ("Reject", response, self.dmrec, politex)




  def exact(self, dom1, udom2):

    ''' Check for cardinality and equality of domain1 and domain2. '''

    if udom2.endswith('.'):
      udom2 = udom2[-1]

    darts1 = dom1.split(".")
    if udom2.find("@") >= 0:
      (udar, darts) = udom2.split("@")
      darts2 = darts.split(".")
    else:
      darts2 = udom2.split(".")

    #Exact match means identical cardinality.
    if len(darts1) != len(darts2):
      return False

    #Bare 'com', 'org', 'gov' addresses are not valid.
    if len(darts1) == 1:
      return False

    #Exact match means label-for-label equality.
    #Case insensitive match, per some rfc:
    for el in range(len(darts1)):
      if darts1[el].lower() != darts2[el].lower():
        return False

    return True

  def orgmatch(self, dom1, dom2):

    ''' Check for equality of domain1 and domain2. '''

    ourlen = 0; revd = []
    darts1 = dom1.split(".")
    darts2 = dom2.split(".")
    darts1.reverse()
    darts2.reverse()

    if len(darts1) < len(darts2):
      ourlen = len(darts1)
    else:
      ourlen = len(darts2)


    #Bare 'com', 'org', 'gov' addresses are not valid.
    if ourlen == 1:
      return False

    #Check for label-for-label equality.
    #Case insensitive match, per some rfc:
    for el in range(ourlen):
      if darts1[el].lower() != darts2[el].lower():
        return False

    return True

  def Housekeeping(self):

    ''' Every message generates DMARC, spf and dkim authentication values. 
        These are periodically returned to the sender according to DMARC
        policy parameters. Save them all from here. '''

    print "Housekeeping."


#end class Dmarc.

class Dmarker:

  ''' Actual DMARC record processing and validation happens here. '''

  def __init__(self):
    self.version = ""
    self.adkim = ""
    self.aspf = ""
    self.p = ""
    self.sp = ""
    self.pct = 100
    self.rf = ""
    self.ri = 86400
    self.rua = []
    self.ruf = []
    self.foes = []

  def printvalues(self):
    print "DMARC record values:"
    print "version =", self.version
    print "adkim =", self.adkim
    print "aspf =", self.aspf
    print "p =", self.p
    print "pct =", self.pct
    print "rf =", self.rf
    print "ri =", self.ri
    print "rua =", self.rua
    print "ruf =", self.ruf


  def populate(self, shards):
    res = True

    if shards[0].lower() == "v":
      self.version = shards[1]
      if self.version != "DMARC1": res = False

    if shards[0].lower() == "adkim":
      self.adkim = shards[1]
      if self.adkim != "r" and self.adkim != "s": res = False

    if shards[0].lower() == "aspf":
      self.aspf = shards[1]
      if self.aspf != "r" and self.aspf != "s": res = False

    if shards[0].lower() == "p":
      self.p = shards[1]
      if self.p != "none" and self.p != "quarantine" and self.p != "reject":
        res = False

    if shards[0].lower() == "pct":
      self.pct = int(shards[1])
      if self.pct <0 or self.pct > 100: res = False

    if shards[0].lower() == "rf":
      self.rf = shards[1].split(",")
      for arf in self.rf:
        if arf != "afrf" and arf != "iodef": res = False

    if shards[0].lower() == "ri":
      self.ri = int(shards[1])
      if self.ri < 300: res = False

    if shards[0].lower() == "rua":
      self.rua = shards[1].split(",")
      for rua in self.rua:
        if rua.find(".") == -1: res = False

    if shards[0].lower() == "ruf":
      self.ruf = shards[1].split(",")
      for ruf in self.ruf:
        if ruf.find(".") == -1: res = False

    return res

#end class Dmarker.


#Non class methods:

def withinlist(alist, astring):
  thestring = astring.lower()

  for el in alist:
    if thestring.find(el) >= 0:
      return True
  return False


#test harness for various methods and classes:
if __name__ == "__main__":
  ix = 0

  for line in open(sys.argv[1]):
    line = line.strip()
    print "[%d]: Parsing '%s'" % (ix, line)
    dim = Dmarc(line)
    print dim.narra,
    if dim.valid:
      print "[%d]: Syntax Good.\n" % (ix)
    else:
      print "[%d]: Syntax Bad.\n" % (ix)
    ix += 1

