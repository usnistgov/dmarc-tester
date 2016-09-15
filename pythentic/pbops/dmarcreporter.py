
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

''' dmarcreporter.py '''

#Generate feedback report for SPF or DKIM all addresses, over the latest time period.

import commons as com
import os, sys, sqlite3, time, hasher, dkim
from twisted.internet import reactor
import squall, hadspf, haddkim, dnsmail, dmarcstats

def saveUnique(dkimrec, tp):

  ''' Save unique DKIM TXT records. '''

  if dkimrec == "": return
  fd = com.filein(tp['drex'])
  if com.inlist(dkimrec, fd): return
  fd.append(dkimrec)
  com.fileout(tp['drex'], fd)


def extractdvalue(aheader):
  ''' Arg is DKIM-Signature header. Parse and extract the d=value.
      the i=value and the s=value. '''

  dval = ""; ival = ""; sval = "";
  args = aheader.split(";")
  for arg in args:
    parts = arg.strip().split("=")
    if parts[0] == "d":
      dval = parts[1]
    if parts[0] == "i":
      ival = parts[1]
    if parts[0] == "s":
      sval = parts[1]
  return (dval, ival, sval)
#end def extractdvalue(aheader).




def get_hash(rek, ads):
  for ad in ads:
    if ad.find(rek) >= 0:
      arts = ad.split("&")
      return arts[2]
  return ""




#Process all the records in the table, by subject.
#Separate "register" from spf,dkim,dmarc:
def skimmode(recks, mutter, tp):

  badtests = ["p.dkim.bad", "p.dkim.nolf", "p.dkim.nocr", "p.dkim.bh", "p.spf.spoof"]

  for rek in recks:

    lowsubj = rek[9].lower()
    if lowsubj == "register":
      doRegistration(rek, mutter, tp)
    elif com.inlist(lowsubj, badtests):
      doBadDMARCTests(rek, mutter, tp)
    else:
      doDMARCfeedback(rek, mutter, tp)


#Records marked 'register' to process for registration:
def doRegistration(rec, mutter, tp):
  #Just return it if it's already reported:
  if rec[3] == 1:
    return ""

  algor = "sha1"
  now =time.time()
  walltime = time.ctime(float(rec[4]))
  stringout = doReg(rec, tp)

  #mail the registrant and the project:
  com.filestringout(tp['tempfile'], stringout)
  repper = "Re:%s" % (rec[9])
  mutterer = mutter % (repper, tp['gudmuttrc'], tp['mailto'], tp['tempfile'])
  mumutterer = mutter % (repper, tp['gudmuttrc'], rec[5], tp['tempfile'])
  print "doRegistration: %s" % (squall.oneshort(rec)),  #oneshort adds the newline.
  os.system(mutterer)
  print mutterer
  os.system(mumutterer)
  print mumutterer


#doReg: Handle the mechanics of the Register file:
def doReg(rec, tp):
  
  regadds = com.filein(tp['register'])
  fermat = "Thank you for registering on the had-pilot.biz test system.\n\
Here is your hash. Please enter it in the Paste-in-Hash field of the test form,\n\
with your address in the MailTo field.\n\n\
The test system is rate limited to one message per minute, to curb spamming through our server.\n\
Mailto = %s\n\
Paste-in-Hash = %s\n\
If you register again you will get the same hash as a reminder.\n"
  firmup = "You are already registered. As a reminder, here is your hash:\n\
Mailto = %s\n\
Paste-in-Hash = %s\n"

  if com.findel(rec[5], regadds):
    hash = get_hash(rec[5], regadds)
    stringout = firmup % (rec[5], hash)
    squall.setreported(tp['mildb'], tp['milscm'], rec[0])
  else:
    hash = hasher.hash_the_address(rec[5], tp['privkey'])
    regadds.append("%s&%s&%s" % (rec[5], now, hash[:20]))
    stringout = fermat % (rec[5], hash[:20])
    squall.setreported(tp['mildb'], tp['milscm'], rec[0])
    com.fileout(tp['register'], regadds)

  return stringout


#Records marked spf,dkim,dmarc,forensic, test to process as a live test:
def doDMARCfeedback(rec, mutter, tp):
  modelist = ["spf", "dkim", "dmarc", "register", "forensic", "test"]
  authenticators = ["auth.returnpath.net", "verifier.port25.com", "unlocktheinbox.com", "messagesystems.com"]
  msgtext = ""
  lowrec = rec[9].lower()


  #Already reported:
  if rec[3] == 1:
    return ""

  #Ignore message if it's local:
  if rec[7] == "127.0.0.1":
    return ""


  #Weed out Spam: non-standard subjects with spf/dkim/dmarc failures:
  if not com.inlist(lowrec, modelist) and not rec[17] == "Deliver":
    doSpamSpoof(rec, mutter, tp)
    return ""

  #don't reply to other known authenticators.
  try:
    (front, back) = rec[5].split('@')
  except ValueError:
    print "doDMARCfeedback: Ill-formed email address %s" % (rec[5])
    return ""

    if back in authenticators:
      print "No reply to other authenticators: %s" % (rec[5])
      squall.setreported(tp['mildb'], tp['milscm'], rec[0])
      return ""


  #Weed out dmarc discards: no point in replying, can only handle with RUA and RUF:
  if rec[17] == "Discard" or rec[17] == "Reject":
    return ""

  #Should be a valid test worthy of reply:
  msgtext = "\n\n===================================================================================================\n"
  msgtext += "Testing for: %s\n" % (lowrec)
  msgtext += "===================================================================================================\n"

  #Summary of results:
  msgtext += "\nSummary of results:\n"
  msgtext += squall.oneshort(rec)
  msgtext += "\n===================================================================================================\n "

  #Special diagnostic prints for SPF using hadspf.checkhost:
  if lowrec.find("spf") >= 0 or lowrec.find("dmarc") >= 0 or lowrec.find("test") >= 0:
    try:
      ipadd = rec[7]
      sender = rec[5]
      domain = rec[5].split("@")[1]
      (res, reas, spfl, expl) = hadspf.checkhost(ipadd, sender, domain)
      spform = hadspf.formatSPFRecords(spfl)
      spfverbose = "\nSPF Analysis:\n\tresult: %s\n\tReason: %s\n\tSPFRecords: %s\nInterimResults:\n%s\n" % (res, reas, spform, expl)
      msgtext += spfverbose
    except:
      msgtext += "%s (%s) failed to verify spfi and format result." % (sender, ipadd)
    yourrec = rec[11]

  #Special diagnostic prints for DKIM using haddkim.verify:
  if lowrec.find("dkim") >= 0 or lowrec.find("dmarc") >= 0 or lowrec.find("test") >= 0:
    yourrec = rec[13]
    saveUnique(yourrec, tp)
    try: 
      ((res, reas, dkimr, expl), dkimdom) = haddkim.verify(rec[10])
      dkimverbose = "\nDKIM Analysis:\n\tresult: %s\n\tReason: %s\n\tDKIM Record: %s\n\tExplanation:\n%s\n" % (res, reas, dkimr, expl)
      msgtext += dkimverbose
    except: 
      dkimfail = "DKIM format failure."
      print dkimfail
      msgtext += "%s\n" % (dkimfail)

  if lowrec.find("dmarc") >= 0 or lowrec.find("test") >= 0:
    anal = dnsmail.Analyser()
    msgtext += anal.dmarcreport(rec[10])

  #Full Record:
  msgtext += "\n===================================================================================================\n "
  msgtext += "Full Message record:\n"
  msgtext += squall.printaresult(rec)
  msgtext += "\n===================================================================================================\n "

  #Register (almost) everywhere:
  if not lowrec.find(" ") >= 0:
    strout = doReg(rec, tp)
    msgtext += "Registration Info:\n"
    msgtext += strout
    msgtext += "\n===================================================================================================\n "

  com.filestringout(tp['tempfile'], msgtext)
  repper = "Re:%s" % (lowrec)
  if repper.find(' ') > 0:
    alist = repper.split(' ')
    repper = "_".join(alist)
  print "doDMARCFeedback: sending %s to %s" % (repper, rec[5])
  mutterer = mutter % (repper, tp['gudmuttrc'], rec[5], tp['tempfile'])
  os.system(mutterer)
  #mutterer = mutter % (repper, tp['gudmuttrc'], tp['mailto'], tp['tempfile'])
  #os.system(mutterer)
  squall.setreported(tp['mildb'], tp['milscm'], rec[0])
  print "doDMARCFeedback: %s" % (squall.oneshort(rec))


#Records with undetermined subject to be processed as Spam:
def doSpamSpoof(rec, mutter, tp):
  squall.setreported(tp['mildb'], tp['milscm'], rec[0])
  print "doSpamSpoof: %s" % (squall.oneshort(rec)),


#Generate tests with bad dkim signatures or spoofed domains:
def doBadDMARCTests(rek, mutter, tp):
  #Already reported:
  if rek[3] == 1:
    return

  #Ignore message if it's local:
  if rek[7] == "127.0.0.1" or rek[5].find("pythentic") >= 0:
    squall.setreported(tp['mildb'], tp['milscm'], rek[0])
    return

  #If the request message failed Dmarc, don't initiate the 'bad' test.  It might be spamming:
  if rek[17] == "Reject" or rek[17] == "Discard":
    print "DMARC failed for %s. Do not initiate 'bad' tests." % (rek[5])
    return

  testname = rek[9].lower()
  if testname == "p.spf.spoof":
    muttrc = tp['badmuttrc']
    com.filestringout(tp['tempfile'], "p.spf.spoof test not yet operational.")
  else:
    muttrc = tp['gudmuttrc']
    com.filestringout(tp['tempfile'], "error test.")

  mutterer = mutter % (testname, muttrc, rek[5], tp['tempfile'])
  print "doBadDMARCTests: %s" % (mutterer)
  os.system(mutterer)
  squall.setreported(tp['mildb'], tp['milscm'], rek[0])



def getpaths(afilename):
  tp = {}
  for line in open(afilename):
    shine = line.strip()
    if shine.find('mildb') >= 0: tp['mildb'] = shine.split('=')[1]
    if shine.find('milscm') >= 0: tp['milscm'] = shine.split('=')[1]
    if shine.find('register') >= 0: tp['register'] = shine.split('=')[1]
    if shine.find('drex') >= 0: tp['drex'] = shine.split('=')[1]
    if shine.find('privkey') >= 0: tp['privkey'] = shine.split('=')[1]
    if shine.find('mailto') >= 0: tp['mailto'] = shine.split('=')[1]
    if shine.find('gudmuttrc') >= 0: tp['gudmuttrc'] = shine.split('=')[1]
    if shine.find('badmuttrc') >= 0: tp['badmuttrc'] = shine.split('=')[1]
    if shine.find('tempfile') >= 0: tp['tempfile'] = shine.split('=')[1]

  return tp

def main(affile):
  tp = getpaths(affile)
  mutter = "mutt -s %s -F %s %s < %s"
  format = "%Y/%m/%d %H:%M:%S"
  now = time.strftime(format)
  (dispo, atable) = squall.getresult(tp['mildb'])
  if not dispo:
    sys.exit("%s: no records." % (tp['mildb']))

  skimmode(atable, mutter, tp)


#################################################################################

def cronfordmarc():
  main(sys.argv[1])
  reactor.callLater(120, cronfordmarc)

def lastnfordmarc():
  wraplastn()
  reactor.callLater(86400, lastnfordmarc)

def wraplastn():
  toaddr = "proj-had@nist.gov"
  #toaddr = "night@nist.gov"
  muttrc = "/home/night/python/pythentic/conf/gudmuttrc"
  (dispo, atable) = squall.getresult('pmarc.db')
  msgtext = dmarcstats.printdmarcs(atable)
  msgtext += squall.lastenn('pmarc.db', 30)
  tempfile = "/tmp/tempfile.txt"
  com.filestringout(tempfile, msgtext)
  repper = "Daily_DMARC_Results_Summary"
  print "dmarcreporter: sending %s to %s" % (repper, toaddr)
  mutter = "mutt -s %s -F %s %s < %s"
  mutterer = mutter % (repper, muttrc, toaddr, tempfile)
  os.system(mutterer)


if __name__ == "__main__":
  now = time.ctime()
  if len(sys.argv) > 2:
    print "%s: Running dmarc processor as a cron job every 120 seconds." % (now)
    reactor.callLater(2, cronfordmarc)
    print "%s: Running dmarc daily results as a cron job every 86400 seconds." % (now)
    reactor.callLater(3600, lastnfordmarc)
    reactor.run()
  else:
    print "%s: Process db records and generate test replies." % (now)
    main(sys.argv[1])

#end main.


