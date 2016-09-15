
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



import squall, dinsget, hadspf, haddkim, haddmarc
import sys, os, re, smtplib, email, email.utils

###############################################################################
#dnsmail.py
#Stephen Nightingale, NIST
#high Assurance Domains Project
#March 8, 2016
#
#Read the mailbox into rfc_822 format,
#Index into headers, bodies
#list all messages with X-spf headers
#list all messages with DKIM_Signature
#list all messages with X-dmarc headers
##############################################################################

#Return the command arguments:
def parseInput(herald):
  raw = raw_input(herald)
  return raw.split(" ")

#Read a file into a line vector:
def filein(afn):
  aster = []

  for line in open(afn):
    aster.append(line)
  return aster


#hashget: get the hash corresponding to the goven email address:
def hashget(tp, anaddr):
  for entry in open(tp['register']):
    fields = entry.strip().split('&')
    if anaddr in fields[0]:
      print "%s == %s" % (fields[0], fields[2])


#dnsget: Get the txt record for the base domain of the indexed message:
def dnsget(domain, typ):
  if typ == "spf":
    domlist = dinsget.domain_curse(domain)
    if len(domlist) == 0:
      print "no records for %s" % (domain)
    else:
      for reco in domlist:
        print "%s:\n\t%s" % (reco[0], reco[1])
  elif typ == "dkim":
    domlist = dinsget.domain_dkim(domain)
    print domlist
  elif typ == "dmarc":
    domlist = dinsget.domain(domain)
    print domlist
  else:
    domlist = dinsget.domain(domain)
    print domlist

#rfc822_parse imported from dkim to separate messages into headers and bodies:
def rfc822_parse(message):
  """Parse a message in RFC822 format.

  @param message: The message in RFC822 format. Either CRLF or LF is an accepted line separator.
  @return: Returns a tuple of (headers, body) where headers is a list of (name, value) pairs.
  The body is a CRLF-separated string.
  """
  headers = []
  lines = re.split(b"\r?\n", message)
  i = 0
  while i < len(lines):
    if len(lines[i]) == 0:
      # End of headers, return what we have plus the body, excluding the blank line.
      i += 1
      break
    if lines[i][0] in ("\x09", "\x20", 0x09, 0x20):
      headers[-1][1] += lines[i]+b"\r\n"
    else:
      m = re.match(br"([\x21-\x7e]+?):", lines[i])
      if m is not None:
        headers.append([m.group(1), lines[i][m.end(0):]+b"\r\n"])
      elif lines[i].startswith(b"From "):
          pass
      else:
        raise haddkim.MessageFormatError("Unexpected characters in RFC822 header: %s" % lines[i])
    i += 1
  return (headers, b"\r\n".join(lines[i:]))



#A class to hold the mailbox and serve up messages in different formats:
class Mailboxer:

  #Split the linear mailbox into separate messages:
  def __init__(self, mailbox):

    #mailbox is either a flat file or an array of messages:
    if isinstance(mailbox, str) and os.path.isfile(mailbox):
      self.mbox = self.pigeonhole(mailbox)
      if mailbox.find('sent') >= 0:
        self.fromto = "To"
      else:
        self.fromto = "From"
    else:
      self.mbox = mailbox
      self.fromto = "From"


  #Return the number of messages in the mailbox:
  def count(self):

    return len(self.mbox)

  #return the raw text message:
  def rawmessage(self, prix):
    return self.mbox[prix]

  #return the parsed message:
  def parsedmessage(self, prix):
    return rfc822_parse(self.mbox[prix])


  #Split the mailfile into messages as a vector of strings:
  def pigeonhole(self, mailfile):
    mix = 1; inmsg = 0; blankseen = 0
    thismsg = ""; allmail = []

    allin = filein(mailfile)

    for aline in allin:
      bareline = aline.strip()

      #Start collecting next message, sae the last one:
      if bareline.startswith("From ") and bareline.find("@") > 0:
        if not thismsg == "":
          allmail.append(thismsg)
          thismsg = ""
        thismsg = thismsg + aline
        inmsg = 1
        continue

      if inmsg == 1:
        thismsg = thismsg + aline
        continue

    #Capture the last message in the mailbox:

    if not thismsg == "":
      allmail.append(thismsg)

    return allmail



  #getone: return the message as a string:
  def getone(self, prix):
    return self.mbox[prix]



  #printone: print the indexed message:
  def printone(self, prix):
    bix = 0
    parsed = rfc822_parse(self.mbox[prix])

    print "Headers:"
    for hdr in  parsed[0]:
      print "\t%s: %s" % (hdr[0], hdr[1]),
    print "Body:"
    for line in parsed[1].split("\n"):
      print "\t%s" % (line)
      if bix == 150:
        print "\t<truncated>"
        break
      bix += 1


  def Fromlines(self, alimit):
    thecount = self.count()

    if alimit >= thecount:
      print "You can list a maximum of %d message headers." % (thecount-1)
      return

    startat = thecount - alimit

    for ix in range(startat, thecount):
      try: parsed = rfc822_parse(self.mbox[ix])
      except: print self.mbox[ix]
      datel = self.formatLine("Date", parsed)
      datel = reformatDate(datel)
      froml = self.formatLine(self.fromto, parsed)
      subjl = self.formatLine("Subject", parsed)
      print "[%s] %s  %s,\t\t%s: %s" % (ix, datel, subjl[1], froml[0], froml[1])


  def formatLine(self, ahdr, amsg):
    for anyhdr in amsg[0]:
      if ahdr == anyhdr[0]:
        subjval = anyhdr[1].strip()
        if subjval == None:
          subjval == ''
        else:
          subjval = "'%s'" % (subjval)
        return (ahdr, subjval) 
    return (ahdr, "''") 

  #Create a new mailbox with the contents of the search results:
  def searchresults(self, searchstring):
    searchbox = []

    for prix in range(self.count()):
      if self.mbox[prix].find(searchstring) > 0:
        searchbox.append(self.mbox[prix])

    self.mbox = Mailboxer(searchbox)
    return self.mbox


#Superclass the Mailboxer for messages in the sqlite db:
class Squealboxer(Mailboxer):

  def __init__(self, sqldb, disposition):
    self.mbox = []
    (outcome, sqlbox) = squall.getmessage(sqldb)
    if not outcome:
      print "%s fails to open."
    else:
      self.fromto = "From"
      for el in sqlbox:
        try:
          if disposition == "All" or disposition == el[2]:
            self.mbox.append(el[1]) 
        except: print el
      print "%d messages in %s." % (len(sqlbox), sqldb)



#Extract from date: dd-mm-yy hh:mm:ss :
def reformatDate(dateline):
  dates = dateline[1].split(" ")
  try: shortdate = "%s %s %s" % (dates[1], dates[2], dates[4])
  except: shortdate = dateline[1]
  return shortdate



#a class for spf,dkim,dmarc analysis
#and their associated arguments:
class Analyser:

  #No arguments, just pure method:
  def __init__(self):

    self.tp = {}


  #spfcheck: Give the SPF authentication result of the indexed message:
  def spfreport(self, parsemess):
    mst = ""

    (self.tp['SPFresult'], self.tp['SPFreason'], self.tp['SPFrecords'], self.tp['SPFexpl']) = self.spfcheck(parsemess)
    mst += "\nSPF Interim Results:\n"
    mst += self.tp['SPFexpl']
    mst += "SPF Final Result: %s\n" % (self.tp['SPFresult'])
    mst += "SPF Reason: %s:\n" % (self.tp['SPFreason'])
    mst += "SPF Records:\n"
    spfx = self.tp['SPFrecords'].split("#")
    for one in spfx:
      mst += "\t%s\n" % (one)
    return mst


  #spfcheck: Give the SPF authentication result of the indexed message:
  def spfcheck(self, parsemess):

    (self.tp['ipaddress'], self.tp['From5322'], self.tp['MailFrom5321']) = self.spfargs(parsemess)

    if __name__ == "__main__":
      print "SPF Evaluating: "; print "ip=%s, 5322=%s, 5321=%s" % (self.tp['ipaddress'], self.tp['From5322'], self.tp['MailFrom5321'])
    return hadspf.checkhost(self.tp['ipaddress'], self.tp['From5322'], self.tp['MailFrom5321'])


  #Get the input args for spf.checkhost:
  def spfargs(self, parsemess):
    ipaddress = ""; ipso = ""; From5322 = ""; MailFrom5321 = ""

    for hdr in  parsemess[0]:
      if hdr[0].find("X-spf") >= 0:
        ihs = hdr[1].split(", ")
        for el in ihs:
          nel = el.strip()
          spfv = nel.split("=")
          if spfv[0] == 'i': ipaddress = spfv[1]
          if spfv[0] == 'h': MailFrom5321 = spfv[1]
          if MailFrom5321.endswith("."): MailFrom5321 = MailFrom5321[:-1]
          if spfv[0] == 's': From5322 = spfv[1]

        if ipaddress.find("forged") > 0:
          (ipso, ipsn) = ipaddress.split("]")
        else:
          ipso = ipaddress

    return (ipso, From5322, MailFrom5321)


  #dkimcheck: Give the DKIM authentication result of the indexed message:
  def dkimcheck(self, rawmess):
    mst = ""

    ((self.tp['DKIMresult'], self.tp['DKIMreason'], self.tp['DKIMrecord'], self.tp['DKIMexpl']), self.tp['DKIMdomain']) = haddkim.verify(rawmess)

    mst += "\nDKIM Results for domain: %s\n" % (self.tp['DKIMdomain'])
    if self.tp['DKIMresult']:
      mst += "DKIM Pass.\n"
    else:
      mst += "DKIM Fails: %s\n" % (self.tp['DKIMreason'])

    if self.tp['DKIMexpl'] != "":
      mst += "\nDKIM Analysis:\n"
      mst += self.tp['DKIMexpl']
    return mst


  #dmarcreport: Get spf and dkim authentication results, give the dmarc evaluation:
  def dmarcreport(self, rawmess):
    rezheads = ['X-spf', 'X-dkim', 'X-dmarc']
    thesubj = "dmarc"; msgtext = ""; notext = ""

    try:
      (headers, body) = rfc822_parse(rawmess)
    except:
      return "rfc822 message format error."

    notext += self.spfreport((headers, body))
    notext += self.dkimcheck(rawmess)

    msgtext += "\n============================================================================================================\n"
    msgtext += "SPF, DKIM and DMARC results are computed twice: once by the incoming mail milter, and again by the outgoing test responder.  Both sets of results are given below. They should be the same.\n"
    msgtext += "--------------------------------------------------------------------------------------------------------------\n"
    msgtext += "Results reported by the Pythentic milter:\n\n"
    for hdr in headers:
      if hadspf.inlist(hdr[0], rezheads):
        msgtext += "\t%s: %s" % (hdr[0], hdr[1])
    msgtext += "\n============================================================================================================\n"

    msgtext += "Results generated by the DMARCreporter:\n\n"
    dm = haddmarc.Dmarc(self.tp['DKIMdomain'], self.tp['MailFrom5321'], self.tp['From5322'], rawmess)
    msgtext += "Intermediate Results for: %s\n" % (dm.getDMARCdomain()); 
    (self.tp['DMARCresult'], self.tp['DMARCreason'], self.tp['DMARCrecord'], self.tp['politex']) = dm.ApplyPolicy(self.tp['SPFresult'], self.tp['DKIMresult'], self.tp['SPFrecords'], self.tp['DKIMrecord'], thesubj)
    msgtext +=  dm.getDMARCInterim()
    msgtext += self.tp['politex']
    msgtext += "DMARC Result: %s, Reason: %s\nRecord: %s\n" % (self.tp['DMARCresult'], self.tp['DMARCreason'], self.tp['DMARCrecord'])
    return msgtext
  

#Wrap the send_email method:
def wrapsendmail(tp, toaddr, subject, body):

  fromaddr = "pythentic@had-pilot.biz"
  mutter = "mutt -s %s -F %s %s < %s"
  filestringout(tp['tempfile'], body)
  os.system("mutt -s %s -F /home/night/python/pythentic/conf/gudmuttrc %s < %s" % (subject, toaddr, tp['tempfile']))
  print "'%s' message sent to %s" % (subject, toaddr)



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
    if shine.find('muttrc') >= 0: tp['muttrc'] = shine.split('=')[1]
    if shine.find('tempfile') >= 0: tp['tempfile'] = shine.split('=')[1]

  return tp


def filestringout(filename, contents, mode='w'):

	''' Open the specified file, and write the contents to it 
            as a string. '''

	try:
		fp = open(filename, mode)
		fp.write(contents)
		fp.close()
	except:
		print filename, "I/O problem."
 	

#Insect the Apache access_log for dmarcresults accesses:
def httpdresults(amode):
  axlist = []
  axlog = "/var/log/httpd/HAD/access_log"
  for line in open(axlog):
    if line.find('dmarcresults.py') >= 0 and line.find(amode) >= 0:
      axlist.append(line.strip())

  for arez in axlist:
    print arez


def main(sysargv):

  allcmds = ['quit', 'exit', 'help', 'list', 'print', 'spf', 'dkim', 'dmarc', 'test', 'sql', 'dns', 'gethash', 'send', 'forward', 'update', 'setdb', 'hashers', 'search']
  boxes = { 'mail':"/var/spool/mail/night", 'sent':"/home/night/sent" }
  mb = Mailboxer(boxes[sysargv[1]])
  tp = getpaths(sys.argv[2])
  anal = Analyser()
  mb.Fromlines(50)
  print "%d messages." % (mb.count())
  cmdp = parseInput("command: ")
  thisdb = "pmarc.db"
  dispo = "All"
  print "Current DB is %s" % (thisdb)

  while cmdp[0] != "quit" and cmdp[0] != "exit":

    try:

      if cmdp[0] == "help":
        print allcmds

      if cmdp[0] == "search":
        mb = mb.searchresults(cmdp[1])
        print "%d results." % (mb.count())
        mb.Fromlines(mb.count() - 1)


      if cmdp[0] == "setdb":
        if len(cmdp) == 2 and cmdp[1].endswith(".db"):
          thisdb = cmdp[1]
          print "Current DB is %s" % (thisdb)
        else:
          print "Usage: setdb <dbname.db>"

      if cmdp[0] == "update":
        if len(cmdp) < 2:
          print "Usage: update [mail|sent|dbname.db]"

        elif cmdp[1] in boxes.keys():
          mb = Mailboxer(boxes[cmdp[1]])
          mb.Fromlines(50)
        elif cmdp[1].endswith(".db"):
          if len(cmdp) == 3:
            dispo = cmdp[2]
          mb = Squealboxer(cmdp[1], dispo)
          mb.Fromlines(50)
        else:
          print "Usage: update [mail|sent|dbname.db]"

      elif len(cmdp) > 1:

        argisnum = cmdp[1].isdigit()
        argisaddr = cmdp[1].find('.') > 0
        try: arginrange = int(cmdp[1]) < mb.count()
        except: arginrange = False

        if cmdp[0] == "hashers":
          try: print httpdresults(cmdp[1])
          except: print httpdresults('full')

        if cmdp[0] == "print":
          if argisnum and arginrange:
            mb.printone(int(cmdp[1]))

        if cmdp[0] == "list":
          if argisnum:
            if arginrange:
              print "Last N Messages in Mailbox:"
              mb.Fromlines(int(cmdp[1]))
            else:
              print "Index out of range."
          else:
            cmds = ['sql', 'thisaddr', thisdb, cmdp[1]]
            print "All messages for %s in %s" % (cmdp[1], thisdb)
            try: squall.docommands(cmds)
            except: print "sql: bad address."

        if cmdp[0] == "sql":
          print "calling "; print cmdp
          if len(cmdp) == 2:
            cmdp.append(thisdb)
          try: squall.docommands(cmdp)
          except: print "sql: bad option."

        if cmdp[0] == "send":
          bodful = "Inconsequential Content."
          try:
            wrapsendmail(tp, cmdp[1], cmdp[2], bodful)
          except:
            print "Send failed. Usage: send <user@domain> <subject>" 

        if cmdp[0] == "forward":
          addp = parseInput("To Address: ")
          bodful = mb.getone(int(cmdp[1]))
          subject = "Forward_from_had-pilot"
          try:
            wrapsendmail(tp, addp[0], subject, bodful)
          except:
            print "Forward failed. Usage: forward <user@domain>" 

        if cmdp[0] == "dns":
          if not argisnum:
            try:
              dnsget(cmdp[1], cmdp[2])
            except:
              dnsget(cmdp[1], "txt")

        if cmdp[0] == "gethash":
            hashget(tp, cmdp[1])


        if cmdp[0] == "spf":
          if argisnum and arginrange:
            print anal.spfreport(mb.parsedmessage(int(cmdp[1])))

        if cmdp[0] == "dkim":
          if argisnum and arginrange:
            print anal.dkimcheck(mb.rawmessage(int(cmdp[1])))

        if cmdp[0] == "dmarc" or cmdp[0] == "test":
          if argisnum and arginrange:
            print anal.dmarcreport(mb.rawmessage(int(cmdp[1])))

      else:
        if cmdp[0] == "dns":
          print "Usage: %s <domain>" % (cmdp[0])
        elif cmdp[0] == "sql":
          print "Usage: %s <squallcommand> <current.db>" % (cmdp[0])
        else:
          print "Usage: %s <index>" % (cmdp[0])

    except:
      raise

    cmdp = parseInput("command: ")



#Run dnsmail from the command line:
if __name__ == "__main__":

  main(sys.argv)

