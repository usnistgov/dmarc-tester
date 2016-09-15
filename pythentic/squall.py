
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



import sys, os, sqlite3, time

#***************************************************
#Data
#***************************************************
class Metafields:

  def __init__(self, metafile):

    try:
      with open(metafile) as f:
        self.org = f.next().strip(); print self.org
        self.email = f.next().strip(); print self.email
        self.extra = f.next().strip(); print self.extra
    except:
      sys.exit("Problem with %s." % (metafile))



  def printfields(self):
    print "org=%s, email=%s, extra=%s" % (self.org, self.email, self.extra)

#***************************************************
#Generic database update methods
#***************************************************

#Crete db with schema, fail if it already exists:
def create_db(dbname, dbschema):

  if os.path.exists(dbname):
    conn = sqlite3.connect(dbname)
  else:
    conn = sqlite3.connect(dbname)
    f = open(dbschema, 'rt')
    schema = f.read()
    conn.executescript(schema)

  return conn


##Create the db if it doesn't exist, or just open it.
##Execute the given sql statement as '%' args.
def update_db(dbname, dbschema, squill, argtuple):

  disp = True; msg = ""
  conn = create_db(dbname, dbschema)
  if conn:    
    try:
      conn.executescript(squill % argtuple)
      conn.commit()
      disp = True; msg = "%s update." % (dbname)
    except:
      disp = False; msg = "%s update failed." % (dbname)
    finally:
      conn.close()
  else:
    disp = False; msg = "%s open failed." % (dbname)

  return (disp, msg)


##Create the db if it doesn't exist, or just open it.
##Execute the given sql statement as '%' args.
def update_safe(dbname, dbschema, squill, argtuple):

  disp = True; msg = ""
  conn = create_db(dbname, dbschema)
  if conn:    
    try:
      conn.execute(squill, argtuple)
      conn.commit()
      disp = True; msg = "%s update." % (dbname)
    except:
      disp = False; msg = "%s update failed." % (dbname)
    finally:
      conn.close()
  else:
    disp = False; msg = "%s open failed." % (dbname)

  return (disp, msg)


##Read data from the db:
def extract_db(dbname, squill):

  disp = True; tuple = None
  if not os.path.exists(dbname):
    return (disp, tuple)

  try:
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute(squill)
    tuple = cursor.fetchone()
  except:
    disp = False; tuple = None
  finally:
    conn.close()

  return (disp, tuple)


def extract_all(dbname, squill):

  disp = True; vector = []
  if not os.path.exists(dbname):
    return (False, vector)

  try:
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute(squill)
    vector = cursor.fetchall()
  except:
    disp = False; vector = []
  finally:
    conn.close()

  return (disp, vector)



#***************************************************
#PGP specific methods
#***************************************************

#Add metadata to the <dbname> database:
def putmeta(dbname, dbschema, metadata):

  sqlstr = "insert into metadata (org_name, email, extra_contact_info) values (?, ?, ?);"
  md = Metafields(metadata)
  argtuple = (md.org, md.email, md.extra)
  return update_safe(dbname, dbschema, sqlstr, argtuple)


#Write one address record into the adders table in the <dbname> database:
def putadder(dbname, dbschema, argtuple):

  sqlstr = "insert into adders (adder, addername, last_report_date) values (?, ?, ?);"
  return update_safe(dbname, dbschema, sqlstr, argtuple)

def getmeta(dbname):
  org = ""; email = ""; extra = ""
  getdator = "select org_name, email, extra_contact_info from metadata;"
  return extract_db(dbname, getdator)

def getadder(dbname):
  getdator = "select id, adder, addername, last_report_date from adders;"
  return extract_all(dbname, getdator)

  
#***************************************************
#DMARC specific methods
#***************************************************

def putresult(dbname, dbschema, argdict):

  fields = "(Version, UserAgent, Reported, ArrivalDate, OriginalMailFrom, OriginalRcptTo, SourceIP, DKIMSignature, Subject, Body, SPFrecord, DKIMrecord, DMARCrecord, SPFresult, DKIMresult, Alignresult, Deliveryresult, SPFreason, DKIMreason, DMARCreason)"
  values = "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
  argtuple = unpackrec(argdict)
  sqlstr = "insert into results %s values %s;" % (fields, values)
  return update_safe(dbname, dbschema, sqlstr, argtuple)


#Support functions for putresult: pack and unpack a dict into a tuple:
def unpackrec(adict):

  return (adict['Version'], adict['UserAgent'], adict['Reported'], adict['ArrivalDate'], adict['OriginalMailFrom'], adict['OriginalRcptTo'], adict['SourceIP'], adict['DKIMSignature'], adict['Subject'], adict['Body'], adict['SPFrecord'], adict['DKIMrecord'], adict['DMARCrecord'], adict['SPFresult'], adict['DKIMresult'], adict['Alignresult'], adict['Deliveryresult'], adict['SPFreason'], adict['DKIMreason'], adict['DMARCreason'])

def buildrec():
  adict = {}
  adict['Version'] = "1"
  adict['UserAgent'] = "Pythentic"
  adict['Reported'] = 0
  adict['ArrivalDate'] = "Dec 17, 2015"
  adict['OriginalMailFrom'] = "j.s.nightingale@gmail.com"
  adict['OriginalRcptTo'] =  "pythentic@had-pilot.biz"
  adict['SourceIP'] = "201.3.129.20"
  adict['DKIMSignature'] = "zxcvbnm"
  adict['Subject'] = "dmarc"
  adict['Body'] = "\n\nnobody.\n"
  adict['SPFrecord'] = "v=spf1; ip4:10.0.20.20 -all"
  adict['DKIMrecord'] = "v=DKIM1;"
  adict['DMARCrecord'] = "v=DMARC1; rua=mailto:results@google.com"
  adict['SPFresult'] = "pass"
  adict['DKIMresult'] = "True"
  adict['Alignresult'] = "Pass"
  adict['Deliveryresult'] = "Deliver"
  adict['SPFreason'] = "sender SPF authorized"
  adict['DKIMreason'] = "Good DKIM Signature"
  adict['DMARCreason'] = "DMARC record bad: none"

  return adict

def getresult(dbname):
  getdator = "select id, Version, UserAgent, Reported, ArrivalDate, OriginalMailFrom, OriginalRcptTo, SourceIP, DKIMSignature, Subject, Body, SPFrecord, DMARCrecord, DKIMrecord, SPFresult, DKIMresult, Alignresult, Deliveryresult, SPFreason, DKIMreason, DMARCreason from results;"
  return extract_all(dbname, getdator)


#set the indexed record as reported:
def setreported(dbname, dbschema, id):

  sqlstr = "update results set Reported = ? where id = ?;"
  argtuple = (1, id)
  return update_safe(dbname, dbschema, sqlstr, argtuple)

#***************************************************
#Presentation methods: pretty print got records.
#***************************************************


#pretty print any named table:
def printtable(dbname, atable):

  if atable == 'adders':
    printadders(dbname)

  elif atable == 'meta':
    printmeta(dbname)

  elif atable == 'results':
    printresults(dbname)

  else:
    print "No such table", atable


#printadders; pretty print the adders table:
def printadders(dbname):

  (dispo, atable) = getadder(dbname)
  if not dispo:
    sys.exit("%s adders table empty." % (dbname))

  for atupl in atable:
    for monad in atupl:
      print monad, '\t',
    print

#printresults; pretty print the results table:
def printresults(dbname):

  (dispo, atable) = getresult(dbname)
  if not dispo:
    sys.exit("%s results table empty." % (dbname))

  ax = 1
  for atupl in atable:
    ix = 1
    print "\nRecord [%d]:" % (ax)
    for monad in atupl:
      print "\t[%02d]  %s" % (ix, monad)
      ix += 1
    ax += 1

#lastresult; pretty print the last record:
def lastresult(dbname):

  (dispo, atable) = getresult(dbname)
  if not dispo:
    sys.exit("%s results table empty." % (dbname))

  ix = 0
  print "\nRecord [%d]:" % (atable[-1][0])
  for monad in atable[-1]:
    print "\t[%02d]  %s" % (ix, monad)
    ix += 1

#shortresults; print the abbreviated results:
def shortresults(dbname):

  (dispo, atable) = getresult(dbname)
  if not dispo:
    sys.exit("%s results table empty." % (dbname))

  for atuple in atable:
    oneshort(atuple)

def oneshort(onerec):
    print "[%02d]:" % (onerec[0]),
    try: print " %s, " % (time.ctime(float(onerec[4]))[4:-5]),
    except: print " bad time",
    print " subj:%s, " % (onerec[9]),
    print " from %s " % (onerec[5]),
    print "(%s)," % (onerec[7]),
    print " spf:%s," % (onerec[14]),
    print " dkim:%s," % (onerec[15]),
    print " dmarc:%s," % (onerec[16]),
    print " reported:%d" % (onerec[3])



#****************************************************************
#Main test and exercise method: do all the generic puts and gets,
#and then all the db specific puts and gets:
#****************************************************************

def dotests(testfile):

  ix = 1

  for line in open(testfile):
    line = line.strip()
    if line.find('command') == -1: continue
    if line.startswith('#'): continue
    print "\n**********"
    print "* Test %02d " % (ix)
    ix += 1
    print "**********\n"
    testargs = line.split(' ')
    docommands(testargs)


def docommands(sysargv):

  if sysargv[1] == 'putmeta':
    print "cmd: %s, db: %s, schema=%s, metafile: %s" % (sysargv[1], sysargv[2], sysargv[3], sysargv[4])
    if sysargv[2] == 'pgp.db' or sysargv[2] == 'pmarc.db':
      print putmeta(sysargv[2], sysargv[3], sysargv[4])
    else:
      sys.exit("Bad dbname: %s" % (sysargv[2]))

  elif sysargv[1] == 'putadder':
    atuple = ('had-pilot.biz', 'night@had-pilot.biz', 102953)
    print "cmd: %s, db: %s, schema=%s, atuple: %s" % (sysargv[1], sysargv[2], sysargv[3], atuple)
    if sysargv[2] == 'pgp.db' or sysargv[2] == 'pmarc.db':
      print putadder(sysargv[2], sysargv[3], atuple)
    else:
      sys.exit("Bad dbname: %s" % (sysargv[2]))

  elif sysargv[1] == 'getmeta':
    print "cmd: %s, db: %s" % (sysargv[1], sysargv[2])
    if sysargv[2] == 'pgp.db' or sysargv[2] == 'pmarc.db':
      print getmeta(sysargv[2])
    else:
      sys.exit("Bad dbname: %s" % (sysargv[2]))

  elif sysargv[1] == 'getadder':
    print "cmd: %s, db: %s" % (sysargv[1], sysargv[2])
    if sysargv[2] == 'pgp.db' or sysargv[2] == 'pmarc.db':
      printadders(sysargv[2])
    else:
      sys.exit("Bad dbname: %s" % (sysargv[2]))

  elif sysargv[1] == 'putresult':
    print "cmd: %s, db: %s, schema: %s" % (sysargv[1], sysargv[2], sysargv[3])
    if sysargv[2] == 'pgp.db' or sysargv[2] == 'pmarc.db':
      print putresult(sysargv[2], sysargv[3], buildrec())
    else:
      sys.exit("Bad dbname: %s" % (sysargv[2]))

  elif sysargv[1] == 'getresult':
    if sysargv[2] == 'pgp.db' or sysargv[2] == 'pmarc.db':
      printresults(sysargv[2])
    else:
      sys.exit("Bad dbname: %s" % (sysargv[2]))

  elif sysargv[1] == 'shortresult':
    if sysargv[2] == 'pgp.db' or sysargv[2] == 'pmarc.db':
      shortresults(sysargv[2])
    else:
      sys.exit("Bad dbname: %s" % (sysargv[2]))

  elif sysargv[1] == 'lastresult':
    if sysargv[2] == 'pgp.db' or sysargv[2] == 'pmarc.db':
      lastresult(sysargv[2])
    else:
      sys.exit("Bad dbname: %s" % (sysargv[2]))

  elif sysargv[1] == 'updatereported':
    print "cmd: %s, db: %s" % (sysargv[1], sysargv[2])
    id = 1
    if sysargv[2] == 'pmarc.db':
      setreported(sysargv[2], sysargv[2], id)
      printresults(sysargv[2])
    else:
      sys.exit("Bad dbname: %s" % (sysargv[2]))

  else:
    sys.exit("Bad command %s. Did you get the args scrambled?" % (sysargv[1]))


if __name__ == "__main__":

  cmdlist = ["autotest", "putmeta", "putadder", "getmeta", "getadder", "putresult", "getresult", "shortresult", "lastresult", "updatereported"]

  if len(sys.argv) < 2:
    for el in cmdlist:
      print el
    sys.exit()

  if sys.argv[1] == "autotest":
    dotests(sys.argv[2])
  else:
    docommands(sys.argv)


