
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



import asyncore, sys, os, sqlite3, time

''' commons.py '''

#Test file directories:
templates = "templates"
bodies = "bodies"
hk = {}

#Record Description
smimeRecordFields = "id, SMIMEACheckStatus, SourceIP, UserAgent, Version, OriginalRcptTo, ArrivalDate, OriginalMailFrom, Subject, Message"
smimea_table_fields = "id, uuid, application, has_DANE, smimelock, certificate_usage, selector, matching, certificate_access, DANE_match_data, local_match_data, signing_cert, signing_cert_spki, DANE_request_domain, DANE_request_result, test_result"
smimea_table_values = "'%d', '%s', '%d', '%d', '%s', '%d', '%d', '%d', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s'"

##############################################################################
#Classes:
##############################################################################

class Housekeeping:

  ''' Accumulate all data needed to populate a DMARC feedback record.
      See: draft-dmarc-base-00, rev. 02, March 30, 2012.
      Extended Aug 22, 2012: Write to sql database using sqlite3.  '''

  def __init__(self, keyval, db="", scm=""):
    try: hk['new'] = "new"
    except: hk = {}
    self.another(keyval)
    self.dbname = db
    self.dbschema =scm 

  def reinit(self):
    try: hk = {}
    except: pass

  def another(self, other):
    (key, val) = other.split("=", 1)
    hk[key] = val

  def update_schema(self, mesk):

    ''' Add non-existing tables to db. Populate the metadata table. '''

    conn = 0; schema = 0
    sqlstring = """insert into metadata(org_name, email, extra_contact_info, last_report_id) values ('%s', '%s', '%s', '%d');""" % (mesk['org_name'], mesk['email'], mesk['extra_contact_info'], 1)

    if not os.path.exists(self.dbname):
      conn = sqlite3.connect(self.dbname)
      with open(self.dbschema, 'rt') as f:
        schema = f.read()
      conn.executescript(schema)
      print "HK: dmarc.db created from update_schema."
    else:
      conn = sqlite3.connect(self.dbname)
    conn.executescript(sqlstring)



  def put_addr(self, adder, addername, last=0):

    ''' Add email source addresses to the adders table. ''' 

    conn = sqlite3.connect(self.dbname)
    with open(self.dbschema, 'rt') as f:
      schema = f.read()
    conn.executescript(schema)
    print "HK: dmarc.db created from put_addr."

    sqlcreator = """ create table if not exists adders (
	id integer primary key autoincrement not null,
	adder text,
	addername text,
	last_report_date int);
    """
    sqlstring1 = """insert into adders(adder, addername) values ('%s', '%s');""" % (adder, addername)
    sqlstring2 = """insert into adders(adder, addername, last_report_date) values ('%s', '%s', '%d');""" % (adder, addername, last)
    conn.executescript(sqlcreator)
    if last == 0:
      conn.executescript(sqlstring1)
    else:
      conn.executescript(sqlstring2)

   
  def record_messages(self, mesk):

    ''' Create db if non-existent.  Add message results to the DMARC database. '''

    conn = 0; schema = 0

    oldsqlstring = """insert into results(AuthFailspf, AuthFaildkim, AuthFailalign, FeedbackType, DeliveryResult, SourceIP, UserAgent, Version, OriginalRcptTo, ArrivalDate, OriginalMailFrom, DKIMSignature, Subject, Reported, SPFReason, DKIMReason, DMARCReason) values('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s');""" % (mesk['AuthFailspf'], mesk['AuthFaildkim'], mesk['AuthFailalign'], mesk['FeedbackType'], mesk['DeliveryResult'], mesk['SourceIP'], mesk['UserAgent'], mesk['Version'], mesk['OriginalRcptTo'], mesk['ArrivalDate'], mesk['OriginalMailFrom'], mesk['DKIMSignature'], mesk['Subject'], mesk['Reported'], mesk['SPFReason'], mesk['DKIMReason'], mesk['DMARCReason'])

    sqlstring = """insert into results(AuthFailspf, AuthFaildkim, AuthFailalign, FeedbackType, DeliveryResult, SourceIP, UserAgent, Version, OriginalRcptTo, ArrivalDate, OriginalMailFrom, DKIMSignature, Subject, Reported, SPFReason, DKIMReason, DMARCReason, Message) values('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s');""" % (mesk['AuthFailspf'], mesk['AuthFaildkim'], mesk['AuthFailalign'], mesk['FeedbackType'], mesk['DeliveryResult'], mesk['SourceIP'], mesk['UserAgent'], mesk['Version'], mesk['OriginalRcptTo'], mesk['ArrivalDate'], mesk['OriginalMailFrom'], mesk['DKIMSignature'], mesk['Subject'], mesk['Reported'], mesk['SPFReason'], mesk['DKIMReason'], mesk['DMARCReason'], mesk['Message'])
    if not os.path.exists(self.dbname):
      conn = sqlite3.connect(self.dbname)
      with open(self.dbschema, 'rt') as f:
        schema = f.read()
      #print schema
      conn.executescript(schema)
      conn.executescript(sqlstring)
      conn.close()
      print "HK: New DMARC Database created in %s." % (self.dbname)
    else:
      conn = sqlite3.connect(self.dbname)
      try:
        conn.executescript(sqlstring)
        print "HK: email record written to %s." % (self.dbname)
      except:
        print "Housekeeping: %s DB write failed." % (self.dbname)

    conn.close()

  def record_bodies(self, bodies):

    '''Create db if non-existent.  Add body results to the DMARC database. '''

    conn = 0; schema = 0

    sqlstring = '''insert into bodies(body) values('%s');''' % (str(bodies))
    if not os.path.exists(self.dbname):
      conn = sqlite3.connect(self.dbname)
      with open(self.dbschema, 'rt') as f:
        schema = f.read()
      #print schema
      conn.executescript(schema)
      conn.executescript(sqlstring)
      conn.close()
      print "HK: New DMARC Database created (bodies)."
    else:
      conn = sqlite3.connect(self.dbname)
      try:
        conn.executescript(sqlstring)
        print "HK: email record written to %s (bodies)." % (self.dbname)
        print str(bodies)
      except:
        print "Housekeeping: %s DB write failed OR bad body." % (self.dbname)

#End class Housekeeping.


class PipeReader(asyncore.file_dispatcher):

  ''' Handle Pipe (I/)O for subprocess returns.
      Only available on posix compliant systems.
      AKA Linux/Unix. '''

  def writable(self):
    return False

  def handle_read(self):
    data = self.recv(1024)
    if data.strip() == "":
      print 'PR:<hic>'
    else:
      print 'PR: (%d) "%s"' % (len(data), data)

  def handle_expt(self):
  # Ignore events that look like out of band data
    pass

  def handle_close(self):
    self.close()

#end class PipeReader(asyncore.file_dispatcher).


class Pipes:

	''' This is a repository for musher and milter hosts and port ids. '''

	tup = {}

	def __init__(self, fillfile):
		self.fillpipes(fillfile)
	#end def init(self, fillfile).


	def fillpipes(self, fillfile):

		''' Host and Port for musher and milter are in a config file.
		    Read it and provision class Pipes with values in it. '''

		ff = 0; pipem = []; hoovered = []; sig = 0

		pipem = filein(fillfile)
		for grawk in pipem:
			kwarg = grawk.strip()
			if kwarg == "": continue
			if kwarg.startswith("#"): continue

			#Deal with test config args first:
			if kwarg == "</test-config>":
				sig = 0
				self.configTests(hoovered) 
				continue
			if sig == 1:
				hoovered.append(kwarg)
				continue
			if kwarg == "<test-config>": 
				sig = 1 
				continue

			#Now do the Host and port assignments:
			(kw, arg) = kwarg.split("=")
			if kw == "trollHost": self.tup['trollHost'] = arg
			elif kw == "trollPort": self.tup['trollPort'] = int(arg)
			elif kw == "mushHost": self.tup['mushHost'] = arg
			elif kw == "mushPort": self.tup['mushPort'] = int(arg)
			elif kw == "milLog": self.tup['milLog'] = arg
			elif kw == "milType": self.tup['milType'] = arg
			elif kw == "milHost": self.tup['milHost'] = arg
			elif kw == "milPort": self.tup['milPort'] = int(arg)
			elif kw == "milDB": self.tup['milDB'] = arg
			elif kw == "smtpHost": self.tup['smtpHost'] = arg
			elif kw == "smtpPort": self.tup['smtpPort'] = int(arg)
			elif kw == "smtpSenderIP": self.tup['smtpSenderIP'] = arg

	#end def fillpipes(self, fillfile).

	def configTests(self, figs):

		''' Apply email address args to test templates. '''

		apply = {}

		if len(figs) == 0: return; # no action needed.

		for fug in figs:
			fig = fug.strip()
			pars = fig.split("=")
			apply[pars[0]] = pars[1]
		self.openTests(apply)
	#end def configTests(figs).

	def openTests(self, kwargs):

		''' Open the test templates directory and iterate
		    over tests. For each test, provision it and
		    write to the bodies directory. '''

		try: tem = os.listdir(templates)
		except: print templates, "failed to open"; raise

		for item in tem:
			itfl = "%s/%s" % (templates, item)
			fl = filein(itfl.strip())
			prov = self.provision(fl, kwargs)
			fileout("%s/%s" % (bodies, item), prov)
	#def openTests(self, kwargs).


	def provision(self, filetempl, kwargs):

		''' Apply real addresses to template args:
		    If rhs contains <placeholder>, substitute
		    the appropriate argument. '''

		provisioned = []; newconf = ""; inmutt = False

		for lune in filetempl:
			line = lune.strip()
			if line == "":
				provisioned.append("")
				continue

			#pass through the mutt config command block:
			if line.find("</mutt-config>") > -1:
				provisioned.append(line)
				inmutt = False
				continue
			if line.find("<mutt-config>") > -1:
				provisioned.append(line)
				inmutt = True
				continue
			if inmutt: provisioned.append(line); continue

			if line.find("=") == -1: 
				provisioned.append(line)
				continue
			parts = line.split("=")
			argpart = parts[1].strip()
			if argpart == "":
				provisioned.append(line.strip())
			elif argpart.startswith("<"):
				newconf = "%s=%s" % (parts[0], kwargs[argpart[1:-1]])
				provisioned.append(newconf)
			else:
				provisioned.append(line.strip())
		return provisioned
	#def provision(self, filetempl, kwargs).


#end class Pipes.


class Borg:
  ''' How to do a Singleton class. It's all about shared state. '''
  __shared_state = {}
  def __init__(self):
    self.__dict__ = self.__shared_state

class Configs(Borg):
  ''' Because of the inheritance from Borg, the state of self.dmrec
      is persistent, so it has to be explicitly assigned with provision,
      even over multiple instances of Configs. '''
  def __init__(self):
    Borg.__init__(self)
  def provision(self, val):
    self.dmrec = val
  def dns(self):
    return self.dmrec


##############################################################################
#DB Functions:
##############################################################################


#Getting stuff from the dmarc.db does not require the functions
#to be in class Housekeeping.

def getmeta(dbname, dbschema):

  ''' Read and return the DMARC metadata table in dmarc.db.  '''

  rows = []
  metadator = ''' select org_name, email, extra_contact_info, last_report_id from metadata; '''

  conn = sqlite3.connect(dbname)
  conn.row_factory = sqlite3.Row
  cursor = conn.cursor()
  cursor.execute(metadator)
  for row in cursor.fetchmany(10):
    org_name, email, extra_contact_id, last_report_id = row
    rows.append(row)
  return (rows)

def get_metadata(dbname, dbschema):

  ''' Read and return the DMARC metadata table in dmarc.db.  '''

  rows = []
  metadator = ''' select org_name, email, extra_contact_info, last_report_id from metadata where org_name = "had-pilot.biz"; '''

  with sqlite3.connect(dbname) as conn:
    conn.row_factory = sqlite3.Row
  cursor = conn.cursor()
  cursor.execute(metadator)
  for row in cursor.fetchmany(10):
    org_name, email, extra_contact_id, last_report_id = row
    rows.append(row)
  return (rows)



def update_last_id(newid, dbname, dbschema):

  ''' Update the last report id in metadata. '''

  conn = 0; schema = 0
  sqlup = """update metadata set last_report_id=%d where id=1;""" % (newid)

  if not os.path.exists(dbname):
    conn = sqlite3.connect(dbname)
    with open(dbschema, 'rt') as f:
      schema = f.read()
    conn.executescript(schema)
  else:
    conn = sqlite3.connect(dbname)
  conn.executescript(sqlup)
  print "commons: last report id updated to %d in dmarc.db." % (newid)


def get_adders(dbname, dbschema):

  ''' Read and return the DMARC address table in dmarc.db.  '''

  rows = []
  adderer = ''' select id, adder, addername, last_report_date from adders; '''

  with sqlite3.connect(dbname) as conn:
    conn.row_factory = sqlite3.Row
  cursor = conn.cursor()
  cursor.execute(adderer)
  for row in cursor.fetchmany(999):
    id, adder, addername, last_report_date = row
    rows.append(row)
  return (rows)


def update_last_date(addr, newdate, dbname):

  ''' Update the last report date for the given address in adders. '''

  conn = 0;
  sqlaup = """update adders set last_report_date=%d where adder=\'%s\';""" % (newdate, addr)
  conn = sqlite3.connect(dbname)
  print dbname, sqlaup
  conn.executescript(sqlaup)


def print_adders(rws):
  if len(rws) == 0:
    print "No records."
  else:
    for oar in rws:
      if oar[1] == "127.0.0.1": continue
      try:
        print "id[%d]: %s (%s), last=%s" % (oar[0], oar[2], oar[1], oar[3])
      except:
        print oar


def get_indexed_record(ix, dbname):

  ''' Get a single dmarc record by index. '''


  sqlmonster = ''' select id, AuthFailspf, AuthFaildkim, AuthFailalign, FeedbackType, DeliveryResult, SourceIP, UserAgent, Version, OriginalRcptTo, ArrivalDate, OriginalMailFrom, DKIMSignature, Subject, Reported, SPFReason, DKIMReason, DMARCReason, Message from results where id = %d; ''' % (ix)

  with sqlite3.connect(dbname) as conn:
    conn.row_factory = sqlite3.Row
  cursor = conn.cursor()
  cursor.execute(sqlmonster)
  row = cursor.fetchone()
  return row


def get_messages_by_fromadd(fromadd, dbname):

  '''get all messages by from address. '''


  if fromadd.find("@") >= 0:
    fromz = fromadd.split("@")
    fromadd = fromz[1]

  sqlget = ''' select id, Message from results where OriginalMailFrom = %s; ''' % (fromadd)

  with sqlite3.connect(dbname) as conn:
    conn.row_factory = sqlite3.Row
  cursor = conn.cursor()
  cursor.execute(sqlget)
  rows = cursor.fetchmany(99)
  return rows

def get_records(fromadd):

  ''' Read and return all records in the DMARC results table. '''

  rows = []; swor = []
  swor = get_all_records()
  for swo in swor:
    if swo[11].find(fromadd) >= 0 or swo[6].find(fromadd) >= 0:
      rows.append(swo)

  return (rows)

def dont_get_all_records(dbname, dbschema):

  ''' Read and return all records in the DMARC results table. '''

  print "dbname=%s" % (dbname)
  print "dbschema=%s" % (dbschema)
  rows = []
  sqlmonster = ''' select id, AuthFailspf, AuthFaildkim, AuthFailalign, FeedbackType, DeliveryResult, SourceIP, UserAgent, Version, OriginalRcptTo, ArrivalDate, OriginalMailFrom, DKIMSignature, Subject, Reported, SPFReason, DKIMReason, DMARCReason, Message from results; '''

  with sqlite3.connect(dbname) as conn:
    conn.row_factory = sqlite3.Row
  cursor = conn.cursor()
  cursor.execute(sqlmonster)
  try:
    for row in cursor.fetchmany(9999):
      bigtuple = row
      rows.append(bigtuple)
  except sqlite3.OperationalError: pass
  #except: print "commons:get_records: No Records Retrieved"

  return (rows)

def get_all_records(dbname, dbschema):

  ''' Read and return all records in the DMARC results table. '''

  rows = []
  sqlmonster = ''' select id, AuthFailspf, AuthFaildkim, AuthFailalign, FeedbackType, DeliveryResult, SourceIP, UserAgent, Version, OriginalRcptTo, ArrivalDate, OriginalMailFrom, DKIMSignature, Subject, Reported, SPFReason, DKIMReason, DMARCReason, Message from results; '''

  with sqlite3.connect(dbname) as conn:
    conn.row_factory = sqlite3.Row
  cursor = conn.cursor()
  cursor.execute(sqlmonster)
  for el in range(99999):
    try:
      row = cursor.fetchone()
    except sqlite3.OperationalError: pass
    except: print "commons:get_records: No Records Retrieved"
    if row == None: break
    rows.append(row)

  return (rows)

def get_all_bods(dbname, dbschema):

  ''' Read and return all records in the DMARC bodies table. '''

  rows = []
  sqlmidget = ''' select id, body from bodies; '''

  with sqlite3.connect(dbname) as conn:
    conn.row_factory = sqlite3.Row
  cursor = conn.cursor()
  cursor.execute(sqlmidget)
  try:
    for row in cursor.fetchmany(9999):
      bigtuple = row
      rows.append(bigtuple)
  except: print "commons:get_bodies: No Records Retrieved"

  return (rows)





def set_reported(id, dbname):
  conn = 0
  sqlrup = ''' update results set Reported=1 where id=%d; ''' % (id)
  print sqlrup
  conn = sqlite3.connect(dbname)
  conn.executescript(sqlrup)
    
def print_dmarc_dict(rec):

  ''' Pretty print the fields in a DMARC record. '''

  print "\n###############################################################"
  print "\tSPF result: ", rec['AuthFailspf']
  print "\tDKIM result: ", rec['AuthFaildkim']
  print "\tAlignment result: ", rec['AuthFailalign']
  print "\tFeedback: ", rec['FeedbackType']
  print "\tDelivery Result: ", rec['DeliveryResult']
  print "\tSource IP: ", rec['SourceIP']
  print "\tUser Agent: ", rec['UserAgent']
  print "\tVersion: ", rec['Version']
  print "\tRecipient: ", rec['OriginalRcptTo']
  print "\tArrival Date: ", rec['ArrivalDate']
  print "\tFrom: ", rec['OriginalMailFrom']
  print "\tDKIM Signature: ", rec['DKIMSignature']
  print "\tSubject: ", rec['Subject']
  print "\tSPFReason: ", rec['SPFReason']
  print "\tDKIMReason: ", rec['DKIMReason']
  print "\tDMARCReason: ", rec['DMARCReason']
  print "\tMessage: ", rec['Message']
  print "###############################################################\n"


def print_dmarc_record(rec):

  ''' Pretty print the fields in a DMARC record. '''

  print "\n"
  print "Id[%d]: " % (rec[0])
  print "\tSPF result: ", rec[1]
  print "\tDKIM result: ", rec[2]
  print "\tAlignment result: ", rec[3]
  print "\tFeedback: ", rec[4]
  print "\tDelivery Result: ", rec[5]
  print "\tSource IP: ", rec[6]
  print "\tUser Agent: ", rec[7]
  print "\tVersion: ", rec[8]
  print "\tRecipient: ", rec[9]
  print "\tArrival Date: ", time.ctime(float(rec[10]))
  print "\tFrom: ", rec[11]
  frags = rec[12].split("Received")
  try: print "\tDKIM Signature: ", frags[0]  #print DKIM-Signature not full headers.
  except: print rec[12]
  print "\tSubject: ", rec[13]
  print "\tReported: ", rec[14]
  print "\tSPFReason: ", rec[15]
  print "\tDKIMReason: ", rec[16]
  print "\tDMARCReason: ", rec[17]
  print "\tMessage: ", rec[18]
  print "\n"

def format_dmarc_record(rec, liner=""):

  ''' Pretty format the fields in a DMARC record. '''
  fmt = "\n"; prr = ""

  prr = rec[0]; fmt += "Id[%d]:  %s\n" % (prr, liner)
  prr = rec[1]; fmt += "\tSPF result: %s %s\n" % (prr, liner)
  prr = rec[2]; fmt += "\tDKIM result: %s %s\n" % (prr, liner)
  prr = rec[3]; fmt += "\tAlignment result: %s %s\n" % (prr, liner)
  prr = rec[4]; fmt += "\tFeedback: %s %s\n" % (prr, liner)
  prr = rec[5]; fmt += "\tDelivery Result: %s %s\n" % (prr, liner)
  prr = rec[6]; fmt += "\tSource IP: %s %s\n" % (prr, liner)
  prr = rec[7]; fmt += "\tUser Agent: %s %s\n" % (prr, liner)
  prr = rec[8]; fmt += "\tVersion: %s %s\n" % (prr, liner)
  prr = rec[9]; fmt += "\tRecipient: %s %s\n" % (prr, liner)
  prr = rec[10]; fmt += "\tArrival Date: %s %s\n" % (time.ctime(float(prr)), liner)
  prr = rec[11]; fmt += "\tFrom: %s %s\n" % (prr, liner)
  frg = rec[12].split("Received")  #print the DKIM-Signature, not full headers.
  try: prr = frg[0]; fmt += "\tDKIM Signature: %s %s\n" % (frg[0], liner)
  except: prr = rec[12]; fmt += prr
  prr = rec[13]; fmt += "\tSubject: %s %s\n" % (prr, liner)
  prr = rec[14]; fmt += "\tReported: %s %s\n" % (prr, liner)
  prr = rec[15]; fmt += "\tSPFReason: %s %s\n" % (prr, liner)
  prr = rec[16]; fmt += "\tDKIMReason: %s %s\n" % (prr, liner)
  prr = rec[17]; fmt += "\tDMARCReason: %s %s\n" % (prr, liner)
  prr = rec[18]; fmt += "\tMessage: %s %s\n" % (prr, liner)
  fmt += " %s\n" % liner
  return fmt

def shortrec(rec):
  ''' Print a short form of the record on one line. '''
  fmt = "ix[%d] %s, subj:%s, from:%s (%s), spf:%s, dkim:%s, align:%s, reported:%d\n"
  ftd = fmt % (rec[0], time.ctime(float(rec[10])), rec[13], rec[11], rec[6], rec[1], rec[2], rec[3], rec[14])
  return ftd
 

def format_skim_result(rec):

  ''' Format the dmarc.db results for SPF and DKIM tests. '''

  prr = ""; walltime = time.ctime(float(rec[10]))

  if rec[5].find("Pass") >= 0 or rec[5].find("Continue") >= 0: prr = "Delivered"
  else: prr = "Not Delivered"
  fmt = "\nHere are the results of the message from %s\n\
received on %s with Subject %s\n\n\
The message was: %s\n\
The SPF result was: %s\n\
The DKIM result was: %s\n" % (rec[11], walltime, rec[13], prr, rec[1], rec[2])

  return fmt



def print_headers(rec, subject=False):

  ''' Pretty print the message headers from a DMARC record. '''

  print "\n###############################################################"
  print "Id[%d]: " % (rec[0])
  print "\tSPF result: ", rec[1]
  print "\tDKIM result: ", rec[2]
  #print the full headers.
  if subject:
    theyall = rec[12].split("\n")
    for wun in theyall:
      if wun.find("Subject:") >= 0:
        print wun
  else:
    print rec[12]
  print "###############################################################\n"


'''
---------------------------------------------------------------------------
SMIMEA TEST FUNCTIONS
Some access same results table as DMARC, all other are distinct
---------------------------------------------------------------------------
'''

def get_smime_records(fromadd):

    ''' Read and return all records from given address '''

    rows = []; # swor = []
    swor = get_all_records("SMIME")
    for swo in swor:
        if swo[2].find(fromadd) >= 0 or swo[7].find(fromadd) >= 0:
            rows.append(swo)

    return (rows)

def get_all_smime_records(dbname, dbschema):

    ''' Read and return all records SMIME formatted records results table. '''

    rows = []
    sqlmonster = " select " + smimeRecordFields +  " from results; "

    with sqlite3.connect(dbname) as conn:
        conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(sqlmonster)
    try:
        for row in cursor.fetchmany(9999):
            bigtuple = row
            rows.append(bigtuple)
    except: print "commons:get_records: No Records Retrieved"

    return (rows)

def get_indexed_smime_record(ix, dbname):

    ''' Get a single smime formatted record by index. '''


    # smimeRecordFields = '''id, SMIMEACheckStatus, SourceIP, UserAgent, Version, OriginalRcptTo, ArrivalDate, OriginalMailFrom, Subject, Message '''
    sqlmonster = " select " + smimeRecordFields + " from results where id = %d; " % (ix)

    with sqlite3.connect(dbname) as conn:
        conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(sqlmonster)
    row = cursor.fetchone()
    return row




def get_danesenders_adders(dname, dbschema):
  
    ''' Read and return the email DANE user addresses in dmarc.db.  '''

    print "In get_danesenders_adders()"
    rows = []
    adderer = ''' select id, ip_addr, email_addr, application, count, first_test_date, last_test_date from danesenders; '''

    with sqlite3.connect(dbname) as conn:
        conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(adderer)
    for row in cursor.fetchmany(999):
        rows.append(row)
    return (rows)


def get_time_since_danesenders_last(ip_addr, email_addr, application, dbname, dbschema):
    ''' 
    Return number of seconds elapsed since user row with specific 
    ip_addr, email_addr, application was updated.
    Returns difference between current time and last_test_data column.
    '''
    # import time
    
    
    sqltext = ''' SELECT last_test_date FROM danesenders WHERE ip_addr=\'%s\' AND email_addr=\'%s\' AND application=\'%s\' ''' % (ip_addr, email_addr, application)
  
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute(sqltext)
    times = cursor.fetchall()
    curtime = int(time.time())
    if len(times) == 0:
        # No Matching Rows
        return(curtime)
    elif len(times) == 1:
        # Return differencem unique matching row
        return(curtime - int(times[0][0]))
    else:
        # Return count from first Matching row
        print "Duplicate entries in danesenders table: %s, %s, %s" % (ip_addr, email_addr, application)
        return(curtime - int(times[0][0]))



def update_danesender(ip_addr, email_addr, application):
    '''
    Update row if exists, insert if new
    '''
    curtime = time.time()
    events = get_danesenders_count(ip_addr, email_addr, application)
    if events > 0:
        update_danesenders_date(ip_addr, email_addr, application, curtime, events+1)
    else:
        insert_danesenders(ip_addr, email_addr, application)
        


def get_danesenders_count(ip_addr, email_addr, application, dbname, dbschema):
    ''' 
    Return 'count' column value for specific ip_addr, email_addr, application row
    Returns 0 if no matching row
    Used to identify whether to update or insert a new row
    '''
    sqltext = ''' SELECT count FROM  danesenders WHERE ip_addr=\'%s\' AND email_addr=\'%s\' AND application=\'%s\' ''' % (ip_addr, email_addr, application)
  
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute(sqltext)
    counts = cursor.fetchall()
    if len(counts) == 0:
        # No Matching Rows
        return(0)
    elif len(counts) == 1:
        # Return count value from unique matching row
        return(int(counts[0][0]))
    else:
        # Return count from first Matching row
        print "Duplicate entries in danesenders table: %s, %s, %s" % (ip_addr, email_addr, application)
        return(counts[0][0])



def update_danesenders_date(ip_addr, email_addr, application, newdate, count, dbname):

    ''' Update the last tested date for the given ip and email address in danesenders. '''

    # conn = 0;
    sqlaup = """update danesenders set last_test_date=%d, count=%d where email_addr=\'%s\' and ip_addr=\'%s\' and application=\'%s\';""" % (newdate, count, email_addr, ip_addr, application)
    conn = sqlite3.connect(dbname)
    print dbname, sqlaup
    with conn:
        cur = conn.cursor()
        cur.execute(sqlaup)
        conn.commit()
        return(cur.rowcount)  # Number of rows updated
  
  
def insert_danesenders(ip_addr, email_addr, application, dbname, dbschema):
    ''' Insert new row into danesenders'''
    #import time
    

    now = int(time.time())
    count = 1
    
    conn = sqlite3.connect(dbname)
    with open(dbschema, 'rt') as f:
        schema = f.read()
    conn.executescript(schema)
    print "HK: dmarc.db created from insert_danesenders."

    sqlstring = """insert into danesenders(ip_addr, email_addr, application, count, first_test_date, last_test_date) values ('%s', '%s', '%s', '%d', '%d', '%d');""" % (ip_addr, email_addr, application, count, now, now)
    curs = conn.cursor()
    curs.execute(sqlstring)
    conn.commit()

    



def getAllNullSMIMEACheckStatus(dbname):

    ''' Return all records (in SMIME fields) that have null SMIMEACheckStatus '''

    try:
        with sqlite3.connect(dbname) as con:
            c = con.cursor()
            query = "select " + smimeRecordFields + " from results WHERE SMIMEACheckStatus IS NULL"
            c.execute(query)
            return(c.fetchall())
    except:
        print "commons: something corrupted in getAllNullSMIMEACheckStatus."
        returnNull 



def updateSMIMEACheckStatus(idx, dbname, status="NotSMIME"):

    ''' Update the SMIMEACheckStatus field in the email results table '''

    with sqlite3.connect(dbname) as conn:
        c = conn.cursor()
        query = "update results set SMIMEACheckStatus = :status where id = :id"
        c.execute(query, {'status':status, 'id':idx})
  

def new_smimea_data_row(row, dbname, dbschema):

    ''' 
    Create db if non-existent.  
    Add new row containing all fields (though some may be empty strings)
    id ([0]) is index matching email message(results) table
    uuid ([1]) is unique identifier for recipients to use for access
    '''

    conn = 0; schema = 0

    # Filling certificate access value with "0" since it's no longer in our model
    print "rows 6, 7, 8 and 9\n%s\n%s\n%s\n%s" % (row[6],row[7],row[8],row[9])
    sqlstring = """insert into smimeadata
                 ( id, uuid, application, has_DANE, 
                   smimelock, certificate_usage, selector, 
                   matching, certificate_access, DANE_match_data, 
                   local_match_data, signing_cert, 
                   signing_cert_spki, DANE_request_domain, 
                   DANE_request_result, test_result ) values 
                   ( %d, '%s', '%s','%s',
                         '%s', '%s','%s',
                         '%s', '%s','%s',
                         '%s', '%s',                                              
                         '%s', '%s',
                         '%s', '%s'
                    );""" % (row[0], row[1], row[2], row[3],
                             row[4], row[5], row[6], 
                             row[7], "0", row[9], 
                             row[10], row[11], 
                             row[12], row[13], 
                             row[14], row[15] 
                     )
                    
    print "SQL IS: %s" % sqlstring
    if not os.path.exists(dbname):
        conn = sqlite3.connect(dbname)
        with open(dbschema, 'rt') as f:
            schema = f.read()
        #print schema
        conn.executescript(schema)
        conn.executescript(sqlstring)
        conn.close()
        print "HK: New DMARC Database created from insert_smime_data()."
    else:
        conn = sqlite3.connect(dbname)
        try:
            conn.executescript(sqlstring)
            print "SMIMEA record written to DB."
        except:
            print "DB write failed."

    conn.close()


def update_smimea_data( recid, has_smimea, certificate_usage, selector, matching, certificate_access, smimea_match_data, smimea_request_domain, smimea_request_result, test_result, dbname, dbschema ):

    ''' 
    Create db if non-existent.  
    Add row with only recid, uuid, smime status and result
    recid is index matching email message(results) table
    '''

    conn = 0; schema = 0


    #sqlstring = """UPDATE smimeadata SET has_smimea = '%d', certificate_usage = '%s', selector = '%s', matching = '%s', certificate_access = '%s', smimea_match_data = '%s', smimea_request_domain = '%s', smimea_request_result = '%s', test_result = '%s'  WHERE id = '%d' ;""" % (has_smimea, certificate_usage, selector, matching, certificate_access, smimea_match_data, smimea_request_domain, smimea_request_result, test_result, recid)
    sqlstring = """UPDATE smimeadata SET has_smimea = '%d', certificate_usage = '%s', selector = '%s', matching = '%s', smimea_match_data = '%s', smimea_request_domain = '%s', smimea_request_result = '%s', test_result = '%s'  WHERE id = '%d' ;""" % (has_smimea, certificate_usage, selector, matching, smimea_match_data, smimea_request_domain, smimea_request_result, test_result, recid)
    print "SQL STRING IS: %s" % sqlstring
    if not os.path.exists(dbname):
        conn = sqlite3.connect(dbname)
        with open(dbschema, 'rt') as f:
            schema = f.read()
        #print schema
        conn.executescript(schema)
        conn.executescript(sqlstring)
        conn.close()
        print "HK: New DMARC Database created from insert_smime_data()."
    else:
        conn = sqlite3.connect(dbname)
        try:
            conn.executescript(sqlstring)
            print "HK: SMIMEA record written to DB."
        except:
            print "Housekeeping: DB write failed."

    conn.close()


def update_certificate_data( idx, is_smime, local_match_data, signing_cert, signing_cert_spki, test_result, dbname, dbschema ):

    '''
    Create db if non-existent.
    Add row with only idx, uuid, smime status and result
    idx is index matching email message(results) table
    '''

    # conn = 0; 
    # schema = 0


    sqlstring = """UPDATE smimeadata SET ( is_smime='%d', local_match_data='%s', signing_cert='%s', signing_cert_spki='%s', test_result=%s') WHERE id='%d';""" % ( is_smime, local_match_data, signing_cert, signing_cert_spki, test_result, idx)

    conn = sqlite3.connect(dbname)
    try:
        conn.executescript(sqlstring)
        print "Certificate info updated"
    except:
        print "Certificate info update failed"

    conn.close()




def get_all_smimea_data_records(dbname, dbschema):

    ''' Read and return all records SMIME formatted records results table. '''

    rows = []
    sqlmonster = " select " + smimea_table_fields +  " from smimeadata; "

    with sqlite3.connect(dbname) as conn:
        conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(sqlmonster)
    try:
        for row in cursor.fetchmany(9999):
            bigtuple = row
            rows.append(bigtuple)
    except: print "commons:get_all_smimea_data_records: No Records Retrieved"

    return (rows)



def get_smimea_data_by_index(idx, dbname, dbschema):

    ''' Read and return all records SMIME formatted records results table. '''

    # rows = []
    sqlmonster = " select " + smimea_table_fields +  " from smimeadata where id=%d; " % idx

    with sqlite3.connect(dbname) as conn:
        conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(sqlmonster)
    try:
        return(cursor.fetchone())
    except: print "commons:get_all_smimea_data_records: No Records Retrieved"

    return (())


def get_smimea_data_by_uuid(uuid, dbname, dbschema):

    ''' Read and return all records SMIME formatted records results table. '''

    # rows = []
    sqlmonster = ''' select %s from smimeadata where uuid="%s"; ''' % (smimea_table_fields, uuid)
    print sqlmonster

    with sqlite3.connect(dbname) as conn:
        conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(sqlmonster)
    try:
        return(cursor.fetchone())
    except: print "commons:get_all_smimea_data_records: No Records Retrieved"

    return (())

def print_smime_record(rec):

    ''' Pretty print the fields in an SMIME record. '''

    print "\n"
    print "Id[%d]: " % (rec[0])
    print "\tSMIMEA Check Status: ", rec[1]
    print "\tSource IP: ", rec[2]
    print "\tUser Agent: ", rec[3]
    print "\tVersion: ", rec[4]
    print "\tRecipient: ", rec[5]
    print "\tArrival Date: ", time.ctime(float(rec[6]))
    print "\tFrom: ", rec[7]
    print "\tSubject: ", rec[8]
    print "\tMessage: ", rec[9]
    print "\n"



##############################################################################
#Utilities:
##############################################################################

def filein(filename, oneline=False):

	''' Open the specified file, read it and return the contents. '''

	sl = []
	fp = open(filename)
	fl = fp.readlines()
	for el in fl:
		sl.append(el.strip())
	fp.close()
	if oneline:
		return "\n".join([el for el in sl])
	else:
		return sl

#def filein(filename).


def fileout(filename, contents, mode='w'):

	''' Open the specified file, and write the contents to it. '''

	fp = open(filename, mode)
	for line in contents:
		fp.write("%s%s" % (line, "\n"))
	fp.close()
	
#def fileout(filename, contents).

def filestringout(filename, contents, mode='w'):

	''' Open the specified file, and write the contents to it 
            as a string. '''

	try:
		fp = open(filename, mode)
		fp.write(contents)
		fp.close()
	except:
		print filename, "I/O problem."
 	
#def filestringout(filename, contents).


def printdict(dict):

	''' printdict(dict): Print the keys and values of a dictionary, unordered'''

	for key in dict:
		print key, "=", dict[key]

#end def printdict(dict).


def printlist(alist, perline=True):

	''' printlist(alist, perline=True): Print the items in a list. 
	    One line or one item per line '''

	print ""
	for el in alist:
		if perline: print el
		else: print el,
	print ""

#end def printlist(alist, perline=True).

def inlist(el, inclu):

	''' return True if el is a member of list inclu, else False. '''

	try:
		for member in inclu:
			if el == member: return True
	except: pass   #Handle empty lists.
	return False

#end def inlist(el, inclu).

def startel(el, inclu):

	''' return True if a member of list inclu startswith el, else False. '''

	try:
		for member in inclu:
			if el.startswith(member): return True
	except: pass   #Handle empty lists.
	return False

#end def startel(el, inclu).

def findel(el, inclu):

	''' return True if a member of list inclu contains el, else False. '''

	try:
		for member in inclu:
			if member.find(el) >= 0: return True
	except: pass   #Handle empty lists.
	return False

#end def findel(el, inclu).


def prunetime(tim):

	''' Top and tail the time.ctime() result. '''

	try:
		pieces = tim.split(" ")
		return " ".join(pieces[1:-1])
	except:
		return tim

#def prunetime(tim):

def snipit(flnm, turm):

	''' Return all instances of turm from flnm, or the given block length. '''

	fi = filein(flnm)
	trums = turm.split("|")
	if len(trums) == 1:
		return snipturm(fi, turm)
	else:
		return snipblock(fi, trums[0], int(trums[1]))

def snipturm(ft, tt):

	''' Return instances of tt in ft. '''

	all = ""
	for ln in ft:
		if ln.find(tt) >= 0:
			all = all + ln + "<br>\n"
	return all

def snipblock(ft, tt, tb):

	''' Return block length tb from onset of tt in ft. '''

	started = False; ix = 0; fix = 0; all = ""
	for ln in ft:
		ix += 1
		if started:
			all = all + ln + "<br>\n"
			if ix == fix:
				return all
		else:
			if ln.find(tt) >= 0:
				started = True
				fix = ix + tb
				all = ln + "<br>\n"
			#else: continue


#Make angle brackets in a string html readable:
def angulate(braksin):
	lbrak = braksin.replace("<", "&lt;")
	rbrak = lbrak.replace(">", "&gt;")
	return rbrak



#####################################################################
