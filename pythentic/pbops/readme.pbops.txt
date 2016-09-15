
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



Created: Dec 22, 2015.
Stephen Nightingale.


squall.py contains the python methods for creating, updating
and reading sqlite3 databases.

This directory contains databases for: dmarc.db, pgp.db
And database schemata for each of these in: dmarc_schema.sql, pgp_schema.sql
Metadata is populated from: dmarcdb.conf, pgpdb.conf
Auto test commands are found in: testfile.

python squall.py<enter>  returns the list of commands.

python squall.py autotest testfile<enter>  runs the auto testfile.

Individual commands are of the general form of:
python squall.py getresult dmarc.db<enter>

Read testfile for a comprehensive set of commands.

Intended use is to import squall as a library into your python script
and call methods with the general scheme of:
squall.putresult(dbname, dbschema, argdict)

#########################################################################
squall.py methods are as follows:

def create_db(dbname, dbschema):
def update_db(dbname, dbschema, squill, argtuple):
def update_safe(dbname, dbschema, squill, argtuple):
def extract_db(dbname, squill):
def extract_all(dbname, squill):
def putmeta(dbname, dbschema, metadata):
def putadder(dbname, dbschema, argtuple):
def getmeta(dbname):
def getadder(dbname):
def putresult(dbname, dbschema, argdict):
def unpackrec(adict):
def buildrec():
def getresult(dbname):
def setreported(dbname, dbschema, id):
def printtable(dbname, atable):
def printadders(dbname):
def printresults(dbname):
def dotests(testfile):
def docommands(sysargv):
#########################################################################


