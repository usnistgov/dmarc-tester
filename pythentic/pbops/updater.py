
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



import sys, os, squall, dinsget

'''
Stephen Nightingale, NIST
April 2016

updater.py: update specific fields in the pmarc database, with SPF/DKIM/DMARC records
and maybe other stuff.
'''

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


#Given the DKIM signature from a message, extract the domain and selector
#and form the dkim domain:
def getDKIMdomain(dksig):
  (dv, iv, sv) = extractdvalue(dksig)
  dkdom = "%s._domainkey.%s" % (sv, dv)
  return dkdom

if __name__ == "__main__":

  dbase = sys.argv[1]
  dschem = sys.argv[2]
  field = sys.argv[3]
  rextodate = {}

  (rez, oldrex) = squall.getresult(dbase)

  if not rez:
    sys.exit("%s read failed." % (dbase))

  for  rec in oldrex:
    mailfrom = rec[5]

    if mailfrom == "": continue

    if mailfrom.find('@') >= 0:
      (front, mailfrom) = mailfrom.split('@')

    if field == 'spfrecord':
      if not mailfrom in rextodate:
        spfrex = dinsget.domain_spf(mailfrom)
        rextodate[mailfrom] = spfrex
      else:
        spfrex = rextodate[mailfrom]

      sqlstr = "update results set SPFrecord = ? where id = ?;"
      argtuple = (spfrex, rec[0])
      (rez, reas) = squall.update_safe(dbase, dschem, sqlstr, argtuple)
      print rec[0], rez, reas

    if field == 'dmarcrecord':
      if not mailfrom in rextodate:
        mailfrom = "_dmarc.%s" % (mailfrom)
        dmrec = dinsget.domain(mailfrom)
        rextodate[mailfrom] = dmrec
      else:
        dmrec = rextodate[mailfrom]

      sqlstr = "update results set DMARCrecord = ? where id = ?;"
      argtuple = (dmrec, rec[0])
      (rez, reas) = squall.update_safe(dbase, dschem, sqlstr, argtuple)
      print "[%d] %s, %s, '%s'" % (rec[0], rez, reas, dmrec)


    if field == 'dkimrecord':
      if rec[8] != "":
        dkdom = getDKIMdomain(rec[8])
        if not dkdom in rextodate:
          dkimrec = dinsget.domain_dkim(dkdom)
          rextodate[dkdom] = dkimrec
        else:
          dkimrec = rextodate[dkdom]
        print "\t[%d]: %s == %s" % (rec[0], dkdom, dkimrec)
        sqlstr = "update results set DKIMrecord = ? where id = ?;"
        argtuple = (dkimrec, rec[0])
        (rez, reas) = squall.update_safe(dbase, dschem, sqlstr, argtuple)
      else:
        print "%s: no DKIM Signature." % (mailfrom)

