
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



import sys, os, ast, squall, dinsget

'''
Stephen Nightingale,
NIST April 2016.

transmogrify.py: Convert sqlite DB records from old 'dmarc.db'
to new 'pmarc.db' format.  Backfill the SPF/DKIM/DMARC DNS records.
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



#buildNewDBfromOld(el): Copy the dmarcdb record elements into the pmarcdb format:
def buildNewDBfromOld(anel):
  adict = {}

  adict['Version'] = anel[8]  
  adict['UserAgent'] = anel[7]  
  if anel[14] == 1:
    adict['Reported'] = 1
  else:
    adict['Reported'] = 0
  adict['ArrivalDate'] = anel[10]  
  adict['OriginalMailFrom'] = str(anel[11])  
  adict['OriginalRcptTo'] = str(anel[9])  
  adict['SourceIP'] = anel[6]  
  adict['DKIMSignature'] = anel[12]  
  adict['Subject'] = ""
  adict['Body'] = anel[13]  
  adict['SPFresult'] = anel[1]  
  adict['DKIMresult'] = anel[2]  
  adict['Alignresult'] = anel[3]  
  if anel[5] == "Pass":
    adict['Deliveryresult'] = "Deliver"
  else:
    adict['Deliveryresult'] = anel[5]  

  #Initialize the non-transferred elements:
  adict['SPFrecord'] = ""
  adict['DKIMrecord'] =  ""
  adict['DMARCrecord'] =  ""
  adict['SPFreason'] =  ""
  adict['DKIMreason'] =  ""
  adict['DMARCreason'] =  ""

  return adict


#getDNSRecords(anel): Fill in the SPF, DKIM and DMARC record fields:
def getDNSRecords(anel, rextodate):
  kmailfrom = ""
  mailfrom = str(anel['OriginalMailFrom'])
  if mailfrom.find('@') >= 0:
    lefrie = mailfrom.split('@')
    mailfrom = lefrie[1]
  if mailfrom and mailfrom[-1] == '.':
    mailfrom = mailfrom[:-1]
  dmailfrom = "_dmarc." + mailfrom
  kmailfrom = getDKIMdomain(anel['DKIMSignature'])

  if mailfrom in rextodate:
    anel['SPFrecord'] = rextodate[mailfrom]
    anel['DMARCrecord'] = rextodate[dmailfrom]
    if kmailfrom and kmailfrom in rextodate:
      anel['DKIMrecord'] = rextodate[kmailfrom]
  else:
    spfrec = dinsget.domain_spf(mailfrom)
    rextodate[mailfrom] = spfrec
    anel['SPFrecord'] = spfrec
    dmarcrec = dinsget.domain(dmailfrom)
    rextodate[mailfrom] = dmarcrec
    anel['DMARCrecord'] = dmarcrec
    if kmailfrom:
      dkimrec = dinsget.domain_dkim(kmailfrom)
      rextodate[kmailfrom] = dkimrec
      anel['DKIMrecord'] = dkimrec

  return anel


if __name__ =="__main__":

  dbrex = sys.argv[1]      #old db text records
  newdb = sys.argv[2]  #new db name
  newsch = sys.argv[3]  #new db schema
  rextups = []; pmarcel = {}

  for el in open(dbrex):
    newel = ast.literal_eval(el)
    if str(newel[6]) == '127.0.0.1': continue
    pmarcel = buildNewDBfromOld(newel)
    rextups.append(pmarcel)

  print len(rextups)
  trashcon = squall.create_db(newdb, newsch)

  for morcel in rextups:
    print squall.putresult(newdb, newsch, morcel)


