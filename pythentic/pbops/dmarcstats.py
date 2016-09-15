
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



import sys, os, squall, time

def printdict(adict):
  for key in adict:
    print "%s = %d" % (key, adict[key])


def printdicbyvec(adict, avec):
  for el in avec:
    print "%s = %d" % (el, adict[el])

def printsorted(adict):
  for key, value in sorted(adict.iteritems(), key=lambda (k, v): (v, k), reverse=True):
    print "%s = %d" % (key, value)


def accumulate(thedict, akey):
  if akey != None and not isinstance(akey, int): lowkey = akey.lower()
  else: lowkey = akey
  if lowkey in thedict: thedict[lowkey] += 1
  else: thedict[lowkey] = 1

  return thedict


def distribution(adict):
  distro = {}
  for key in adict:
    if not adict[key] in distro:
      distro[adict[key]] = 1
    else:
      distro[adict[key]] += 1
  return distro



def sumup(thedict):
  thetot = 0
  for key in thedict:
    thetot += thedict[key]
  return thetot


def printtld(adict):
  bagup = {}
  for key in adict:
    bag = key.split('.')
    if len(bag) == 1: continue
    bagup = accumulate(bagup, bag[-1])

  printsorted(bagup)
  print "%d unique tlds." % (len(bagup))


def spiffsort(dbrex):
  sprex = []

  for reck in alldbrex:
    if reck[11] == "":
      sprex.append("non")
    elif reck[11] == None:
      continue
    elif reck[11].find('#') > 0:
      sparts = reck[11].split('#')
      for spart in sparts:
        sprex.append(spart)
    else:
      sprex.append(reck[11])

  sprex.sort(lambda x,y:  cmp(len(x), len(y)))
  for spiff in sprex:
    print spiff



def spiffup(dbrex):
  spfup = {}; spfdep = {}
  v6count = 0; v4count = 0; alls = 0; allalls = 0
  for reck in dbrex:
    spfr = reck[11]
    if spfr != None:
      try: 
        spfmult = spfr.split('#')
        for spfrec in spfmult:
          meks = spfrec.split(' ')
          for mek in meks:
            if mek.find('ip4') >= 0: v4count += 1
            if mek.find('ip6') >= 0: v6count += 1
            if mek.find('+all') >= 0: alls += 1
            if mek.find('all') >= 0: allalls += 1
          spfup = accumulate(spfup, len(meks))
        spfdep = accumulate(spfdep, len(spfmult))
      except:
        meks = spfr.split(' ')
        if mek.find('ip4') >= 0: v4count += 1
        if mek.find('ip6') >= 0: v6count += 1
        if mek.find('+all') >= 0: alls += 1
        if mek.find('all') >= 0: allalls += 1
        spfup = accumulate(spfup, len(meks))
        spfdep = accumulate(spfdep, 1)

  print "Range of SPF mechanism lengths:"
  for oneup in spfup:
    print "%d = %d" % (oneup, spfup[oneup])
  print "Total unique SPF records: %s" % (sumup(spfup))
  print "Range of SPF record depths:"
  for onedep in spfdep:
    print "%d = %d" % (onedep, spfdep[onedep])
  print "ip6 versus ip4:"
  print "ip6 = %d, ip4 = %d, ratio = %d%%" % (v6count, v4count, (v6count*100/v4count))
  print "Spam Vectors (+all) vs (all): %d / %d = %d" % (alls, allalls, alls*100/allalls)


#Print summaries of DMARC Delivery results:
def printdmarcs(dbrex):
  deli = [0,0,0,0,0]
  disc = [0,0,0,0,0]
  rej = [0,0,0,0,0]
  doper = [0,1,2,3,4]
  dopy = ['Hour', 'Day', 'Week', 'Month', 'Year']
  spanner = [3600, 86400, 604800, 4233600, 31536000]
  now = time.time()
  preent = "Result Deliver Discard Reject\n"

  for rek in dbrex:
    for ix in doper:
      try:
        if now - float(rek[4]) < spanner[ix]:
          if rek[16] == 'Deliver': deli[doper[ix]] += 1
          if rek[16] == 'Discard': disc[doper[ix]] += 1
          if rek[16] == 'Reject': rej[doper[ix]] += 1
      except: continue

  for ix in range(len(dopy)):
    preent += "%s\t" % (dopy[ix])
    preent += "%d\t" % (deli[ix])
    preent += "%d\t" % (disc[ix])
    preent += "%d\n" % (rej[ix])

  preent += "\n"
  return preent


def alltimes(dbrex):
  first = 0; timebux = {}; timeseq = []

  for line in dbrex:
    try:
      thist = float(line[4])
      if first == 0: first = thist
      thisstr = time.ctime(thist)
      parts = thisstr.split(' ')
      bux = "%s%s" % (parts[1].lower(), parts[-1])
      if not bux in timeseq:
        timeseq.append(bux.lower())
      #if line[17] == 'Discard':
      #  timebux = accumulate(timebux, bux)
      timebux = accumulate(timebux, bux)
    except:
      print "Discard: ", line[4]

  printdicbyvec(timebux, timeseq)


if __name__ == "__main__":

  allsql = "select * from results;"
  dbhasrex = False; alldbrex = []
  countup = {}; subup = {}; spfup = {}; dmarcup = {}; dkimup = {}
  dkdisp = { '0' : "fail", '1' : "pass", 'False' : "fail", 'Fail' : "fail", 'True' : "pass" }

  try:
    dbn = sys.argv[1]
    argtoo = sys.argv[2]
    (dbhasrex, alldbrex) = squall.extract_all(dbn, allsql)
  except:
    sys.exit("Usage: python dmarcstats.py olddmarc.db|pmarc.db <qualifier>")

  if not dbhasrex:
    sys.exit("No records in %s" % (dbn))

  #sys.argv[2] determines what analysis is to be done:
  if argtoo == "raw":
    for line in alldbrex:
      print line

  if argtoo == "alltimes":
    alltimes(alldbrex)

  elif argtoo == "domain":
    dister = {}
    for reck in alldbrex:
      countup = accumulate(countup, reck[5])
    printsorted(countup)
    print "%d unique users." % (len(countup))
    dister = distribution(countup)
    print "Distribution of use instances:"
    printsorted(dister)

  elif argtoo == "tld":
    for reck in alldbrex:
      countup = accumulate(countup, reck[5])
    printtld(countup)

  elif argtoo == "subject":
    for reck in alldbrex:
      subup = accumulate(subup, "%s:%s" % (reck[17], reck[9]))
    printsorted(subup)
    print "%d unique subjects." % (len(subup))

  elif argtoo == "disposition":
    for reck in alldbrex:
      try: thist = float(reck[4])
      except: continue
      thisstr = time.ctime(thist)
      parts = thisstr.split(' ')
      bux = "%s%s:%s" % (parts[1].lower(), parts[-1], reck[17])
      subup = accumulate(subup, bux)
    printsorted(subup)
    print "%d unique dispositions." % (len(subup))

  elif argtoo == "spfrec":
    spiffup(alldbrex)

  elif argtoo == "spfrecurse":
    for reck in alldbrex:
      try:
        if reck[11].find('#') > 0:
          cursers = reck[11].split('#')
          print cursers[0]
          for onespf in cursers[1:]:
            print "\t%s" % (onespf)
      except: pass

  elif argtoo == "spfrecord":
    spiffsort(alldbrex)

  elif argtoo == "dkimrec":
    for reck in alldbrex:
      dkimup = accumulate(dkimup, reck[12])
    printsorted(dkimup)
    print "%d unique subjects, %d total subjects." % (len(dkimup), sumup(dkimup))

  elif argtoo == "dmarcrec":
    for reck in alldbrex:
      dmarcup = accumulate(dmarcup, reck[13])
    printsorted(dmarcup)
    print "%d unique subjects, %d total subjects." % (len(dmarcup), sumup(dmarcup))

  elif argtoo == "dkimsig":
    for reck in alldbrex:
      dkimup = accumulate(dmarcup, reck[17])
    printsorted(dmarcup)
    print "%d DMARC dispositions." % (len(dmarcup))


  elif argtoo == "dmarcresult":
    print printdmarcs(alldbrex)

  elif argtoo == "spfresult":
    for reck in alldbrex:
      try: spfup = accumulate(spfup, "%s:%s" % (reck[14], dkdisp[reck[15]]))
      except: print "Bad Key combination: '%s', '%s'" % (reck[14], reck[15])
    printsorted(spfup)
    print "Total: %d" % (sumup(spfup))

  else:
    print "Usage: python dmarcresults.py dbname.db raw|alltimes|domain|tld|subject|disposition!spfrec|dkimrec|dmarcrec|dkimsig|dmarcresult|spfresult"

