
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



OVERVIEW

The High Assurance Domains had-pilot DMARC test system is an email
based system that exercises:

- A sender's deployment of spf, dkim and dmarc dns records.
- A recipient's processing of had-pilot spf, dkim and dmarc records.

How It Works:
=============

- Send a message to pythentic@had-pilot.biz with subject: spf, dkim,
dmarc.
- Get a reply with an analysis of your spf, dkim dmarc record and results.
- OR Send a message to pythentic with subject: p.dkim.bad, p.dkim.bh,
p.dkim.nocr, p.dkim.nolf.
- Get a reply with a modified dkim signature, to test dkim processing.

For test instructions: https://www.had-pilot.com/py/had.html.
- This is a static page not connected to the operation of the email test
system.

Note: there is no setup.py. Fairly detailed manual configuration is
required,  for both Sendmail and the local test modules. The milter
and responder are generally run in test-system-owner directory space.


Directory structure:
===================

- all milter related code and configuration is in the pythentic directory.
- all SQLite database, test responder and mailchecker code and configuration
is in the pythentic/pbops directory.


Configuration:
==============

The tester relies on Sendmail.  All files in /etc/mail should be configured
with your own owner names and domains.  Ours are given to exemplfy what you
need to change:

access: 
Connect: had-pilot.biz     RELAY

aliases:
pythentic@had-pilot.biz:  night
forensics@had-pilot.biz:  night
reports@had-pilot.biz:    night

localhostnames:
had-pilot.biz

sendmail.mc:
FEATURE(`accept_unresolvable_domaions')dnl
define(`confDOMAIN_NAME', `had-pilot.biz')dnl
define(`confCHECK_ALIASES', true)dnl
define(`confMILTER_LOG_LEVEL', `11')dnl
INPUT_MAIL_FILTER(`pythentic_sender', `s=inet:9909@had1')dnl
INPUT_MAIL_FILTER(`pythentic_rcvr', `s=inet:9999@had1')dnl

trusted_users:
night

virtusertable:
reports@had-pilot.biz  night
forensics@had-pilot.biz  night

Files needed in /tmp: (these need write permission for the test system owner)
/tmp/pyhtentic.rlog   #milter log for receiver
/tmp/pythentic.slog   #milter log for sender
/tmp/skimfile         #tempfile for cronjob responses

DNS Records: all of type "txt"
had-pilot.biz: "v=spf1 ip4:129.6.100.200 ip6:2610:20:6005:100::200 -all"
_dmarc.had-pilot.biz: "v=DMARC1; adkim=r; aspf=s; p=none; pct=100; rf=afrf;
ri=86400; ruf=forensics.had-pilot.biz"
mailkey._domainkey.had-pilot.biz: "v=DKIM1; p=<your-private-key>"



The MILTER: dmarcmilter.py
=========================

pythentic.py and dmarcmilter.py extend ppymilterbase.py and ppymilterserver.py
originally developed by Eric DeFriez at Google.  They implement the sendmail 
milter protocol, and when configured together with an instance of sendmail, 
filter inbound and outbound messages.  The had-pilot extensions include spf,
dkim and dmarc processing of received messages, adding headers, notifying
results, and writing results and dns records to the SQLite database.
Outbound messages are dkim signed, with the DKIM-Signature field added 
to message headers.

The Sendmail Milter:
====================

Location: ./pythentic/

Invocation:
$ nohup python pythentic.py conf/send.conf &
$ nohup pthon pythentic.py conf/recv.conf &

Configs:
========

send.conf:
 milLog=/tmp/pythentic.slog
 milType=Sender
 milDB=/pathto/pythentic/pbops/pmarc.db
 milSCM=/pathto/pythentic/pbops/pmarc_schema.sql
 whoWeAre=had-pilot.biz
 keyFile=/pathto/pythentic/.domainkeys/rsa.private
 selector=mailkey
 smtpHost=had5
 smtpPort=9909


recv.conf:
 milLog=/tmp/pythentic.rlog
 milType=Receiver
 milDB=/pathto/pythentic/pbops/pmarc.db
 milSCM=/pathto/pythentic/pbops/pmarc_schema.sql
 smtpHost=had5
 smtpPort=9999

Pythentic modules and imports:
==============================

pythentic.py:	milter server
dmarcmilter.py:	milter instance
hadspf.py:	spf module
dinsget.py:	dns lookup module
ipcalc.py:	IP addrss range calculator
six.py:		IPv6 address range calculator
haddkim.py:	dkim module
haddmarc.py:	dmarc module
squall.py:	SQLite database write module
commons.py:	some common methods



The Test Responder: dmarcreporter.py
===================================

The dmarcreporter operates as a cron job. It wakes up every 120 seconds,
and processes all new entries in the SQLite database written by the milter
for email messages sent to pythentic@had-pilto.biz.  Messages evaluated by
dmarc as Deliver receive a reply with spf, dkim and /or dmarc analysis.
Messages marked Discard are not replied to.  Messages marked Reject are
analysed and replied if they contain a legitimate test subject, and are
ignored otherwise.

There is a set of "bad dkim" tests that cause the responder to initiate 
a message with a defective dkim signature.  Defects include: bad header
field, incorrect body hash, bad signature folding options.  These are for
the client to exercise dkim signature processing.  There is also an spf
spoof test that is not yet operational.  It requires deployment of a 3rd 
party spoofing agent.

The Test Responder cronjob:
==========================

Location: ./pythentic/pbops/dmarcreporter.py

Invocation: nohup python dmarcreporter.py skim.conf &

Config:
=======

 mildb=/pathto/pythentic/pbops/pmarc.db
 milscm=/pathto/pythentic/pbopspmarc_schema.sql
 register=/pathto/pythentic/pbops/registered.txt
 drex=/pathto/pythentic/pbops/dkimrecords.txt
 privkey=/pathto/pythentic/pbops/.domainkeys/rsa.private
 mailto=night@nist.gov
 gudmuttrc=/pathto/pythentic/pbops/cnf/gudmuttrc
 badmuttrc=/pathto/pythentic/pbops/conf/badmuttrc
 tempfile=/tmp/skimfile

dmarcreporter.py modules and imports:
====================================

dmarcreporter.py:	cronjob test responder
commons.py:		file IO and search methods
hasher.py:		hash the address
squall.py:		SQLite database access
hadspf.py:		replay spf checks
dinsget.py:		dns lookup
ipcalc.py:		Ip addrss rane matches
six.py:			IPv6 address matcher
haddkim.py:		replay dkim checks
dnsmail.py:		analysis and reporting of spf, dkim, dmarc
haddmarc.py:		replay dmarc checks


The Mailchecker: dnsmail.py
===========================

All mail received by pythentic can be viewed at the owner's account using
mutt.  A separate mailchecker has also been developed and is invoked by:
$ python dnsmail.py mail skim.conf
This allows various views of messages and tests processed.  Messages in the 
mailbox can be listed, printed, checked for spf, dkim and dmarc
authentication.  Messages in the 'sent' box can be listed and printed -
useful for reviewing test replies sent by dmarcreporter.
Messages in the SQLite database can be listed and printed.  This will
include Discards and Rejects, not present in the mailbox.

dnsmail.py: local mail viewer and test replay:
=============================================

Location: /pathto/pythentic/pbops/dnsmail.py

Invocation: $ python dnsmail.py mail skim.conf

Config: skim.conf  <see above>

dnsmail.py modules and imports:
==============================

squall.py:	SQLite database access
dinsget.py:	dns lookup
hadspf.py:	SPF checks
ipcalc.py:	IP address range match
six.py:		IPv6 address range match
haddkim.py:	DKIM checks
haddmarc.py:	DMARC checks

