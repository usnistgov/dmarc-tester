# $Id: ppymilterbase.py 33 2009-04-08 20:40:02Z codewhale $
# ==============================================================================
# Copyright 2008 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ==============================================================================
#
# Pure python milter interface (does not use libmilter.a).
# Handles parsing of milter protocol data (e.g. over a network socket)
# and provides standard arguments to the callbacks in your handler class.
#
# For details of the milter protocol see:
#  http://search.cpan.org/src/AVAR/Sendmail-PMilter-0.96/doc/milter-protocol.txt
#

__author__ = 'Eric DeFriez'

'''
Stephen Nightingale, NIST
Extended July 9, 2012 to implement DMARC policy, bringing SPF and DKIM
under this same umbrella.
Changes to:
OnMacro
OnHeader
OnEndBody (add assemble_message)
MilterReceiver
MilterSender
'''

import binascii, logging, os, socket, struct, sys, types, dkim, time
import hadspf, haddkim #JSN 03/15/16 verbose versions
import commons as com
import haddmarc, socket
import dinsget    #to substitute for 'get_txt' in dkim call
import squall     #alternative db write.

MILTER_VERSION = 2 # Milter version we claim to speak (from pmilter)

# Potential milter command codes and their corresponding PpyMilter callbacks.
# From sendmail's include/libmilter/mfdef.h
SMFIC_ABORT   = 'A' # "Abort"
SMFIC_BODY    = 'B' # "Body chunk"
SMFIC_CONNECT = 'C' # "Connection information"
SMFIC_MACRO   = 'D' # "Define macro"
SMFIC_BODYEOB = 'E' # "final body chunk (End)"
SMFIC_HELO    = 'H' # "HELO/EHLO"
SMFIC_HEADER  = 'L' # "Header"
SMFIC_MAIL    = 'M' # "MAIL from"
SMFIC_EOH     = 'N' # "EOH"
SMFIC_OPTNEG  = 'O' # "Option negotation"
SMFIC_RCPT    = 'R' # "RCPT to"
SMFIC_QUIT    = 'Q' # "QUIT"
SMFIC_DATA    = 'T' # "DATA"
SMFIC_UNKNOWN = 'U' # "Any unknown command"

COMMANDS = {
  SMFIC_ABORT: 'Abort',
  SMFIC_BODY: 'Body',
  SMFIC_CONNECT: 'Connect',
  SMFIC_MACRO: 'Macro',
  SMFIC_BODYEOB: 'EndBody',
  SMFIC_HELO: 'Helo',
  SMFIC_HEADER: 'Header',
  SMFIC_MAIL: 'MailFrom',
  SMFIC_EOH: 'EndHeaders',
  SMFIC_OPTNEG: 'OptNeg',
  SMFIC_RCPT: 'RcptTo',
  SMFIC_QUIT: 'Quit',
  SMFIC_DATA: 'Data',
  SMFIC_UNKNOWN: 'Unknown',
  }

# To register/mask callbacks during milter protocol negotiation with sendmail.
# From sendmail's include/libmilter/mfdef.h
NO_CALLBACKS = 127  # (all seven callback flags set: 1111111)
CALLBACKS = {
  'OnConnect':    1,  # 0x01 SMFIP_NOCONNECT # Skip SMFIC_CONNECT
  'OnHelo':       2,  # 0x02 SMFIP_NOHELO    # Skip SMFIC_HELO
  'OnMailFrom':   4,  # 0x04 SMFIP_NOMAIL    # Skip SMFIC_MAIL
  'OnRcptTo':     8,  # 0x08 SMFIP_NORCPT    # Skip SMFIC_RCPT
  'OnBody':       16, # 0x10 SMFIP_NOBODY    # Skip SMFIC_BODY
  'OnHeader':     32, # 0x20 SMFIP_NOHDRS    # Skip SMFIC_HEADER
  'OnEndHeaders': 64, # 0x40 SMFIP_NOEOH     # Skip SMFIC_EOH
  }

# Acceptable response commands/codes to return to sendmail (with accompanying
# command data).  From sendmail's include/libmilter/mfdef.h
RESPONSE = {
    'ADDRCPT'    : '+', # SMFIR_ADDRCPT    # "add recipient"
    'DELRCPT'    : '-', # SMFIR_DELRCPT    # "remove recipient"
    'ACCEPT'     : 'a', # SMFIR_ACCEPT     # "accept"
    'REPLBODY'   : 'b', # SMFIR_REPLBODY   # "replace body (chunk)"
    'CONTINUE'   : 'c', # SMFIR_CONTINUE   # "continue"
    'DISCARD'    : 'd', # SMFIR_DISCARD    # "discard"
    'CONNFAIL'   : 'f', # SMFIR_CONN_FAIL  # "cause a connection failure"
    'ADDHEADER'  : 'h', # SMFIR_ADDHEADER  # "add header"
    'INSHEADER'  : 'i', # SMFIR_INSHEADER  # "insert header"
    'CHGHEADER'  : 'm', # SMFIR_CHGHEADER  # "change header"
    'PROGRESS'   : 'p', # SMFIR_PROGRESS   # "progress"
    'QUARANTINE' : 'q', # SMFIR_QUARANTINE # "quarantine"
    'REJECT'     : 'r', # SMFIR_REJECT     # "reject"
    'SETSENDER'  : 's', # v3 only?
    'TEMPFAIL'   : 't', # SMFIR_TEMPFAIL   # "tempfail"
    'REPLYCODE'  : 'y', # SMFIR_REPLYCODE  # "reply code etc"
    }



def printchar(char):
  """Useful debugging function for milter developers."""
  print ('char: %s [qp=%s][hex=%s][base64=%s]' %
         (char, binascii.b2a_qp(char), binascii.b2a_hex(char),
          binascii.b2a_base64(char)))
#end def printchar(char).

def CanonicalizeAddress(addr):
  """Strip angle brackes from email address iff not an empty address ("<>").

  Args:
    addr: the email address to canonicalize (strip angle brackets from).

  Returns:
    The addr with leading and trailing angle brackets removed unless
    the address is "<>" (in which case the string is returned unchanged).
  """
  if addr == '<>': return addr
  return addr.lstrip('<').rstrip('>')
#end def CanonicalizeAddress(addr).

class PpyMilterException(Exception):
  """Parent of all other PpyMilter exceptions.  Subclass this: do not
  construct or catch explicitly!"""


class PpyMilterPermFailure(PpyMilterException):
  """Milter exception that indicates a perment failure."""


class PpyMilterTempFailure(PpyMilterException):
  """Milter exception that indicates a temporary/transient failure."""


class PpyMilterCloseConnection(PpyMilterException):
  """Exception that indicates the server should close the milter connection."""

class PpyMilterActionError(PpyMilterException):
  """Exception raised when an action is performed that was not negotiated."""


class PpyMilterDispatcher(object):
  """Dispatcher class for a milter server.  This class accepts entire
  milter commands as a string (command character + binary data), parses
  the command and binary data appropriately and invokes the appropriate
  callback function in a milter_class instance.  One PpyMilterDispatcher
  per socket connection.  One milter_class instance per PpyMilterDispatcher
  (per socket connection)."""

  def __init__(self, milter_class, tp):
    """Construct a PpyMilterDispatcher and create a private
    milter_class instance.

    Args:
      milter_class: A class (not an instance) that handles callbacks for
                    milter commands (e.g. a child of the PpyMilter class).

    June 11, 2012, Stephen Nightingale, NIST.
    Added argument 'miltin' to differentitate mail Sender and Receiver 
    processing.
    """
    self.__milter = milter_class()
    self.__milter.setMilType(tp)

  #end def __init__(self, milter_class, miltin).

  def Dispatch(self, data):
    """Callback function for the milter socket server to handle a single
    milter command.  Parses the milter command data, invokes the milter
    handler, and formats a suitable response for the server to send
    on the socket.

    Args:
      data: A (binary) string (consisting of a command code character
            followed by binary data for that command code).

    Returns:
      A binary string to write on the socket and return to sendmail.  The
      string typically consists of a RESPONSE[] command character then
      some response-specific protocol data.

    Raises:
      PpyMilterCloseConnection: Indicating the (milter) connection should
                                be closed.
    """
    (cmd, data) = (data[0], data[1:])
    try:
      if cmd not in COMMANDS:
        logging.warn('Unknown command code: "%s" ("%s")', cmd, data)
        return RESPONSE['CONTINUE']
      command = COMMANDS[cmd]
      parser_callback_name = '_Parse%s' % command
      handler_callback_name = 'On%s' % command
      if not hasattr(self, parser_callback_name):
        logging.error('No parser implemented for "%s"', command)
        return RESPONSE['CONTINUE']

      if not hasattr(self.__milter, handler_callback_name):
        logging.warn('Unimplemented command: "%s" ("%s")', command, data)
        return RESPONSE['CONTINUE']

      parser = getattr(self, parser_callback_name)
      callback = getattr(self.__milter, handler_callback_name)
      args = parser(cmd, data)
      return callback(*args)
    except PpyMilterTempFailure, e:
      logging.info('Temp Failure: %s', str(e))
      return RESPONSE['TEMPFAIL']
    except PpyMilterPermFailure, e:
      logging.info('Perm Failure: %s', str(e))
      return RESPONSE['REJECT']
    return RESPONSE['CONTINUE']

  #end def Dispatch(self, data).


  def _ParseOptNeg(self, cmd, data):
    """Parse the 'OptNeg' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple consisting of:
        cmd: The single character command code representing this command.
        ver: The protocol version we support.
        actions: Bitmask of the milter actions we may perform
                 (see "PpyMilter.ACTION_*").
        protocol: Bitmask of the callback functions we are registering.

    """
    (ver, actions, protocol) = struct.unpack('!III', data)
    ##print "ParseOptNeg: ver=%0x, act=%0x, prot=%0x" % (ver, actions, protocol)
    #logging.debug(' x>>> act=[%s] prot=[%s]', actions, protocol)
    return (cmd, ver, actions, protocol)

  #end   def _ParseOptNeg(self, cmd, data).


  def _ParseMacro(self, cmd, data):
    """Parse the 'Macro' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple consisting of:
        cmd: The single character command code representing this command.
        macro: The single character command code this macro is for.
        data: A list of strings alternating between name, value of macro.
    """
    (macro, data) = (data[0], data[1:])
    return (cmd, macro, data.split('\0'))

  #end def _ParseMacro(self, cmd, data).


  def _ParseConnect(self, cmd, data):
    """Parse the 'Connect' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple (cmd, hostname, family, port, address) where:
        cmd: The single character command code representing this command.
        hostname: The hostname that originated the connection to the MTA.
        family: Address family for connection (see sendmail libmilter/mfdef.h).
        port: The network port if appropriate for the connection.
        address: Remote address of the connection (e.g. IP address).
    """
    (hostname, data) = data.split('\0', 1)
    family = struct.unpack('c', data[0])[0]
    port = struct.unpack('!H', data[1:3])[0]
    address = data[3:]
    return (cmd, hostname, family, port, address)

  #end def _ParseConnect(self, cmd, data).


  def _ParseHelo(self, cmd, data):
    """Parse the 'Helo' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple (cmd, data) where:
        cmd: The single character command code representing this command.
        data: TODO: parse this better
    """
    return (cmd, data)

  #end def _ParseHelo(self, cmd, data).


  def _ParseMailFrom(self, cmd, data):
    """Parse the 'MailFrom' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple (cmd, mailfrom, esmtp_info) where:
        cmd: The single character command code representing this command.
        mailfrom: The canonicalized MAIL From email address.
        esmtp_info: Extended SMTP (esmtp) info as a list of strings.
    """
    (mailfrom, esmtp_info) = data.split('\0', 1)
    return (cmd, CanonicalizeAddress(mailfrom), esmtp_info.split('\0'))

  #end def _ParseMailFrom(self, cmd, data).


  def _ParseRcptTo(self, cmd, data):
    """Parse the 'RcptTo' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple (cmd, rcptto, emstp_info) where:
        cmd: The single character command code representing this command.
        rcptto: The canonicalized RCPT To email address.
        esmtp_info: Extended SMTP (esmtp) info as a list of strings.
    """
    (rcptto, esmtp_info) = data.split('\0', 1)
    return (cmd, CanonicalizeAddress(rcptto), esmtp_info.split('\0'))

  #end def _ParseRcptTo(self, cmd, data).


  def _ParseHeader(self, cmd, data):
    """Parse the 'Header' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple (cmd, key, val) where:
        cmd: The single character command code representing this command.
        key: The name of the header.
        val: The value/data for the header.
    """

    return (cmd, data)

  #end def _ParseHeader(self, cmd, data).


  def _ParseEndHeaders(self, cmd, data):
    """Parse the 'EndHeaders' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple (cmd) where:
        cmd: The single character command code representing this command.
    """

    return (cmd)

  #end def _ParseEndHeaders(self, cmd, data).


  def _ParseBody(self, cmd, data):
    """Parse the 'Body' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple (cmd, data) where:
        cmd : The single character command code representing this command.
        data: TODO: parse this better
    """

    return (cmd, data)

  #end def _ParseBody(self, cmd, data).


  def _ParseEndBody(self, cmd, data):
    """Parse the 'EndBody' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: No data is sent for this command.

    Returns:
      A tuple (cmd) where:
        cmd: The single character command code representing this command.
    """

    return (cmd)

  #end def _ParseEndBody(self, cmd, data).


  def _ParseQuit(self, cmd, data):
    """Parse the 'Quit' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple (cmd) where:
        cmd: The single character command code representing this command.
    """

    return (cmd)

  #end def _ParseQuit(self, cmd, data).


  def _ParseAbort(self, cmd, data):
    """Parse the 'Abort' milter data into arguments for the milter handler.

    Args:
      cmd: A single character command code representing this command.
      data: Command-specific milter data to be unpacked/parsed.

    Returns:
      A tuple (cmd) where:
        cmd: The single character command code representing this command.
    """

    return (cmd)

  #end def _ParseAbort(self, cmd, data).

#end class PpyMilterDispatcher(object).

class KimpfMilter(object):
  """Pure python milter handler base class.  Inherit from this class
  and override any On*() commands you would like your milter to handle.
  Register any actions your milter may perform using the Can*() functions
  during your __init__() (after calling PpyMilter.__init()__!) to ensure
  your milter's actions are accepted.

  Pass a reference to your handler class to a python milter socket server
  (e.g. AsyncPpyMilterServer) to create a stand-alone milter
  process than invokes your custom handler.

  June 11, 2012: Stephen Nightingale, NIST.
  KimpfMilter is the extension of PpyMilter, to include header and
  body processing, for DKIM.
  """

  # Actions we tell sendmail we may perform
  # PpyMilter users invoke self.CanFoo() during their __init__()
  # to toggle these settings.
  ACTION_ADDHDRS    = 1  # 0x01 SMFIF_ADDHDRS    # Add headers
  ACTION_CHGBODY    = 2  # 0x02 SMFIF_CHGBODY    # Change body chunks
  ACTION_ADDRCPT    = 4  # 0x04 SMFIF_ADDRCPT    # Add recipients
  ACTION_DELRCPT    = 8  # 0x08 SMFIF_DELRCPT    # Remove recipients
  ACTION_CHGHDRS    = 16 # 0x10 SMFIF_CHGHDRS    # Change or delete headers
  ACTION_QUARANTINE = 32 # 0x20 SMFIF_QUARANTINE # Quarantine message

  def __init__(self):
    """Construct a PpyMilter object.  Sets callbacks and registers
    callbacks.  Make sure you call this directly "PpyMilter.__init__(self)"
    at the beginning of your __init__() if you override the class constructor!
    June 11, 2012, Stephen Nightingale, NIST.
    Always set ParseBody and ParseHeader callbacks.
    """
    self.__actions = 0
    self.CanAddHeaders()
    self.__mutations = []
    self.heds = ""
    self.bods = ""
    self.message = ""
    self.subj = ""
    self.modsig = ""
    self.miltype = 'Receiver'
    self.RFC5321MailFrom = ""
    self.RFC5322From = ""
    self.dvalue = ""
    self.svalue = ""
    self.recvd = 0
    self.retn = 0
    self.spfrecord = False
    self.dkimrecord = False  #Assume false till we delve into dkim.py
    nb = com.Housekeeping("Feedback-Type=aggregate")
    nb.another("User-Agent=pythentic")
    nb.another("Version = 1.0")
    self.__mail_addr = ""   #To save the SPF address
    self.__mail_add = ""   #To save the incoming mail address
    self.__mail_to = ""   #To save the to address
    self.spfresult = ""    #Save in complete_dns for return in OnEndBody
    self.spfreason = ""
    self.dkimreason = ""
    self.dmarcreason = ""
    self.__protocol = 79 #ParseBody and ParseHeader callbacks.

  #end def __init__(self).


  def Accept(self):
    """Create an 'ACCEPT' response to return to the milter dispatcher."""
    return RESPONSE['ACCEPT']

  def Reject(self):
    """Create a 'REJECT' response to return to the milter dispatcher."""
    return RESPONSE['REJECT']

  def Discard(self):
    """Create a 'DISCARD' response to return to the milter dispatcher."""
    return RESPONSE['DISCARD']

  def TempFail(self):
    """Create a 'TEMPFAIL' response to return to the milter dispatcher."""
    return RESPONSE['TEMPFAIL']

  def Continue(self):
    """Create an '' response to return to the milter dispatcher."""
    return RESPONSE['CONTINUE']

  def CustomReply(self, code, text):
    """Create a 'REPLYCODE' (custom) response to return to the milter
    dispatcher.

    Args:
      code: Integer or digit string (should be \d\d\d).  NOTICE: A '421' reply
            code will cause sendmail to close the connection after responding!
            (https://www.sendmail.org/releases/8.13.0.html)
      text: Code reason/explaination to send to the user.
    """
    return '%s%s %s\0' % (RESPONSE['REPLYCODE'], code, text)

  #end def CustomReply(self, code, text).


  def AddRecipient(self, rcpt):
    """Construct an ADDRCPT reply that the client can send during OnEndBody.

    Args:
      rcpt: The recipient to add, should have <> around it.
    """
    self.__VerifyCapability(self.ACTION_ADDRCPT)
    return '%s%s\0' % (RESPONSE['ADDRCPT'], rcpt)

  #end def AddRecipient(self, rcpt).


  def AddHeader(self, name, value):
    """Construct an ADDHEADER reply that the client can send during OnEndBody.

    Args:
      name: The name of the header to add
      value: The value of the header
    """
    self.__VerifyCapability(self.ACTION_ADDHDRS)
    return '%s%s\0%s\0' % (RESPONSE['ADDHEADER'], name, value)

  #end def AddHeader(self, name, value).


  def DeleteRecipient(self, rcpt):
    """Construct an DELRCPT reply that the client can send during OnEndBody.

    Args:
      rcpt: The recipient to delete, should have <> around it.
    """
    self.__VerifyCapability(self.ACTION_DELRCPT)
    return '%s%s\0' % (RESPONSE['DELRCPT'], rcpt)

  #end def DeleteRecipient(self, rcpt).


  def InsertHeader(self, index, name, value):
    """Construct an INSHEADER reply that the client can send during OnEndBody.

    Args:
      index: The index to insert the header at. 0 is above all headers.
             A number greater than the number of headers just appends.
      name: The name of the header to insert.
      value: The value to insert.
    """
    self.__VerifyCapability(self.ACTION_ADDHDRS)
    index = struct.pack('!I', index)
    retval = '%s%s%s\0%s\0' % (RESPONSE['INSHEADER'], index, name, value)
    #print "InsertHeader:", retval
    return retval

  #end def InsertHeader(self, index, name, value).


  def ChangeHeader(self, index, name, value):
    """Construct a CHGHEADER reply that the client can send during OnEndBody.

    Args:
      index: The index of the header to change, offset from 1.
             The offset is per-occurance of this header, not of all headers.
             A value of '' (empty string) will cause the header to be deleted.
      name: The name of the header to insert.
      value: The value to insert.
    """
    self.__VerifyCapability(self.ACTION_CHGHDRS)
    index = struct.pack('!I', index)
    return '%s%s%s\0%s\0' % (RESPONSE['CHGHEADER'], index, name, value)

  #end def ChangeHeader(self, index, name, value).


  def ReturnOnEndBodyActions(self, actions):
    """Construct an OnEndBody response that can consist of multiple actions
    followed by a final required Continue().

    All message mutations (all adds/changes/deletes to envelope/header/body)
    must be sent as response to the OnEndBody callback.  Multiple actions
    are allowed.  This function formats those multiple actions into one
    response to return back to the PpyMilterDispatcher.

    For example to make sure all recipients are in 'To' headers:
    +---------------------------------------------------------------------
    | class NoBccMilter(PpyMilterBase):
    |  def __init__(self):
    |    self.__mutations = []
    |    ...
    |  def OnRcptTo(self, cmd, rcpt_to, esmtp_info):
    |    self.__mutations.append(self.AddHeader('To', rcpt_to))
    |    return self.Continue()
    |  def OnEndBody(self, cmd):
    |    tmp = self.__mutations
    |    self.__mutations = []
    |    return self.ReturnOnEndBodyActions(tmp)
    |  def OnResetState(self):
    |    self.__mutations = []
    +---------------------------------------------------------------------

    Args:
      actions: List of "actions" to perform on the message.
               For example:
                 actions=[AddHeader('Cc', 'lurker@example.com'),
                          AddRecipient('lurker@example.com')]
    """
    return actions[:] + [self.Continue()]

  #end def ReturnOnEndBodyActions(self, actions).


  def __ResetState(self):
    """Clear out any per-message data.

    Milter connections correspond to SMTP connections, and many messages may be
    sent in the same SMTP conversation. Any data stored that pertains to the
    message that was just handled should be cleared so that it doesn't affect
    processing of the next message. This method also implements an
    'OnResetState' callback that milters can use to catch this situation too.
    """
    try:
      self.OnResetState()
    except AttributeError:
      logging.warn('No OnResetState() callback is defined for this milter.')

  #end def __ResetState(self).


  # you probably should not be overriding this  :-p
  def OnOptNeg(self, cmd, ver, actions, protocol):
    """Callback for the 'OptNeg' (option negotiation) milter command.
    Shouldn't be necessary to override (don't do it unless you
    know what you're doing).

    Option negotation is based on:
    (1) Command callback functions defined by your handler class.
    (2) Stated actions your milter may perform by invoking the
        "self.CanFoo()" functions during your milter's __init__().
    """

    out = struct.pack('!III', MILTER_VERSION,
                      self.__actions & actions,
                      self.__protocol & protocol)
    ##print "OnOptNeg: sact=%0x, act=%0x, sprot=%0x, prot=%0x" % (self.__actions, actions, self.__protocol, protocol)
    return cmd+out

  #end def OnOptNeg(self, cmd, ver, actions, protocol).


  def OnMacro(self, cmd, macro_cmd, data):
    """Callback for the 'Macro' milter command: no response required.

    June 12, 2012, Stephen Nightingale, NIST.
    Receivers only: Actual SPF processing happens here. 
    Result goes in OnEndBody.
    """

    if macro_cmd == "C":
      self.setup_spf_call(data)

    if self.miltype == "Receiver":
      if macro_cmd == "M":
        self.complete_spf(data)
    return None

  #end def OnMacro(self, cmd, macro_cmd, data).


  def OnQuit(self, cmd):
    """Callback for the 'Quit' milter command: close the milter connection.

    The only logical response is to ultimately raise a
    PpyMilterCloseConnection() exception.
    """
    raise PpyMilterCloseConnection('close milter connection.')

  #end def OnQuit(self, cmd).


  def OnAbort(self, cmd):
    """Callback for the 'Abort' milter command.

    This callback is required because per-message data must be cleared when an
    Abort command is received. Otherwise any message modifications will end up
    being applied to the next message that is sent down the same SMTP
    connection.

    Args:
      cmd: Unused argument.

    Returns:
      A Continue response so that further messages in this SMTP conversation
      will be processed.
    """

    self.__ResetState()
    return self.Continue()

  #end def OnAbort(self, cmd).


  #June 11, 2012: Stephen Nightingale, NIST
  #added OnBody for DKIM processing.
  #Feb 20, 2013 JSN: Set body as CRLF if null.
  def OnBody(self, cmd, data):
    logging.debug("Body Data: '%s'" % (data))
    if self.bods == "":
      self.bods = data
    else:
      self.bods = self.bods + data

    '''
    if self.bods == "":
      if data == "":
        self.bods = "\r\n"
      else:
        self.bods = data
    else:
      self.bods = self.bods + "\r\n" + data
    '''
    return self.Continue()

  #end def OnBody(self, cmd, data).


  #June 11, 2012: Stephen Nightingale, NIST
  #added OnHeader for DKIM processing: 
  #Receiver needs to check sig. Sender needs to accumulate headers to sign it.
  #June 25, 2012: SN NIST.
  #Patch newlines back into DKIM Signature to rectify the 
  #error in sendmail transmission.
  #July 9, 2012, SN.
  #Extract RFC5322From address and save.
  #Feb 20, 2013 JSN: Get rid of spurious terminating CRs in the signature.
  

  def OnHeader(self, cmd, data):

    tmp = ""
    nb = com.Housekeeping("new=new")
    strungs = data.split("\0")
    oncmd = strungs[0]
    onvalue = strungs[1].rstrip()

    if oncmd.lower() == "dkim-signature":
      (self.dvalue, self.ivalue, self.svalue) = self.extractdvalue(onvalue)
      #Receiver: Monitor folding white space in dkim signature."
      onvalue = onvalue.replace("\r ", "\r\n")
      self.modsig = onvalue
    elif oncmd.lower() == "from":
      try: self.RFC5322From = onvalue.split("@")[1][:-1]
      except: self.RFC5322From = ""
    elif oncmd.lower() == "to":
      nb = com.Housekeeping("Original-Rcpt-To=%s" % (onvalue))
      now = time.ctime()
      nb.another("Arrival-Date=%s" % (now))
    elif oncmd.lower() == "subject":
      self.subj = onvalue
    elif oncmd.lower() == "received":
      logging.debug("%s: InOnHeader: Received headers:\n%s:%s" % (com.prunetime(time.ctime()), strungs[0], strungs[1]))
      self.recvd += 1
    elif oncmd.lower() == "return-path":
      self.retn += 1

    tmp = "%s: %s\r\n" % (oncmd, onvalue)

    self.heds = self.heds + tmp
    return self.Continue()

  #end def OnHeader(self, cmd, data).


  def OnEndBody(self, cmd):

    """Callback for the 'EndBody' milter command.

    If your milter wants to do any message mutations (add/change/delete any
    envelope/header/body information) it needs to happen as a response to
    this callback (so need to override this function and cause those
    actions by returning using ReturnOnEndBodyActions() above).

    Args:
      cmd: Unused argument.

    Returns:
      A continue response so that further messages in this SMTP conversation
      will be processed.

    June 12, 2012, Stephen Nightingale, NIST:
    Do SPF and DKIM processing here.
    -  SPF checking for Receivers
    - if spf is good:
      - DKIM signature checking for Receivers.
    - DKIM signature generation for Senders

    July 9, 2012, Sn, NIST:
    Reorganized to separate out Sender actions and Receiver actions.

    August 13, 2014, Sn, NIST:
    Added PGPeer as a new milter type.
    """


    if self.RFC5321MailFrom.find("localhost") >= 0 or self.RFC5321MailFrom == socket.gethostname() or self.RFC5321MailFrom == "":
      logging.debug("%s: OnEndBody: SenderAddress: %s, LocalAddress: %s" % (self.miltype, self.RFC5321MailFrom, socket.gethostname()))

    if self.miltype == "Sender": 
      if self.__mail_add == "127.0.0.1":
        return self.MilterSender()
      else:
        return self.Continue()

    elif self.miltype == "Receiver":
      if self.__mail_add == "127.0.0.1":
        return self.Continue()
      else:
        return self.MilterReceiver()
     
    elif self.miltype == "PGPeer": 
      return self.MilterPGP()
    else: 
      return self.Continue()


  #end def OnEndBody(self, cmd).


  # Call these from __init__() (after calling PpyMilter.__init__()  :-p
  # to tell sendmail you may perform these actions
  # (otherwise performing the actions may fail).
  def CanAddHeaders(self):
    """Register that our milter may perform the action 'ADDHDRS'."""
    self.__actions |= self.ACTION_ADDHDRS

  def CanChangeBody(self):
    """Register that our milter may perform the action 'CHGBODY'."""
    self.__actions |= self.ACTION_CHGBODY

  def CanAddRecipient(self):
    """Register that our milter may perform the action 'ADDRCPT'."""
    self.__actions |= self.ACTION_ADDRCPT

  def CanDeleteRecipient(self):
    """Register that our milter may perform the action 'DELRCPT'."""
    self.__actions |= self.ACTION_DELRCPT

  def CanChangeHeaders(self):
    """Register that our milter may perform the action 'CHGHDRS'."""
    self.__actions |= self.ACTION_CHGHDRS

  def CanQuarantine(self):
    """Register that our milter may perform the action 'QUARANTINE'."""
    self.__actions |= self.ACTION_QUARANTINE

  def __VerifyCapability(self, action):
    if not (self.__actions & action):
      logging.error('Error: Attempted to perform an action that was not' +
                     'requested.')
      raise PpyMilterActionError('Action not requested in __init__')

####################################################################
#Stephen Nightingale, NIST July 2012.
#My additions:

  def newdbwrite(self, indict):
    outdict = {}
    #newdb, newscm OBE, as tp[milDB] and tp[milSCM] point to new DB and Schema:
    #newdb = "/home/night/python/pythentic/pbops/pmarc.db"
    #newscm = "/home/night/python/pythentic/pbops/pmarc_schema.sql"
    outdict['Version'] = indict['Version']
    outdict['UserAgent'] = indict['UserAgent']
    outdict['Reported'] = indict['Reported']
    outdict['ArrivalDate'] = indict['ArrivalDate']
    outdict['OriginalMailFrom'] = indict['OriginalMailFrom']
    outdict['OriginalRcptTo'] = indict['OriginalRcptTo']
    outdict['SourceIP'] = indict['SourceIP']
    outdict['DKIMSignature'] = indict['DKIMSignature']
    outdict['Subject'] = indict['Subject']
    outdict['Body'] = indict['Body']   #JSN 03/17/16 Body is now full message
    outdict['SPFrecord'] = indict['SPFrecord']
    outdict['DKIMrecord'] = indict['DKIMrecord']
    outdict['DMARCrecord'] = indict['DMARCrecord']
    outdict['SPFresult'] = indict['AuthFailspf']
    outdict['DKIMresult'] = indict['AuthFaildkim']
    outdict['Alignresult'] = indict['AuthFailalign']
    outdict['Deliveryresult'] = indict['DeliveryResult']
    outdict['SPFreason'] = indict['SPFReason']
    outdict['DKIMreason'] = indict['DKIMReason']
    outdict['DMARCreason'] = indict['DMARCReason']

    #Apply a correction due to spf records with '+all' as the last mechanism.
    #These are spam vectors, and should cause the message to be discarded,
    #and the test responder should not reply.
    #If there is no SPF record just let it go:
    try:
      if outdict['SPFrecord'].endswith('+all'):
        outdict['SPFresult'] = 'fail'
        outdict['Deliveryresult'] = 'Discard'
        outdict['SPFreason'] = "+all mechanism is a spam vector"
        outdict['DMARCreason'] = "DMARC fails since both SPF and DKIM fail"
    except: pass

    #newdb, newscm OBE, as tp[milDB] and tp[milSCM] point to new DB and Schema:
    #squall.putresult(newdb, newscm, outdict)
    squall.putresult(self.mildb, self.milscm, outdict)

  def setMilType(self, tp):

    ''' Set milter type as (mail) Sender or Receiver. 
        Senders add Dkim signatures. Receivers do SPF processing and
        verify Dkim signatures. Only AddHeaders for Senders. 
        Mar 28, 2013, JSN: Allow Receivers to AddHeaders. '''
    self.miltype = tp.tup['milType']
    if self.miltype == "Sender":
      self.keyfile = tp.tup['keyFile']
      self.select = tp.tup['selector']
      self.weare = tp.tup['whoWeAre']
    elif self.miltype == "Receiver":
      self.mildb = tp.tup['milDB']
      self.milscm = tp.tup['milSCM']

  #end def setMilType(self, newtype).


  #Feb 25, 2013 JSN:
  #From '_' arg pick up IP add directly from within [brackets]
  #instead of separating out any prior From address.
  def setup_spf_call(self, args):

    ''' Separate out the args on connect and save them for DNS lookup. '''

    tup = {}; MailFrom = ""; MailName = ""; MailAdd = ""; MailTo = ""

    for i in range(len(args)):
      try:
        if args[i] == "j": MailTo = args[i+1]
        elif args[i] == "_":
          mfadd = args[i+1]
          mfx = mfadd.find("[")
          MailAdd = mfadd[mfx+1:-1]
      except IndexError: pass

    self.__mail_add = MailAdd
    self.__mail_to = MailTo

  #end def setup_spf_call(self, args).


  def complete_spf(self, args):

    ''' Separate out the args on the mail milter cmd and do the DNS lookup.
        Save the result in class variable, self.spfresult. 
        SN, July 9, 2012, save mail_host as RFC5321MailFrom.
        SN 03/15/16, verbose spf.checkhost call. '''

    MailId = ""; MailMailer = ""

    for i in range(len(args)):
      try:
        if args[i] == "{mail_host}": 
          self.RFC5321MailFrom = args[i+1]
          #nb = com.Housekeeping("Original-Mail-From=%s" % (self.RFC5321MailFrom))
        if args[i] == "{mail_addr}": 
          self.__mail_addr = args[i+1]
      except IndexError: pass

    #Unclutter the ip address:
    ipad = self.__mail_add
    if ipad.find("forged") > 0:
      (ipso, ipsn) = ipad.split("]")
    else:
      ipso = ipad 
    logging.debug("spf args: %s, %s, %s" % (ipso, self.RFC5321MailFrom, self.__mail_addr))
    #(res, exp) = spf.check2(i=self.__mail_add, h=self.RFC5321MailFrom, s=self.__mail_addr)
    (res, exp, recks, interim) = hadspf.checkhost(ipso, self.__mail_addr, self.RFC5321MailFrom)
    logging.debug("dodns: checkhost result=%s, reason=%s, recks=%s" % (res, exp, recks))
    self.spfresult = res
    self.spfreason = exp
    self.spfrecord = recks

  #end def complete_spf(self, args).


  def extractdvalue(self, aheader):
    ''' Arg is DKIM-Signature header. Parse and extract the d=value. '''

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

  #end def extractdvalue(self, aheader).


  def assemble_message(self):
    msg = self.heds + "\r\n" + self.bods
    return msg

  #end def assemble_message(self).

#I fthe subject signifies a HAD test, set flags to allow manipulation
#of the message headers. Called from MilterSender().
#modsig values extended to (0, 1, 2, 3) to allow additional tests for
#No CR and for No LF.
  def testConfigs(self, subj):
    sub = subj.lower(); 
    #Default values for non-test subject:
    modfrom = False; dkimsig = True; modsig = 0; testnm = "";

    if sub.find("p.spf.good") > -1: dkimsig = False; modsig = 0; testnm = "p.spf.good"
    if sub.find("p.spf.spoof") > -1: dkimsig = False; modsig = 0; modfrom = True; testnm = "p.spf.spoof"
    if sub.find("p.dkim.good") > -1: dkimsig = True; modsig = 0; testnm = "p.dkim.good"
    if sub.find("p.dkim.bad") > -1: dkimsig = True; modsig = 1; testnm = "p.dkim.bad"
    if sub.find("p.dkim.bad") > -1: dkimsig = True; modsig = 1; testnm = "p.dkim.bad"
    if sub.find("p.dkim.nolf") > -1: dkimsig = True; modsig = 2; testnm = "p.dkim.nolf"
    if sub.find("p.dkim.nocr") > -1: dkimsig = True; modsig = 3; testnm = "p.dkim.nocr"
    if sub.find("p.dkim.bh") > -1: dkimsig = True; modsig = 4; testnm = "p.dkim.bh"
    if sub.find("p.dmarc.spf.good") > -1: dkimsig = False; modsig = 0; testnm = "p.dmarc.spf.good"
    if sub.find("p.dmarc.spf.spoof") > -1: dkimsig = False; modsig = 0; modfrom = True; testnm = "p.dmarc.spf.spoof"
    if sub.find("p.dmarc.dkim.good") > -1: dkimsig = True; modsig = 0; testnm = "p.dmarc.dkim.good"
    if sub.find("p.dmarc.dkim.bad") > -1: dkimsig = True; modsig = 1; testnm = "p.dmarc.dkim.bad"
    if sub.find("p.dmarc.align.good") > -1: dkimsig = True; modsig = 0; testnm = "p.dmarc.align.good"
    if sub.find("p.dmarc.align.bad") > -1: dkimsig = True; modsig = 0; testnm = "p.dmarc.align.bad"
    return (dkimsig, modsig, modfrom, testnm)


  #confuseHash: jumble up the body hash in the DKIM signature, to provide a body hash verification test:
  def confuseHash(self, kimsig):
    nudargs = []
    dargs = kimsig.split(';')
    for darg in dargs:
      if darg.find('bh=') > -1:
        logging.debug("Original Hash = %s" % (darg))
        (bh, bhash) = darg.split('=', 1)
        bhash = bhash[::-1]
        darg = "bh=%s" % (bhash)
        logging.debug("Bodged Hash = %s" % (darg))
        nudargs.append(darg)
      else:
        nudargs.append(darg)

    bodgedsig = ";".join([el for el in nudargs])
    return bodgedsig


  def MilterSender(self):

      #To be sure and idiot-proof: sign messages only if mail_add is 127.0.0.1:
      if self.__mail_add != "127.0.0.1":
        return self.Continue()

      self.message = self.assemble_message()
      (signit, modit, spoofit, testit) = self.testConfigs(self.subj)

      if signit: #Generate good or bad dkim signature:
        privkey = open(self.keyfile).read()
        d = dkim.DKIM(self.message)
        newsig = d.sign(self.select, self.weare, privkey)
        (label, fields) = newsig.split(":", 1)
        if modit == 1:
          fields = fields.replace("Date", "Late")
        elif modit == 2:
          fields = fields.replace("\r\n", "\r ")
        elif modit == 3:  #default is signature with \n\t line endings, which doesn't get jimmied by Sendmail.
          fields = fields.replace("\r\n", "\n\t")
        elif modit == 4:
          fields = self.confuseHash(fields)

        fields = fields.rstrip()  #No redundant newline needed at end of header.
        logging.debug("DKIM Signature created in MilterSender:\n'%s: %s'" % (label, fields))
        self.__mutations.append(self.InsertHeader(0, label, fields))

      else:
        logging.debug("DKIM Signature NOT created in MilterSender: %s\n" % (self.weare))

      if spoofit:  #spoofed in the address:
        logging.debug("Check for spoofed address in test %s" % (testit))

      if testit != "":  #Add header for modified test:
        label = "X-Authentication-Test"
        fields = testit + " (sent)"
        self.__mutations.append(self.AddHeader(label, fields))

      tmp = self.__mutations
      self.__mutations = []; self.heds = ""; self.bods = ""; self.message = ""
      logging.debug("%s: InMilterSender: message processed." % (com.prunetime(time.ctime())))
      #return self.Continue()
      return self.ReturnOnEndBodyActions(tmp)

  #end def MilterSender(self).




  #JSN 03/15/16 use verbose dkim.verify from haddkim:
  def MilterReceiver(self):
    resdict = {}; expl = ""; verbex = ""
    subjlist = ["spf", "dkim", "dmarc", "register", "feedback"]

    self.message = self.assemble_message() #redo below for headers to receiver.
    dm = haddmarc.Dmarc(self.dvalue, self.RFC5321MailFrom, self.RFC5322From, self.message)
    #d = dkim.DKIM(self.message)
    try: 
      #Substitute 'get_txt' with dinsget
      #self.dkimresult = d.verify(dnsfunc=dinsget.domain)
      ((self.dkimresult, self.dkimreason, self.dkpub, expl), self.dvalue) = haddkim.verify(self.message)
      self.dkimrecord = True
    except dkim.DKIMException as err: 
      self.dkimreason = err
      self.dkimresult = False
      logging.debug("dkim.DKIMException: %s" % (err))
    #self.dkimreason = self.dkimreason + "\n" + expl   #till we can put the expl or the full message in the DB.

    if not self.dkpub == None:
      klabel = "X-dkim"
      kfields = "d=%s, s=%s, DKIMReason=%s, DKIMrecord=%s" % (self.dvalue, self.svalue, self.dkimreason, self.dkpub) #to sendmail without newline.
      self.__mutations.append(self.AddHeader(klabel, kfields))
      xtmp = "%s: %s\r\n" % (klabel, kfields) #to DB with newline.
      self.heds = self.heds + xtmp

    #dmarcation options are "Reject" or "Pass"
    (dmarcation, self.dmarcreason, drek, verbex) = dm.ApplyPolicy(self.spfresult, self.dkimresult, self.spfrecord, self.dkimrecord, self.subj)
    thistime = time.time()
    resdict['ArrivalDate'] = thistime
    resdict['AuthFailspf'] = self.spfresult
    resdict['AuthFaildkim'] = self.dkimresult
    resdict['AuthFailalign'] = dmarcation
    resdict['DeliveryResult'] = dmarcation # 'Deliver' or 'Reject'
    resdict['FeedbackType'] = "RecordType"
    resdict['OriginalMailFrom'] = self.__mail_addr
    resdict['OriginalRcptTo'] = self.__mail_to
    resdict['SourceIP'] = self.__mail_add
    resdict['UserAgent'] = "Pythentic"
    resdict['Version'] = 1
    resdict['DKIMSignature'] = self.modsig
    resdict['Subject'] = self.subj  #for filtering spf,dkim,dmarc.
    resdict['Reported'] = 0 #Feedback only once for spf and dkim
    resdict['DKIMReason'] = self.dkimreason
    if self.spfreason == 0: self.spfreason = "None."
    if self.dmarcreason == 0: self.dmarcreason = "None."
    resdict['SPFReason'] = self.spfreason 
    resdict['DMARCReason'] = self.dmarcreason

    label = "X-spf"
    self.spfrec = dinsget.domain_spf(self.RFC5321MailFrom)
    fields = "i=%s, h=%s, s=%s, SPFResult=%s, SPFrecord=%s" % (self.__mail_add, self.RFC5321MailFrom, self.__mail_addr, self.spfresult, self.spfrec)
    self.__mutations.append(self.AddHeader(label, fields))
    xtmp = "%s: %s\r\n" % (label, fields) #to DB with newline.
    self.heds = self.heds + xtmp

    dlabel = "X-dmarc"
    dfields = "result=%s, DMARCAction=%s, DMARCrecord=%s" % (dmarcation, self.dmarcreason, drek)
    self.__mutations.append(self.AddHeader(dlabel, dfields))
    dtmp = "%s: %s\r\n" % (dlabel, dfields)
    self.heds = self.heds + dtmp

    self.message = self.assemble_message()

    #Do writes to squall db as well:
    #resdict['Body'] = self.bods  #Save the whole message in this field:
    resdict['Body'] = self.message
    resdict['SPFrecord'] = self.spfrec
    resdict['DKIMrecord'] = self.dkpub
    resdict['DMARCrecord'] = drek
    self.newdbwrite(resdict)

    #Old DB superseded by New DB:
    #nb = com.Housekeeping("new=new", self.mildb, self.milscm)
    resdict['Message'] = self.message
    #nb.record_messages(resdict)
    #nb.record_bodies(self.bods)
    #nb.put_addr(self.__mail_add, self.RFC5321MailFrom, last=thistime)
    logging.debug("%s: Receiver: DMARC Values written to %s." % (time.ctime(thistime), self.mildb))
    logging.debug("Receiver: Subject: %s, SourceIP: %s" % (self.subj, self.__mail_add))
    if dmarcation == "Reject":
      return self.Reject()
    elif dmarcation == "Discard":
      return self.Discard()

    #Add the spf/dkim/dmarc headers to display in the received message:
    tmp = self.__mutations; self.__mutations = []
    return self.ReturnOnEndBodyActions(tmp)

  #end def MilterReceiver(self).



  def MilterPGP(self):
    resdict = {}
    subjpgp = ["openpgp"]

    #only process the message if Subject contains openpgp
    if not withinlist(subjpgp, self.subj):
      return self.Continue()

    #no need to process outbound messages
    if self.__mail_add == "127.0.0.1":
      return self.Continue()

    thistime = time.time()
    #logging.debug("%s: MilterPGP: %s." % (time.ctime(thistime)), self.subj)
    logging.debug("%s: MilterPGP: with openpgp." % (time.ctime(thistime)))
    return self.Continue()

  #end def MilterPGP(self).


#end class KimpfMilter(object).
####################################################################

#ordinary methods:
def withinlist(alist, astring):
  thestring = astring.lower()

  for el in alist:
    if thestring.find(el) >= 0:
      return True
  return False

