#!/usr/bin/python2.4
# $Id: ppymilterserver.py 31 2009-01-13 01:04:38Z cajunhustla $
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
# Asynchronous and threaded socket servers for the sendmail milter protocol.
#
# Example usage:
#"""
#   import asyncore
#   import ppymilterserver
#   import ppymilterbase
#
#   class MyHandler(ppymilterbase.PpyMilter):
#     def OnMailFrom(...):
#       ...
#   ...
#
#   # to run async server
#   ppymilterserver.AsyncPpyMilterServer(port, MyHandler)
#   asyncore.loop()
#"""
#

__author__ = 'Eric DeFriez'

import asynchat, asyncore, binascii, logging, SocketServer
import struct, sys, time, os, socket
import dmarcmilter as kimpf, subprocess as sp, commons as com

MILTER_LEN_BYTES = 4  # from sendmail's include/libmilter/mfdef.h
DNSCache = ""  #For local test operations.
BACKLOG                 = 5
SIZE                    = 1024


class AsyncPpyMilterServer(asyncore.dispatcher):
  """Asynchronous server that handles connections from
  sendmail over a network socket using the milter protocol.
  """

  # TODO: allow network socket interface to be overridden
  def __init__(self, tp, milter_class, max_queued_connections=1024):
    """Constructs an AsyncPpyMilterServer.

    Args:
      port: A numeric port to listen on (TCP).
      milter_class: A class (not an instance) that handles callbacks for
                    milter commands (e.g. a child of the PpyMilter class).
      max_queued_connections: Maximum number of connections to allow to
                              queue up on socket awaiting accept().
    """
    asyncore.dispatcher.__init__(self)
    self.__milter_class = milter_class
    self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
    self.set_reuse_addr()
    self.bind(('', tp.tup['smtpPort']))
    self.milt = tp.tup['milType']
    self.mildb = tp.tup['milDB']
    self.tp = tp
    print "Async.init: miltype=%s listen on %d" % (self.milt, tp.tup['smtpPort'])
    self.listen(max_queued_connections)

  def handle_accept(self):
    """Callback function from asyncore to handle a connection dispatching."""
    try:
      (conn, addr) = self.accept()
    except socket.error, e:
      logging.error('warning: server accept() threw an exception ("%s")',
                        str(e))
      return
    AsyncPpyMilterServer.ConnectionHandler(conn, addr, self.__milter_class, self.tp)


  class ConnectionHandler(asynchat.async_chat):
    """A connection handling class that manages communication on a
    specific connection's network socket.  Receives callbacks from asynchat
    when new data appears on a socket and when an entire milter command is
    ready invokes the milter dispatching class.
    """

    # TODO: allow milter dispatcher to be overridden (PpyMilterDispatcher)?
    def __init__(self, conn, addr, milter_class, tp):
      """A connection handling class to manage communication on this socket.

      Args:
        conn: The socket connection object.
        addr: The address (port/ip) as returned by socket.accept()
        milter_class: A class (not an instance) that handles callbacks for
                      milter commands (e.g. a child of the PpyMilter class).

      June 11, 2012, Stephen Nightingale, NIST:
      Added chmiltype to differentiate mail sender and receiver processing.
      """
      asynchat.async_chat.__init__(self, conn)
      self.__conn = conn
      self.__addr = addr
      self.__milter_dispatcher = kimpf.PpyMilterDispatcher(milter_class, tp)
      self.__input = []
      self.set_terminator(MILTER_LEN_BYTES)
      self.found_terminator = self.read_packetlen
      self.chmilt = tp.tup['milType']
      self.mildb = tp.tup['milDB']
      self.tp = tp
 
    def collect_incoming_data(self, data):
      """Callback from asynchat--simply buffer partial data in a string."""
      self.__input.append(data)

    def log_info(self, message, type='info'):
      """Provide useful logging for uncaught exceptions"""
      if type == 'info':
        logging.debug(message)
      else:
        logging.error(message)

    def read_packetlen(self):
      """Callback from asynchat once we have an integer accumulated in our
      input buffer (the milter packet length)."""
      packetlen = int(struct.unpack('!I', "".join(self.__input))[0])
      self.__input = []
      self.set_terminator(packetlen)
      self.found_terminator = self.read_milter_data

    def __send_response(self, response):
      """Send data down the milter socket.

      Args:
        response: The data to send.
      """
      #logging.debug('  >>> %s', binascii.b2a_qp(response[0]))
      self.push(struct.pack('!I', len(response)))
      self.push(response)

    def read_milter_data(self):

      """ Callback from asynchat once we have read the milter packet length
      worth of bytes on the socket and it is accumulated in our input buffer
      (which is the milter command + data to send to the dispatcher). """

      import binascii
      inbuff = "".join(self.__input)
      self.__input = []
      if not inbuff.startswith("B"):
        if self.chmilt == "Receiver":
          logging.debug(' read: %s %s', self.chmilt, binascii.b2a_qp(inbuff))
      try:
        response = self.__milter_dispatcher.Dispatch(inbuff)
        #logging.debug(' >>> resp: [%s]', response)
        if type(response) == list:
          for r in response:
            self.__send_response(r)
        elif response:
          self.__send_response(response)

        # rinse and repeat :)
        self.found_terminator = self.read_packetlen
        self.set_terminator(MILTER_LEN_BYTES)
      except kimpf.PpyMilterCloseConnection, e:
        self.close()


  #end class ConnectionHandler(asynchat.async_chat).

#end class AsyncPpyMilterServer(asyncore.dispatcher).

#SN July 13, 2015
#Bring configuration processing inside here, instead of in commons.
class conFig:

  def __init__(self, infile):
    self.tup = {}
    self.tup = self.getFigs(infile)
  #end def __init__

  def filein(self, infile):
    sl = []
    for el in open(infile):
      sl.append(el.strip())

    return sl
  #end def filein

  def getFigs(self, flin):

    tup = {}
    fg = self.filein(flin)
    for kwarg in fg:
      kwey = kwarg.strip()
      if kwey.startswith("#"): continue
      if kwey == "": continue
      (kw, arg) = kwey.split("=")
      if kw == "milLog": tup['milLog'] = arg; continue
      if kw == "milType": tup['milType'] = arg; continue
      if kw == "milHost": tup['milHost'] = arg; continue
      if kw == "milDB": tup['milDB'] = arg; continue
      if kw == "milSCM": tup['milSCM'] = arg; continue
      if kw == "smtpHost": tup['smtpHost'] = arg; continue
      if kw == "smtpPort": tup['smtpPort'] = int(arg); continue
      if tup['milType'] == "Sender":
        if kw == "whoWeAre": tup['whoWeAre'] = arg; continue
        if kw == "keyFile": tup['keyFile'] = arg; continue
        if kw == "selector": tup['selector'] = arg; continue

    return tup


#Need to differentiate port numbers when 2 milters are running:
#ex. Sender=9909, Receiver=9999.
if __name__ == '__main__':

  try: tp = conFig(sys.argv[1])
  except IndexError: sys.exit("Usage: pythentic.py <pipes>.conf")

  logging.basicConfig(filename=tp.tup['milLog'], level=logging.DEBUG, 
                      format="%(asctime)s %(message)s", datefmt='%m-%d %H:%M:%S')
  logging.debug('Pythentic Restarted for %s.\n' % (tp.tup['milType']))
  server = AsyncPpyMilterServer(tp, kimpf.KimpfMilter)
  asyncore.loop()

#end if __name__ == '__main__'.
