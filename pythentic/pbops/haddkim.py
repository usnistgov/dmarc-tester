# This software is provided 'as-is', without any express or implied
# warranty.  In no event will the author be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not
#    claim that you wrote the original software. If you use this software
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
# 2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
# 3. This notice may not be removed or altered from any source distribution.
#
# Copyright (c) 2008 Greg Hewgill http://hewgill.com
#
# This has been modified from the original software.
# Copyright (c) 2011 William Grant <me@williamgrant.id.au>

#Additional modifications by Stephen Nightingale, U.S. National Institute of Standards and Technology.
#Novenber 2012 - August 2016.
#no additional copyright or license is implied by these subsequent modifications.
#Stephen Nightingale, night@nist.gov

import base64
import hashlib
import logging
import re
import time

from dkim.canonicalization import (
    CanonicalizationPolicy,
    InvalidCanonicalizationPolicyError,
    )
from dkim.crypto import (
    DigestTooLargeError,
    HASH_ALGORITHMS,
    parse_pem_private_key,
    parse_public_key,
    RSASSA_PKCS1_v1_5_sign,
    RSASSA_PKCS1_v1_5_verify,
    UnparsableKeyError,
    )
try:
  import dinsget
except:
  raise RuntimeError("DKIM.verify requires dinsget module")
from dkim.util import (
    get_default_logger,
    InvalidTagValueList,
    parse_tag_value,
    )

__all__ = [
    "DKIMException",
    "InternalError",
    "KeyFormatError",
    "MessageFormatError",
    "ParameterError",
    "Relaxed",
    "Simple",
    "DKIM",
    "sign",
    "verify",
]

Relaxed = b'relaxed'    # for clients passing dkim.Relaxed
Simple = b'simple'      # for clients passing dkim.Simple

def bitsize(x):
    """Return size of long in bits."""
    return len(bin(x)) - 2

class DKIMException(Exception):
    """Base class for DKIM errors."""
    pass

class InternalError(DKIMException):
    """Internal error in dkim module. Should never happen."""
    pass

class KeyFormatError(DKIMException):
    """Key format error while parsing an RSA public or private key."""
    pass

class MessageFormatError(DKIMException):
    """RFC822 message format error."""
    pass

class ParameterError(DKIMException):
    """Input parameter error."""
    pass

class ValidationError(DKIMException):
    """Validation error."""
    pass

def select_headers(headers, include_headers):
    """Select message header fields to be signed/verified.

    >>> h = [('from','biz'),('foo','bar'),('from','baz'),('subject','boring')]
    >>> i = ['from','subject','to','from']
    >>> select_headers(h,i)
    [('from', 'baz'), ('subject', 'boring'), ('from', 'biz')]
    >>> h = [('From','biz'),('Foo','bar'),('Subject','Boring')]
    >>> i = ['from','subject','to','from']
    >>> select_headers(h,i)
    [('From', 'biz'), ('Subject', 'Boring')]
    """
    sign_headers = []
    lastindex = {}
    for h in include_headers:
        assert h == h.lower()
        i = lastindex.get(h, len(headers))
        while i > 0:
            i -= 1
            if h == headers[i][0].lower():
                sign_headers.append(headers[i])
                break
        lastindex[h] = i
    return sign_headers

FWS = r'(?:\r?\n\s+)?'
RE_BTAG = re.compile(r'([;\s]b'+FWS+r'=)(?:'+FWS+r'[a-zA-Z0-9+/=])*(?:\r?\n\Z)?')

def hash_headers(hasher, canonicalize_headers, headers, include_headers,
                 sigheader, sig):
    """Update hash for signed message header fields."""
    sign_headers = select_headers(headers,include_headers)
    # The call to _remove() assumes that the signature b= only appears
    # once in the signature header
    cheaders = canonicalize_headers.canonicalize_headers(
        [(sigheader[0], RE_BTAG.sub(b'\\1',sigheader[1]))])
    # the dkim sig is hashed with no trailing crlf, even if the
    # canonicalization algorithm would add one.
    for x,y in sign_headers + [(x, y.rstrip()) for x,y in cheaders]:
        hasher.update(x)
        hasher.update(b":")
        hasher.update(y)
    return sign_headers

def validate_signature_fields(sig):
    """Validate DKIM-Signature fields.

    Basic checks for presence and correct formatting of mandatory fields.
    Raises a ValidationError if checks fail, otherwise returns None.

    @param sig: A dict mapping field keys to values.
    """
    mandatory_fields = (b'v', b'a', b'b', b'bh', b'd', b'h', b's')
    for field in mandatory_fields:
        if field not in sig:
            raise ValidationError("signature missing %s=" % field)

    if sig[b'v'] != b"1":
        raise ValidationError("v= value is not 1 (%s)" % sig[b'v'])
    if re.match(br"[\s0-9A-Za-z+/]+=*$", sig[b'b']) is None:
        raise ValidationError("b= value is not valid base64 (%s)" % sig[b'b'])
    if re.match(br"[\s0-9A-Za-z+/]+=*$", sig[b'bh']) is None:
        raise ValidationError(
            "bh= value is not valid base64 (%s)" % sig[b'bh'])
    # Nasty hack to support both str and bytes... check for both the
    # character and integer values.
    if b'i' in sig and (
        not sig[b'i'].endswith(sig[b'd']) or
        sig[b'i'][-len(sig[b'd'])-1] not in ('@', '.', 64, 46)):
        raise ValidationError(
            "i= domain is not a subdomain of d= (i=%s d=%s)" %
            (sig[b'i'], sig[b'd']))
    if b'l' in sig and re.match(br"\d{,76}$", sig['l']) is None:
        raise ValidationError(
            "l= value is not a decimal integer (%s)" % sig[b'l'])
    if b'q' in sig and sig[b'q'] != b"dns/txt":
        raise ValidationError("q= value is not dns/txt (%s)" % sig[b'q'])
    if b't' in sig and re.match(br"\d+$", sig[b't']) is None:
        raise ValidationError(
            "t= value is not a decimal integer (%s)" % sig[b't'])
    if b'x' in sig:
        if re.match(br"\d+$", sig[b'x']) is None:
            raise ValidationError(
                "x= value is not a decimal integer (%s)" % sig[b'x'])
        if int(sig[b'x']) < int(sig[b't']):
            raise ValidationError(
                "x= value is less than t= value (x=%s t=%s)" %
                (sig[b'x'], sig[b't']))


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
                raise MessageFormatError("Unexpected characters in RFC822 header: %s" % lines[i])
        i += 1
    return (headers, b"\r\n".join(lines[i:]))



def fold(header):
    """Fold a header line into multiple crlf-separated lines at column 72.

    >>> fold(b'foo')
    'foo'
    >>> fold(b'foo  '+b'foo'*24).splitlines()[0]
    'foo  '
    >>> fold(b'foo'*25).splitlines()[-1]
    ' foo'
    >>> len(fold(b'foo'*25).splitlines()[0])
    72
    """
    i = header.rfind(b"\r\n ")
    if i == -1:
        pre = b""
    else:
        i += 3
        pre = header[:i]
        header = header[i:]
    while len(header) > 72:
        i = header[:72].rfind(b" ")
        if i == -1:
            j = 72
        else:
            j = i + 1
        pre += header[:j] + b"\r\n "
        header = header[j:]
    return pre + header

#: Hold messages and options during DKIM signing and verification.
class DKIM(object):
  RFC5322_SINGLETON = ('date','from','sender','reply-to','to','cc','bcc',
        'message-id','in-reply-to','references')
  FROZEN = ('from','date','subject')
  SHOULD = (
    'sender', 'reply-to', 'subject', 'date', 'message-id', 'to', 'cc',
    'mime-version', 'content-type', 'content-transfer-encoding', 'content-id',
    'content- description', 'resent-date', 'resent-from', 'resent-sender',
    'resent-to', 'resent-cc', 'resent-message-id', 'in-reply-to', 'references',
    'list-id', 'list-help', 'list-unsubscribe', 'list-subscribe', 'list-post',
    'list-owner', 'list-archive'
  )
  SHOULD_NOT = (
    'return-path', 'received', 'comments', 'keywords', 'bcc', 'resent-bcc',
    'dkim-signature'
  )

  #: Create a DKIM instance to sign and verify rfc5322 messages.
  def __init__(self,message=None,signature_algorithm=b'rsa-sha256',
        minkey=1024):
    self.set_message(message)
    if signature_algorithm not in HASH_ALGORITHMS:
        raise ParameterError(
            "Unsupported signature algorithm: "+signature_algorithm)
    self.signature_algorithm = signature_algorithm
    self.should_sign = set(DKIM.SHOULD)
    self.should_not_sign = set(DKIM.SHOULD_NOT)
    self.frozen_sign = set(DKIM.FROZEN)
    self.minkey = minkey

  def add_frozen(self,s):
    """ Add headers not in should_not_sign to frozen_sign.
    @param s: list of headers to add to frozen_sign
    @since: 0.5

    >>> dkim = DKIM()
    >>> dkim.add_frozen(DKIM.RFC5322_SINGLETON)
    >>> sorted(dkim.frozen_sign)
    ['cc', 'date', 'from', 'in-reply-to', 'message-id', 'references', 'reply-to', 'sender', 'subject', 'to']
    """
    self.frozen_sign.update(x.lower() for x in s
        if x.lower() not in self.should_not_sign)

  #: Load a new message to be signed or verified.
  #: @param message: an RFC822 formatted message to be signed or verified
  #: (with either \\n or \\r\\n line endings)
  #: @since: 0.5
  def set_message(self, message):
    if message:
      self.headers, self.body = rfc822_parse(message)
    else:
      self.headers, self.body = [],''
    self.domain = None
    self.selector = 'default'
    self.signature_fields = {}
    self.signed_headers = []
    self.keysize = 0

  def default_sign_headers(self):
    """Return the default list of headers to sign: those in should_sign or
    frozen_sign, with those in frozen_sign signed an extra time to prevent
    additions.
    @since: 0.5"""
    hset = self.should_sign | self.frozen_sign
    include_headers = [ x for x,y in self.headers
        if x.lower() in hset ]
    return include_headers + [ x for x in include_headers
        if x.lower() in self.frozen_sign]

  def all_sign_headers(self):
    """Return header list of all existing headers not in should_not_sign.
    @since: 0.5"""
    return [x for x,y in self.headers if x.lower() not in self.should_not_sign]

  #: Sign an RFC822 message and return the DKIM-Signature header line.
  #:
  #: The include_headers option gives full control over which header fields
  #: are signed.  Note that signing a header field that doesn't exist prevents
  #: that field from being added without breaking the signature.  Repeated
  #: fields (such as Received) can be signed multiple times.  Instances
  #: of the field are signed from bottom to top.  Signing a header field more
  #: times than are currently present prevents additional instances
  #: from being added without breaking the signature.
  #:
  #: The length option allows the message body to be appended to by MTAs
  #: enroute (e.g. mailing lists that append unsubscribe information)
  #: without breaking the signature.
  #:
  #: The default include_headers for this method differs from the backward
  #: compatible sign function, which signs all headers not 
  #: in should_not_sign.  The default list for this method can be modified 
  #: by tweaking should_sign and frozen_sign (or even should_not_sign).
  #: It is only necessary to pass an include_headers list when precise control
  #: is needed.
  #:
  #: @param selector: the DKIM selector value for the signature
  #: @param domain: the DKIM domain value for the signature
  #: @param privkey: a PKCS#1 private key in base64-encoded text form
  #: @param identity: the DKIM identity value for the signature
  #: (default "@"+domain)
  #: @param canonicalize: the canonicalization algorithms to use
  #: (default (Simple, Simple))
  #: @param include_headers: a list of strings indicating which headers
  #: are to be signed (default rfc4871 recommended headers)
  #: @param length: true if the l= tag should be included to indicate
  #: body length signed (default False).
  #: @return: DKIM-Signature header field terminated by '\r\n'
  #: @raise DKIMException: when the message, include_headers, or key are badly
  #: formed.
  def sign(self, selector, domain, privkey, identity=None,
        canonicalize=(b'relaxed',b'simple'), include_headers=None, length=False):
    try:
        pk = parse_pem_private_key(privkey)
    except UnparsableKeyError as e:
        raise KeyFormatError(str(e))

    if identity is not None and not identity.endswith(domain):
        raise ParameterError("identity must end with domain")

    canon_policy = CanonicalizationPolicy.from_c_value(
        b'/'.join(canonicalize))
    headers = canon_policy.canonicalize_headers(self.headers)

    if include_headers is None:
        include_headers = self.default_sign_headers()

    # rfc4871 says FROM is required
    if 'from' not in ( x.lower() for x in include_headers ):
        raise ParameterError("The From header field MUST be signed")

    # raise exception for any SHOULD_NOT headers, call can modify 
    # SHOULD_NOT if really needed.
    for x in include_headers:
        if x.lower() in self.should_not_sign:
            raise ParameterError("The %s header field SHOULD NOT be signed"%x)

    body = canon_policy.canonicalize_body(self.body)

    hasher = HASH_ALGORITHMS[self.signature_algorithm]
    h = hasher()
    h.update(body)
    bodyhash = base64.b64encode(h.digest())

    sigfields = [x for x in [
        (b'v', b"1"),
        (b'a', self.signature_algorithm),
        (b'c', canon_policy.to_c_value()),
        (b'd', domain),
        (b'i', identity or b"@"+domain),
        length and (b'l', len(body)),
        (b'q', b"dns/txt"),
        (b's', selector),
        (b't', str(int(time.time())).encode('ascii')),
        (b'h', b" : ".join(include_headers)),
        (b'bh', bodyhash),
        # Force b= to fold onto it's own line so that refolding after
        # adding sig doesn't change whitespace for previous tags.
        (b'b', b'0'*60), 
    ] if x]
    include_headers = [x.lower() for x in include_headers]
    # record what verify should extract
    self.include_headers = tuple(include_headers)

    sig_value = fold(b"; ".join(b"=".join(x) for x in sigfields))
    sig_value = RE_BTAG.sub(b'\\1',sig_value)
    dkim_header = (b'DKIM-Signature', b' ' + sig_value)
    h = hasher()
    sig = dict(sigfields)
    self.signed_headers = hash_headers(
        h, canon_policy, headers, include_headers, dkim_header,sig)
    self.logger.debug("sign headers: %r" % self.signed_headers)

    try:
        sig2 = RSASSA_PKCS1_v1_5_sign(h, pk)
    except DigestTooLargeError:
        raise ParameterError("digest too large for modulus")
    # Folding b= is explicity allowed, but yahoo and live.com are broken
    #sig_value += base64.b64encode(bytes(sig2))
    # Instead of leaving unfolded (which lets an MTA fold it later and still
    # breaks yahoo and live.com), we change the default signing mode to
    # relaxed/simple (for broken receivers), and fold now.
    sig_value = fold(sig_value + base64.b64encode(bytes(sig2)))

    self.domain = domain
    self.selector = selector
    self.signature_fields = sig
    return b'DKIM-Signature: ' + sig_value + b"\r\n"

  #: Verify a DKIM signature.
  #: @type idx: int
  #: @param idx: which signature to verify.  The first (topmost) signature is 0.
  #: @type dnsfunc: callable
  #: @param dnsfunc: an option function to lookup TXT resource records
  #: for a DNS domain.  The default uses dnspython or pydns.
  #: @return: True if signature verifies or False otherwise
  #: @raise DKIMException: when the message, signature, or key are badly formed
  # JSN 03/15/16 All exceptions returned as Reason, with result=False. 
  def verify(self,idx=0,dnsfunc=dinsget.domain_dkim):
    expl = ""; dkix = 0; sig = ""; rec = ""

    sigheaders = [(x,y) for x,y in self.headers if x.lower().find(b"dkim-signature") >= 0]
    if len(sigheaders) <= idx:
        expl += "No DKIM signature.\n"
        return (False, "no DKIM signature", rec, expl)

    expl += "\nDKIM Signatures in the message:\n"
    for hdr in sigheaders:
      expl += "[%d] %s:" % (dkix, hdr[0])
      dkix += 1
      for headline in hdr[1].split('\r\n'):
        expl += "%s\n" % (headline)

    # By default, we validate the first DKIM-Signature line found.
    try:
        sig = parse_tag_value(sigheaders[idx][1])
        self.signature_fields = sig
    except InvalidTagValueList as e:
        return(False, e, rec, expl)

    validate_signature_fields(sig)
    self.domain = sig[b'd']
    self.selector = sig[b's']
    self.algorithm = sig[b'a']
    self.policy = sig[b'c']

    try:
        canon_policy = CanonicalizationPolicy.from_c_value(sig.get(b'c'))
    except InvalidCanonicalizationPolicyError as e:
        return(False, "invalid c= value: %s" % e.args[0], rec, expl)
    headers = canon_policy.canonicalize_headers(self.headers)
    body = canon_policy.canonicalize_body(self.body)

    try:
        hasher = HASH_ALGORITHMS[sig[b'a']]
    except KeyError as e:
        return(False, "unknown signature algorithm: %s" % e.args[0], rec, expl)

    if b'l' in sig:
        body = body[:int(sig[b'l'])]

    h = hasher()
    h.update(body)
    bodyhash = h.digest()
    try:
        bh = base64.b64decode(re.sub(br"\s+", b"", sig[b'bh']))
        expl += "BH field in signature:\t %s\n" % (sig[b'bh'])
        expl += "Computed BodyHash:\t %s\n"  % (base64.b64encode(bodyhash))
    except TypeError as e:
        return(False, str(e), rec, expl)
    if bodyhash == bh:
      expl += "Computed Hash matches Message Hash.\n"
    else:
      if base64.b64encode(bodyhash).startswith("frcCV"):
        expl += "Note: frccV[...] is simple canonicalization of empty body.\n"
      else:
          return(False, "body hash mismatch (I compute %s, You send %s)" % (base64.b64encode(bodyhash), sig[b'bh']), rec, expl)
          

    name = sig[b's'] + b"._domainkey." + sig[b'd'] + b"."
    rec = dnsfunc(name)

    if not rec:
        return(False, "missing public key: %s"%name, rec, expl)
    try:
        pub = parse_tag_value(rec)
    except InvalidTagValueList:
        return(False, e, rec, expl)
    try:
        pk = parse_public_key(base64.b64decode(pub[b'p']))
        self.keysize = bitsize(pk['modulus'])
    except KeyError:
        return(False, "incomplete public key: %s" % rec, rec, expl)
    except (TypeError,UnparsableKeyError) as e:
        return(False, "could not parse public key (%s): %s" % (pub[b'p'],e), rec, expl)
    include_headers = [x.lower() for x in re.split(br"\s*:\s*", sig[b'h'])]
    self.include_headers = tuple(include_headers)

    if 'from' in include_headers:
      include_headers.append('from')      
    h = hasher()
    self.signed_headers = hash_headers(
        h, canon_policy, headers, include_headers, sigheaders[idx], sig)
    try:
        signature = base64.b64decode(re.sub(br"\s+", b"", sig[b'b']))
        res = RSASSA_PKCS1_v1_5_verify(h, signature, pk)
        if res:
          if self.keysize >= self.minkey:
            expl += "\nSignature: %s\n" % (sig[b'b'])
            expl += "\nDKIM Signature Verifies.\n"
          else:
            return(False, "public key too small: %d" % self.keysize, rec, expl)
        else:
          expl += "DKIM Fails.\n"
        return (res, "DKIM Pass.", rec, expl)
    except (TypeError,DigestTooLargeError) as e:
        return(False, "digest too large for modulus: %s"%e, rec, expl)



def sign(message, selector, domain, privkey, identity=None,
         canonicalize=(b'relaxed', b'simple'),
         signature_algorithm=b'rsa-sha256',
         include_headers=None, length=False):
    """Sign an RFC822 message and return the DKIM-Signature header line.
    @param message: an RFC822 formatted message (with either \\n or \\r\\n line endings)
    @param selector: the DKIM selector value for the signature
    @param domain: the DKIM domain value for the signature
    @param privkey: a PKCS#1 private key in base64-encoded text form
    @param identity: the DKIM identity value for the signature (default "@"+domain)
    @param canonicalize: the canonicalization algorithms to use (default (Simple, Simple))
    @param include_headers: a list of strings indicating which headers are to be signed (default all headers not listed as SHOULD NOT sign)
    @param length: true if the l= tag should be included to indicate body length (default False)
    @return: DKIM-Signature header field terminated by \\r\\n
    @raise DKIMException: when the message, include_headers, or key are badly formed.
    """

    d = DKIM(message)
    if not include_headers:
        include_headers = d.all_sign_headers()
    return d.sign(selector, domain, privkey, identity=identity, canonicalize=canonicalize, include_headers=include_headers, length=length)

def verify(message, dnsfunc=dinsget.domain_dkim, minkey=1024):

    d = DKIM(message,minkey=minkey)
    return (d.verify(dnsfunc=dnsfunc), d.domain)


if __name__ == "__main__":
  import sys
  s = dinsget.domain_dkim(sys.argv[1])
  pub = parse_tag_value(s)
  for key in pub:
    print key, "=", pub[key]
  pk = parse_public_key(base64.b64decode(pub[b'p']))
  for key in pk:
    print key, "=",  pk[key]

