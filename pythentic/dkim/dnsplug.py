#Substitute dnsplug.py for use with dkim and dmarc modules.
#Compatible with the DNS call in spf.

import DNS, spf

def get_txt(name):

  if name.endswith('.'):
    name = name[:-1]

  try:
    for k, v in spf.DNSLookup(name, 'TXT'):
      if k[1] == 'TXT':
        return b''.join(v)
  except: pass

  return None

