import sys
MIN_VERSION = (3, 11) # required minimal Python version
if sys.version_info < MIN_VERSION:
    sys.exit(f"Python version {'.'.join(map(str, MIN_VERSION))} or later is required.")

import socketserver
import threading
import binascii
import tomllib
import random
import socket
import string
import struct
import glob
import time
import os
import nfz

polardns_version = "1.6.0"

################################

stamp = str(time.time()).ljust(18, "0")

# load config
with open("polardns.toml", "rb") as f:
    _config = tomllib.load(f)
config = {k:v for k,v in _config['main'].items() if k != 'known_servers'}

known_servers = {}
for line in _config['main']['known_servers'].split('\n'):
    if not line:
        continue
    host, ip_address = line.split()
    known_servers[host] = ip_address

debug = config['debug']
#debug = 1

config_ttl = int(config['ttl'])
config_sleep = float(config['sleep'])
config_compression = int(config['compression'])
config_parse_edns0 = config['parse_edns0']

# a domain which is a 3rd party which we don't control
a3rdparty_domain = config['a3rdparty_domain']

# domains which we want to be authoritative for
OURDOMAINS = [
   config['domain'],
   a3rdparty_domain,
   "anything.com",
   "version.polar"
]

ZONEFILE = {
   "ns1."+config['domain']:   {"A": config['ns1']},
   "ns2."+config['domain']:   {"A": config['ns2']},
   "end."+config['domain']:   {"A": "1.2.3.4"},
   config['domain']:       {"NS": "ns1."+config['domain'],
                             "MX": "10 mail1."+config['domain'],
                             "TXT": "hello, this is a testing domain",
                             "SOA": "ns1."+config['domain']+" hostmaster."+config['domain']+" 2023052903 10800 3600 604800 3600"},
   "mail1."+config['domain']:                    {"A": "1.2.3.4"},
   "hello."+config['domain']:                    {"A": "1.2.3.4"},
   "injected."+a3rdparty_domain:                 {"A": "6.6.6.0"},
   "injected10."+a3rdparty_domain:               {"A": "6.6.6.10"},
   "injected11."+a3rdparty_domain:               {"A": "6.6.6.11"},
   "injected12."+a3rdparty_domain:               {"A": "6.6.6.12"},
   "injected13."+a3rdparty_domain:               {"A": "6.6.6.13"},
   "ns1."+a3rdparty_domain:                      {"A": config['ns1']},
   "ns1."+a3rdparty_domain+"."+config['domain']: {"A": config['ns1']},
   "ns1."+config['domain']+"."+a3rdparty_domain: {"A": config['ns1']}
}

DNSCLASS = {
   "IN":       1,
   "CH":       3,
   "HS":       4
}

DNSTYPE = {
   "A":           1,
   "NS":          2,
   "MD":          3,
   "MF":          4,
   "CNAME":       5,
   "SOA":         6,
   "MB":          7,
   "MG":          8,
   "MR":          9,
   "NULL":       10,
   "WKS":        11,
   "PTR":        12,
   "HINFO":      13,
   "MINFO":      14,
   "MX":         15,
   "TXT":        16,
   "RP":         17,
   "AFSDB":      18,
   "X25":        19,
   "ISDN":       20,
   "RT":         21,
   "NSAP":       22,
   "NSAP-PTR":   23,
   "SIG":        24,
   "KEY":        25,
   "PX":         26,
   "GPOS":       27,
   "AAAA":       28,
   "LOC":        29,
   "NXT":        30,
   "EID":        31,
   "NIMLOC":     32,
   "SRV":        33,
   "ATMA":       34,
   "NAPTR":      35,
   "KX":         36,
   "CERT":       37,
   "A6":         38,
   "DNAME":      39,
   "SINK":       40,
   "OPT":        41,
   "APL":        42,
   "DS":         43,
   "SSHFP":      44,
   "IPSECKEY":   45,
   "RRSIG":      46,
   "NSEC":       47,
   "DNSKEY":     48,
   "DHCID":      49,
   "NSEC3":      50,
   "NSEC3PARAM": 51,
   "TLSA":       52,
   "SMIMEA":     53,
   "HIP":        55,
   "NINFO":      56,
   "RKEY":       57,
   "TALINK":     58,
   "CDS":        59,
   "CDNSKEY":    60,
   "OPENPGPKEY": 61,
   "CSYNC":      62,
   "ZONEMD":     63,
   "SVCB":       64,
   "HTTPS":      65,
   "SPF":        99,
   "UINFO":      100,
   "UID":        101,
   "GID":        102,
   "UNSPEC":     103,
   "NID":        104,
   "L32":        105,
   "L64":        106,
   "LP":         107,
   "EUI48":      108,
   "EUI64":      109,
   "TKEY":       249,
   "TSIG":       250,
   "IXFR":       251,
   "AXFR":       252,
   "MAILB":      253,
   "MAILA":      254,
   "ANY":        255,
   "URI":        256,
   "CAA":        257,
   "AVC":        258,
   "DOA":        259,
   "AMTRELAY":   260,
   "TA":         32768,
   "DLV":        32769
}

# Function to get DNS class name (string) from code (int)
def getClassName(q):
    for key, val in DNSCLASS.items():
        if val == q:
            return key
    return "None"

# Function to get DNS class code (int) from name (string)
def getClassCode(q):
    return DNSCLASS.get(q)

# Function to get binary DNS class from name (string)
def getClassBin(q):
    code = DNSCLASS.get(q)
    return struct.pack(">H", code)

# Create a reverse dictionary of DNS types so that look ups are very fast
DNSTYPER = {}
for key, val in DNSTYPE.items():
    DNSTYPER[val] = key

# Function to get DNS type name (string) from code (int)
def getTypeName(q):
    return DNSTYPER.get(q)

# Function to get DNS type code (int) from name (string)
def getTypeCode(q):
    return DNSTYPE.get(q)

# Function to get binary DNS type from name (string)
def getTypeBin(q):
    code = DNSTYPE.get(q)
    return struct.pack(">H", code)

################################
# Function to convert domain name string to the binary form
# aka. DNS name notation
# input example: www.abcd.com
# output       : \x03www\x04abcd\x3com\x00

def convDom2Bin(x):
    if hasattr(resp, 'DOM_ALREADY_CONVERTED'):
        delattr(resp, 'DOM_ALREADY_CONVERTED')
        return x
    if x == "": return b"\x00"
    parts = []
    append = parts.append  # Local variable lookup is faster
    for y in x.split('.'):
        y = y.replace("<DOT>", ".")
        length = bytes([len(y)])
        append(length)
        append(y.encode("utf-8"))
    parts.append(b"\x00")
    return b''.join(parts)

################################
# Function to convert data string to the binary form
# input example: somedata.something
# output       : \x08somedata\x09something

def convData2Bin(x):
    parts = []
    append = parts.append  # Local variable lookup is faster
    for y in x.split('.'):
        y = y.replace("<DOT>", ".")
        length = bytes([len(y)])
        append(length)
        append(y.encode("utf-8"))
    return b''.join(parts)

################################

def name_fuzz(n):
    rand_suffix = '{:06d}'.format(random.getrandbits(20) % 1000000)
    match n:
      ######################
      case 0:
         dom = nfz.name_fuzz_malf_p0(resp) + b'\x00'
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 1 | 2 | 3 | 4 | 5 | 6:
         match n:
            case 1:
               firstdom = "always"
               suffix = ""
            case 2:
               firstdom = "nonres"
               suffix = ""
            case 3:
               firstdom = req.first_subdomain
               suffix = ""
            case 4:
               firstdom = "always"
               suffix = rand_suffix
            case 5:
               firstdom = "nonres"
               suffix = rand_suffix
            case 6:
               firstdom = req.first_subdomain
               suffix = rand_suffix
         # figure out the position
         match resp.nfz_pos:
            case 0:
               # <HERE>.always######.yourdomain.com
               dom  = nfz.name_fuzz_malf_p0(resp)
               dom += convData2Bin(firstdom + suffix + "." + req.sld_tld_domain) + b'\x00'
            case 1:
               # <HERE>always######.yourdomain.com
               dom  = nfz.name_fuzz_malf_p1(resp, firstdom + suffix)
               dom += convData2Bin(req.sld_tld_domain) + b'\x00'
            case 2:
               # always<HERE>######.yourdomain.com
               dom  = nfz.name_fuzz_malf_p2(resp, firstdom, suffix)
               dom += convData2Bin(req.sld_tld_domain) + b'\x00'
            case 3:
               # always######<HERE>.yourdomain.com
               dom  = nfz.name_fuzz_malf_p3(resp, firstdom + suffix)
               dom += convData2Bin(req.sld_tld_domain) + b'\x00'
            case 4:
               # always######<HERE>yourdomain.com
               dom  = nfz.name_fuzz_malf_p4(resp, firstdom + suffix, req.sld)
               dom += convData2Bin(req.tld) + b'\x00'
            case 5:
               # always######.<HERE>.yourdomain.com
               dom  = convData2Bin(firstdom + suffix)
               dom += nfz.name_fuzz_malf_p0(resp)
               dom += convData2Bin(req.sld_tld_domain) + b'\x00'
            case 6:
               # always######.<HERE>yourdomain.com
               dom  = convData2Bin(firstdom + suffix)
               dom += nfz.name_fuzz_malf_p1(resp, req.sld)
               dom += convData2Bin(req.tld) + b'\x00'
            case 7:
               # always######.yourdomain<HERE>.com
               dom  = convData2Bin(firstdom + suffix)
               dom += nfz.name_fuzz_malf_p3(resp, req.sld)
               dom += convData2Bin(req.tld) + b'\x00'
            case 8:
               # always######.yourdomain<HERE>com
               dom  = convData2Bin(firstdom + suffix)
               dom += nfz.name_fuzz_malf_p4(resp, req.sld, req.tld) + b'\x00'
            case 9:
               # always######.yourdomain.<HERE>.com
               dom  = convData2Bin(firstdom + suffix + "." + req.sld)
               dom += nfz.name_fuzz_malf_p0(resp)
               dom += convData2Bin(req.tld) + b'\x00'
            case 10:
               # always######.yourdomain.<HERE>com
               dom  = convData2Bin(firstdom + suffix + "." + req.sld)
               dom += nfz.name_fuzz_malf_p1(resp, req.tld) + b'\x00'
            case 11:
               # always######.yourdomain.com<HERE>
               dom  = convData2Bin(firstdom + suffix + "." + req.sld)
               dom += nfz.name_fuzz_malf_p3(resp, req.tld) + b'\x00'
            case 12:
               # always######.yourdomain.com.<HERE>
               dom  = convData2Bin(firstdom + suffix + "." + req.sld_tld_domain)
               dom += nfz.name_fuzz_malf_p0(resp) + b'\x00'
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 7:
         # <ROOT> domain
         dom = b'\x00'
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 8:
         # always123456.yourdomain.com:80
         dom = "always" + rand_suffix + "." + req.sld_tld_domain + ":80"
      ######################
      case 9:
         # always123456.yourdomain.com:443
         dom = "always" + rand_suffix + "." + req.sld_tld_domain + ":443"
      ######################
      case 10:
         # http://always123456.yourdomain.com/
         dom = "http://always" + rand_suffix + "." + req.sld_tld_domain + "/"
      ######################
      case 11:
         # http://always123456.yourdomain.com:80/
         dom = "http://always" + rand_suffix + "." + req.sld_tld_domain + ":80/"
      ######################
      case 12:
         # https://always123456.yourdomain.com/
         dom = "https://always" + rand_suffix + "." + req.sld_tld_domain + "/"
      ######################
      case 13:
         # https://always123456.yourdomain.com:443/
         dom = "https://always" + rand_suffix + "." + req.sld_tld_domain + ":443/"
      ######################
      case 14:
         # 1.2.3.4 (in DNS name notation as 4 labels)
         dom = "1.2.3.4"
      ######################
      case 15:
         # 1.2.3.4:80 (in DNS name notation as 4 labels)
         dom = "1.2.3.4:80"
      ######################
      case 16:
         # 1.2.3.4 (in DNS name notation as 1 label)
         dom = "1<DOT>2<DOT>3<DOT>4"
      ######################
      case 17:
         # 1.2.3.4:80 (in DNS name notation as 1 label)
         dom = "1<DOT>2<DOT>3<DOT>4:80"
      ######################
      case 18:
         # <OUR-IP-ADDRESS> (in DNS name notation as 4 labels)
         dom = ZONEFILE["ns1." + req.sld_tld_domain]["A"]
      ######################
      case 19:
         # <OUR-IP-ADDRESS>:80 (in DNS name notation as 4 labels)
         ourip = ZONEFILE["ns1." + req.sld_tld_domain]["A"]
         dom = ourip + ":80"
      ######################
      case _:
         # hello (default case)
         dom = "wrongnfz"
      ######################
    return dom

################################
# Function to increment chainXXX if there is one

def increment_chain(req_domain):
   new_subdomains = req.subdomains

   # in case of domains with attribute leaves (domains prefixed with an underscore),
   # do not modify the leading underscored subdomains (up to first 3 subdomains)
   # e.g., '_sub._service._proto...'
   skip = 0
   for i in range(3):
       if req.subdomains[2-i][0:1] == "_":
          new_subdomains = req.subdomains[3-i:]
          skip = 3-i
          break

   first_subdomain = new_subdomains[0]
   first_subdomain_length = len(first_subdomain)
   if first_subdomain_length > 5:
      # how many last characters are numeric
      hmlcan = 0
      while True:
         lastchar = first_subdomain[first_subdomain_length-(hmlcan+1):]
         if lastchar.isnumeric():
            hmlcan += 1
         else:
            break
         if hmlcan >= first_subdomain_length:
            break
      if hmlcan > 0:
         current_index = first_subdomain[first_subdomain_length-hmlcan:]
         subd_wo_index = first_subdomain[0:first_subdomain_length-hmlcan]
      else:
         current_index = 0
         subd_wo_index = first_subdomain

      new_label_number = int(current_index)+1
      new_subdomain = subd_wo_index + str(new_label_number)
   else:
      new_subdomain = "chain1"

   # replace the subdomain with new incremented index (if there was no index, it will be "chain1")
   new_subdomains[0] = new_subdomain

   # now construct a nice full domain name and return it
   new_domain_name = new_subdomain
   for l in range(1, len(new_subdomains)):
      new_domain_name += "." + new_subdomains[l]

   # in case of domains with attribute leaves, prepend back the first N subdomains we skipped above
   if skip:
      tmp = ""
      for i in range(skip):
         tmp += req.subdomains[i] + "."
      new_domain_name = tmp + new_domain_name

   print("new domain name:", new_domain_name) if debug else True
   return new_domain_name

################################
# Function to generate random chainXXX

def random_chain(req_domain):
   new_subdomains = req.subdomains

   # in case of domains with attribute leaves (domains prefixed with an underscore),
   # do not modify the leading underscored subdomains (up to first 3 subdomains)
   # e.g., '_sub._service._proto...'
   skip = 0
   for i in range(3):
       if req.subdomains[2-i][0:1] == "_":
          new_subdomains = req.subdomains[3-i:]
          skip = 3-i
          break

   first_subdomain = new_subdomains[0]
   first_subdomain_length = len(first_subdomain)
   new_random_number = random.getrandbits(20) % 1000000

   # how many last characters are numeric
   hmlcan = 0
   while True:
      lastchar = first_subdomain[first_subdomain_length-(hmlcan+1):]
      if lastchar.isnumeric():
         hmlcan += 1
      else:
         break
      if hmlcan >= first_subdomain_length:
         break
   if hmlcan > 0:
      current_index = first_subdomain[first_subdomain_length-hmlcan:]
      subd_wo_index = first_subdomain[0:first_subdomain_length-hmlcan]
   else:
      current_index = 0
      subd_wo_index = first_subdomain

   new_subdomain = subd_wo_index + str(new_random_number)

   # replace the subdomain with new random index
   new_subdomains[0] = new_subdomain

   # now construct a nice full domain name and return it
   new_domain_name = new_subdomain
   for l in range(1, len(new_subdomains)):
      new_domain_name += "." + new_subdomains[l]

   # in case of domains with attribute leaves, prepend back the first N subdomains we skipped above
   if skip:
      tmp = ""
      for i in range(skip):
         tmp += req.subdomains[i] + "."
      new_domain_name = tmp + new_domain_name

   print("new domain name:", new_domain_name) if debug else True
   return new_domain_name

################################
# Function for printing messages on the console

def log(m):
    stamp = str(time.time()).ljust(18, "0")
    end = ""
    #if resp.len != 0:
    if resp.len >= 0:
       # custom length requested in the response? print message at the end
       if proto == "tcp":
          end = " (LEN:" + str(resp.len) + ")"
       else:
          end = " (Use LEN only in TCP!)"
    try:
       print("%s | %s %s %s | (%s) %s%s" % (stamp, req.info, req.type_str, req.full_domain, req.customlog, m, end))
    except:
       print("%s | %s %s %s | %s%s" % (stamp, req.info, req.type_str, req.full_domain, m, end))

################################
# Add custom message to the message on the console

def addcustomlog(m):
    try:
        req.customlog += "," + m
    except AttributeError:
        req.customlog = m

################################
# Send buffer with DNS message (TCP and UDP)

def send_buf(self, buffer, totallen = 0):
   print("      Sending:", buffer) if debug else True
   print("        Sleep:", resp.sleep) if debug else True
   print("  Orig length:", len(buffer)) if debug else True
   print("Custom length:", resp.len) if debug else True
   time.sleep(resp.sleep)

   append = b''
   if hasattr(resp, "addbyte"):
      append = os.urandom(resp.addcount) if resp.addbyte == "r" else bytes([resp.addbyte] * resp.addcount)

   newlen = len(buffer) - getattr(resp, 'cutcount', 0)
   newbuffer = buffer[:max(newlen, 0)] + append

   # UDP mode
   if proto == "udp":
      self.wfile.write(newbuffer)
      self.wfile.flush()
      return

   # TCP mode
   # In TCP mode, we need to prepend the packet with a 2-byte length field.
   # The length can be determined by one of the following methods:
   #  - Overridden length specified by the '.lenXXX.' modifier in the domain name
   #  - Overridden length provided as a parameter to this function
   #  - Calculated from the buffer length if neither of the above is provided
   if resp.len >= 0:
      buflen = resp.len
   else:
      buflen = totallen or len(buffer)

   if hasattr(resp, "cutcount"):
      buflen -= resp.rl * resp.cutcount  # adjust the length
   if hasattr(resp, "addbyte"):
      buflen += resp.rl * resp.addcount  # adjust the length
   try:
      if hasattr(resp, "chunked"):
         send_buf_chunked(self, struct.pack(">H", buflen) + newbuffer)
      else:
         self.request.sendall(struct.pack(">H", buflen) + newbuffer)
   except Exception as e:
       print(f"Error sending buffer: {e}")
       return(-1)

################################
# Send buffer chunked (TCP only).
# The buffer is expected to contain the length at the beginning

def send_buf_chunked(self, buffer):
   for i in range(0, len(buffer), resp.chunked):
      chunk = buffer[i:i + resp.chunked]
      print("Sending:", chunk) if debug else True
      time.sleep(resp.sleep)
      self.request.sendall(chunk)

################################
# Send buffer without length (TCP only)

def send_buf_wo_len(self, buffer):
   print("Sending:", buffer) if debug else True
   time.sleep(resp.sleep)
   try:
       self.request.sendall(buffer)
   except:
       return(-1)

################################
# Close connection

def close_conn(self):
   if proto == "tcp":
      # send proper FIN immediately
      self.request.close()
   else:
      # In UDP this will just send nothing and close the socket.
      # Nothing will be sent out.
      self.rfile.close()
      self.wfile.close()
      # Consider sending ICMP port unreachable packet instead, but this is
      # non-trivial to implement

################################
# Timeout the connection

def timeout_conn(self):
   if proto == "tcp":
      # Not possible to just abandon the TCP connections using socketserver.
      # Workaround below:
      # Wait 20 seconds and then close the socket gracefully (a resolver or
      # a client will unlikely wait 20 seconds for an answer) 
      time.sleep(20)
      self.finish()
   else:
      # In UDP this will just send nothing and close the socket.
      # Nothing will be sent out.
      self.rfile.close()
      self.wfile.close()
 
################################
# Function to get a sample random data appropriate to the record type

def getRandomDataOfType(thetype):
    databin = b''
    if thetype == 1:
        # send random IP address
        data = '.'.join(str(random.getrandbits(8)) for _ in range(4))
        databin = socket.inet_aton(data)
        # send random hostname
    elif thetype in (0, 2, 3, 4, 5, 7, 8, 9, 25):
        data = "hello." + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(int(25))) + ".com"
        databin = convDom2Bin(data)
    elif thetype == 16:
        # send some random data
        data = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(int(253)))
        databin = convData2Bin(data)
    elif thetype == 6:
        # SOA
        # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.13
        pass
    elif thetype == 21:
        # RT / Route Through
        # https://www.rfc-editor.org/rfc/rfc1183#section-3.3
        pass
    else:
        data = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(int(253)))
        databin = convData2Bin(data)

    return databin

################################

def prep_dns_header(flags, qurr, anrr, aurr, adrr):
    # Here we build the DNS header using the default values provided
    # via the above parameters. But, if these were requested to be
    # overriden (via the flgsXXX, qurrXXX, anrrXXX, aurrXXX or adrrXXX
    # modifiers), then they will be overriden here and a custom DNS
    # header will be constructed according to the user's specs.

    # custom flags
    try: resp.FLGS
    except AttributeError: resp.FLGS = flags

    # custom number of Questions
    try: resp.QURR
    except AttributeError: resp.QURR = qurr

    # custom number of Answer RRs
    try: resp.ANRR
    except AttributeError: resp.ANRR = anrr

    # custom number of Authority RRs
    try: resp.AURR
    except AttributeError: resp.AURR = aurr

    # custom number of Additional RRs
    try: resp.ADRR
    except AttributeError: resp.ADRR = adrr

    # construct the DNS header
    buffer = resp.ID
    buffer += resp.FLGS
    buffer += struct.pack(">H", resp.QURR)
    buffer += struct.pack(">H", resp.ANRR)
    buffer += struct.pack(">H", resp.AURR)
    buffer += struct.pack(">H", resp.ADRR)

    # give the DNS header to the caller
    return buffer
 
################################
# Thread functions

class MyUDPHandler(socketserver.DatagramRequestHandler):
    def handle(self):
        req.RAW = self.request[0]
        if len(req.RAW) < 12:
           # packet too short
           return
        process_DNS(self, req)
    # override the finish function of the socketserver, because it throws an exception
    # when we want to close the UDP connection without sending anything
    def finish(self):
       try:
         super().finish()
       except ValueError:
         pass

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        req.RAW = self.request.recv(1024)
        if len(req.RAW) < 14:
           # packet too short
           return
        req.len = req.RAW[0:2]
        req.RAW = req.RAW[2:]
        process_DNS(self, req)

################################
# Process DNS packet

def process_DNS(self, req):
        req.HEX = binascii.b2a_hex(req.RAW) if debug else True
        print("Request (RAW):", proto, req.RAW) if debug else True
        print("Request (HEX):", proto, req.HEX) if debug else True

        ##################################
        # Make a nice client IP/name string for logging on the console
        try:
            # try replace the client IP string with a name if we know this client
            sender_label = known_servers[self.client_address[0]]
        except:
            # if we don't know this client IP, just put the IP address then
            sender_label = self.client_address[0]
        # finally, make the nice client string
        req.info = format(proto) + "://" + sender_label + ":" + \
                   format(self.client_address[1]) + " " + \
                   binascii.hexlify(req.RAW[0:2]).decode('ascii')
        #      proto://ip-address:port id
        # e.g. tcp://54.166.138.71:59965 09b5

        #print("thread id: %d" % (threading.get_ident()))
        ##################################
        # 1. Parse the DNS request, the flags, number of records and the question domain name

        req.ID    = req.RAW[0:2]
        req.FLAGS = req.RAW[2:4]
        req.QURR  = int.from_bytes(req.RAW[4:6], 'big')
        req.ANRR  = int.from_bytes(req.RAW[6:8], 'big')
        req.AURR  = int.from_bytes(req.RAW[8:10], 'big')
        req.ADRR  = int.from_bytes(req.RAW[10:12], 'big')

        # decode the domain name in the question
        req.subdomains = []    # sOMeThINg whaTEVeR ANytHinG cOM
        req.subdomains_lc = [] # something whatever anything com
        req.full_domain = ""   # sOMeThINg.whaTEVeR.ANytHinG.cOM
        offset = 12
        try:
           while True:
               size = int.from_bytes(req.RAW[offset:offset+1], 'big')
               if size == 0:
                  offset += 1
                  break
               label = req.RAW[offset+1:offset+1+size].decode('utf-8', 'backslashreplace')
               label = label.replace(".", "<DOT>")
               print("size: %d, label: %s" % (size, label)) if debug else True
               req.subdomains.append(label)
               req.subdomains_lc.append(label.lower())
               if offset == 12:
                 req.full_domain = label
               else:
                 req.full_domain += "." + label
               offset += size + 1
        except:
           stamp = str(time.time()).ljust(18, "0")
           print("%s | %s ? ? | ERROR: Cannot parse query name | (len: %d) %s" % (stamp, req.info, len(req.RAW)+2, binascii.b2a_hex(req.RAW)))
           return

        try:
            req.first_subdomain = req.subdomains_lc[0]  # something
        except:
            # someone is asking for the root e.g., for the root name servers, where the requested domain name is just empty
            req.first_subdomain = ""

        try:
            req.type_bin = req.RAW[offset:offset+2]
            req.type_int = struct.unpack(">H", req.type_bin)[0]
            req.type_str = getTypeName(req.type_int)

            req.class_bin = req.RAW[offset+2:offset+4]
            req.class_int = struct.unpack(">H", req.class_bin)[0]
            req.class_str = getClassName(req.class_int)
        except:
           stamp = str(time.time()).ljust(18, "0")
           print("%s | %s ? %s | ERROR: Cannot parse query | (len: %d) %s" % (stamp, req.info, req.full_domain.strip(), len(req.RAW)+2, binascii.b2a_hex(req.RAW)))
           return

        print("Request from %s %s %s" % (req.info, req.type_str, req.full_domain)) if debug else True

        ###############################################
        # 2. Parse out also the EDNS0 and its OPT pseudo-section with dnssec flag and cookies

        if config_parse_edns0 and req.ADRR == 1:
            offset += 4
            req.edns_opt_opt_client_cookie = b''
            req.edns_opt_opt_server_cookie = b''
            
            # Extract EDNS0 fields
            req.edns_opt_name  = int.from_bytes(req.RAW[offset:offset+1], 'big')    # 1 byte
            req.edns_opt_type  = int.from_bytes(req.RAW[offset+1:offset+3], 'big')  # 2 bytes
            req.edns_opt_size  = int.from_bytes(req.RAW[offset+3:offset+5], 'big')  # 2 bytes
            req.edns_opt_rcode = int.from_bytes(req.RAW[offset+5:offset+6], 'big')  # 1 byte
            req.edns_opt_ver   = int.from_bytes(req.RAW[offset+6:offset+7], 'big')  # 1 byte
            req.edns_opt_z     = int.from_bytes(req.RAW[offset+7:offset+9], 'big')  # 2 bytes
            req.edns_opt_len   = int.from_bytes(req.RAW[offset+9:offset+11], 'big') # 2 bytes
            
            # Ensure that there are enough bytes left for the next part of parsing
            if len(req.RAW) < offset + 11 + req.edns_opt_len:
                raise ValueError("Insufficient data in EDNS0 section")
            
            # Extract EDNS0 option fields
            req.edns_opt_opt_code = int.from_bytes(req.RAW[offset+11:offset+13], 'big') # 2 bytes
            req.edns_opt_opt_len  = int.from_bytes(req.RAW[offset+13:offset+15], 'big') # 2 bytes

            req.edns_opt_z_do = req.edns_opt_z >> 15  # dnssec
            
            if req.edns_opt_opt_code == 10:  # Check for DNS COOKIE option code
                if req.edns_opt_opt_len >= 8:  # Ensure the client cookie length is valid
                    # 8 bytes for the client cookie
                    req.edns_opt_opt_client_cookie = req.RAW[offset+15:offset+23]
                    if req.edns_opt_opt_len > 8:
                        # Remaining bytes for the server cookie
                        req.edns_opt_opt_server_cookie = req.RAW[offset+23:offset+23+(req.edns_opt_opt_len-8)]
                else:
                    raise ValueError("Invalid client cookie length")

            print("client cookie:", req.edns_opt_opt_client_cookie.hex()) if debug else True
            print("server cookie:", req.edns_opt_opt_server_cookie.hex()) if debug else True
            print("dnssec:", req.edns_opt_z_do) if debug else True

        ###############################################
        # 3. Extract SLD+TLD to see later if we are authoritative or not

        try:
            req.sld = req.subdomains_lc[int(len(req.subdomains_lc)-2)]  # anything
            req.tld = req.subdomains_lc[int(len(req.subdomains_lc)-1)]  # com
        except:
            req.sld = ""
            req.tld = ""
        req.sld_tld_domain = req.sld + "." + req.tld  # anything.com
        print("SLD + TLD:", req.sld_tld_domain) if debug else True

        ###############################################
        # 3. Check for global modifiers here which can influence how we respond.
        # These modifiers can come in the requested domain name in any position as a separate subdomain.
         
        # Supported global modifiers are:
        #  slp   - delay before responding (in miliseconds) e.g.:
        #          .slp1000.(1 second delay)
        #  ttl   - set specific TTL value for this response e.g.:
        #          .ttl3600. (1 hour TTL)
        #  len   - in TCP mode set arbitrary length value in the 
        #          beginning of the packet e.g.: .len123.
        #  newid - generate a new random transaction ID in the response
        #  noq   - remove the question section from the response body
        #          (!not the DNS header!, see qurr below)
        #  tc    - in UDP mode respond with truncated bit set so that the
        #          client/server will retry with TCP
        #  fc    - force compression
        #  nc    - no compression
        #  flgs  - set custom flags, either in hex (0x????) or in decimal
        #          (0-65535) or rand to generate random, e.g.: .flgsrand.
        #  nfz   - enable name fuzzer which can generate various illegal
        #          and malformed domain names
        #  cut   - cut N bytes from the end of the packet e.g.: .cut10.
        #  add   - add N bytes to the end of the packet e.g.: .add10.byte.
        #  rl    - recalculate length in TCP ('cut' and 'add' modifiers)
        #  qurr  - set custom number of Questions in the DNS header
        #  anrr  - set custom number of Answer RRs in the DNS header
        #  aurr  - set custom number of Authority RRs in the DNS header
        #  adrr  - set custom number of Additional RRs in the DNS header

        resp.compress = config_compression
        resp.sleep = config_sleep
        resp.TTL = config_ttl
        resp.len = -1
        resp.rl = 0  # recalculate length in TCP (in case cut/add is used)
        resp.noq = req.QURR # number of questions
        resp.QURR = req.QURR # number of questions

        resp.ID = req.ID # naturaly, set the ID in the response to the same ID as in the query, but
                         # keep in mind that a new random ID can be generated via the 'newid' global modifier

        # Check if any domain label starts with any of the global modifiers
        # Is there custom sleep (".slpXXXX.") or custom TTL (".ttlXXX.") or custom length (".lenXXX.") in the domain name?
        for index, label in enumerate(req.subdomains_lc):
            #######################
            if label.startswith("slp"):        # custom delay requested
               if label[3:].isnumeric():
                  resp.sleep = float(int(label[3:])/1000)
                  addcustomlog("SLP:" + str(resp.sleep))
            #######################
            elif label.startswith("ttl"):      # custom TTL requested
               if label[3:].isnumeric():
                  resp.TTL = int(label[3:])
                  addcustomlog("TTL:" + str(resp.TTL))
            #######################
            elif label.startswith("len"):      # TCP length override
               if label[3:].isnumeric():
                  resp.len = min(int(label[3:]), 65535)
                  addcustomlog("LEN:" + str(resp.len))
            #######################
            elif label == "newid":             # new random transaction ID
               resp.ID = struct.pack(">H", random.getrandbits(16))
               addcustomlog("NEWID")
            #######################
            elif label.startswith("flgs"):     # set custom flags in the DNS header
               flgs = label[4:]
               if flgs.isnumeric():
                  resp.FLGS = struct.pack(">H", min(int(flgs), 65535))
               elif flgs[:2] == "0x":
                  resp.FLGS = struct.pack(">H", min(int(flgs[2:], base=16), 65535))
               elif flgs == "r":
                  resp.FLGS = struct.pack(">H", random.getrandbits(16))
               addcustomlog("FLGS:" + flgs)
            #######################
            elif label.startswith("qurr"):     # set custom number of questions in the DNS header
               if label[4:].isnumeric():
                  resp.QURR = min(int(label[4:]), 65535)
                  addcustomlog("QURR:" + str(resp.QURR))
            #######################
            elif label.startswith("anrr"):     # set custom number of answer RR in the DNS header
               if label[4:].isnumeric():
                  resp.ANRR = min(int(label[4:]), 65535)
                  addcustomlog("ANRR:" + str(resp.ANRR))
            #######################
            elif label.startswith("aurr"):     # set custom number of authority RR in the DNS header
               if label[4:].isnumeric():
                  resp.AURR = min(int(label[4:]), 65535)
                  addcustomlog("AURR:" + str(resp.AURR))
            #######################
            elif label.startswith("adrr"):     # set custom number of additional RR in the DNS header
               if label[4:].isnumeric():
                  resp.ADRR = min(int(label[4:]), 65535)
                  addcustomlog("ADRR:" + str(resp.ADRR))
            #######################
            elif label == "noq":               # remove the question from the response query section
               resp.noq = 0
               addcustomlog("NOQ")
            #######################
            elif label.startswith("nfz"):      # enable name fuzzer
               if label[3:].isnumeric():
                  resp.nfz = min(int(label[3:]), 19)    # the variant
                  resp.nfz_pos = getattr(resp, 'nfz_pos', 0)                   # default position
                  resp.nfz_subs = getattr(resp, 'nfz_subs', 1)                 # default number of subdomains
                  resp.nfz_malf = getattr(resp, 'nfz_malf', 0)                 # default malformation
                  resp.nfz_malf_size = getattr(resp, 'nfz_malf_size', 1)       # default malformation size
                  resp.nfz_byte_iterator = 0   # to make sure we keep track of values from \x00 to \xff
                  addcustomlog("NFZ:" + str(resp.nfz))
            # # # # # # # # # # # #
            elif label.startswith("s"):        # number of subdomains
               if label[1:].isnumeric():
                  resp.nfz_subs = min(int(label[1:]), 65535)
                  addcustomlog("S:" + str(resp.nfz_subs))
            # # # # # # # # # # # #
            elif label.startswith("m"):        # malformation
               if label[1:].isnumeric():
                  resp.nfz_malf = min(int(label[1:]), 9)
                  resp.nfz_malf_size = getattr(resp, 'nfz_malf_size', 1)       # default malformation size
                  resp.nfz_malf_byte = getattr(resp, 'nfz_malf_byte', b'\x00') # default malformation custom byte
                  resp.nfz_pos = getattr(resp, 'nfz_pos', 0)                   # default position
                  if req.subdomains[index+1].isnumeric() and req.subdomains[index+2].isnumeric():
                     # the next 2 subdomains contain only numbers, which can only be size and byte for malformation 9
                     resp.nfz_malf_size = min(int(req.subdomains[index+1]), 65535)
                     resp.nfz_malf_byte = min(int(req.subdomains[index+2]), 255)
                     addcustomlog("M:" + str(resp.nfz_malf) + "." + str(resp.nfz_malf_byte) + "." + str(resp.nfz_malf_size))
                     resp.nfz_malf_byte = resp.nfz_malf_byte.to_bytes(1, 'big')
                  elif req.subdomains[index+1].isnumeric():     # does the next subdomain contain only a number?
                     resp.nfz_malf_size = int(req.subdomains[index+1])  # if yes, then it is the size
                     addcustomlog("M:" + str(resp.nfz_malf) + "." + str(resp.nfz_malf_size))
                  else:
                     addcustomlog("M:" + str(resp.nfz_malf))
            # # # # # # # # # # # #
            elif label.startswith("p"):        # position
               if label[1:].isnumeric():
                  resp.nfz_pos = min(int(label[1:]), 12)
                  addcustomlog("P:" + str(resp.nfz_pos))
            #######################
            elif label == "nc":                # no compression
               resp.compress = 0
               addcustomlog("NC")
            #######################
            elif label == "fc":                # force compression
               resp.compress = 1
               addcustomlog("FC")
            #######################
            elif label.startswith("cut"):      # cut N bytes from the end of the packet
               if label[3:].isnumeric():
                  resp.cutcount = int(label[3:])
                  addcustomlog("CUT:" + str(resp.cutcount))
            #######################
            elif label.startswith("cnk"):      # send in N bytes long chunks
               if label[3:].isnumeric():
                  resp.chunked = int(label[3:])
                  addcustomlog("CHUNKED:" + str(resp.chunked))
            #######################
            elif label.startswith("add"):  # add N bytes to the end of the packet
               if label[3:].isnumeric():
                  resp.addcount = int(label[3:]) if label[3:].isnumeric() else 0
                  next_subdom = req.subdomains[index+1]
                  if next_subdom.isnumeric():
                     resp.addbyte = min(int(next_subdom), 255)
                  elif next_subdom.startswith("0x"):
                     resp.addbyte = min(int(next_subdom[2:], 16), 255)
                  else:
                     resp.addbyte = "r"
                  addcustomlog("ADD:" + str(resp.addcount) + "." + str(resp.addbyte))
            #######################
            elif label == "rl":                # recalculate length in TCP
               resp.rl = 1                     # in case 'cut' or 'add' was used
               addcustomlog("RL")
            #######################
            # DO NOT REMOVE (additional modifiers)
            #######################
            elif label == "tc" and proto == "udp": # request truncation
               # In UDP let's send only empty response with Truncated flag set.
               # This will prompt server/client to retry using TCP.
               buffer = prep_dns_header(b'\x87\x00', req.QURR, 0, 0, 0)
               if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
               log("only a header with truncated flag (TC)")
               send_buf(self, buffer)
               return

        ###############################################
        # 4. The main logical functionality starts here where it is possible to respond in a custom way to any specific query.
        # In every if/elsif branch we craft the response and send it out back to the client.
         
        # First check if we are authoritative for the requested domain

        #####################################################################
        if req.type_str == "NS" and (req.sld_tld_domain == "." or req.sld_tld_domain not in OURDOMAINS):
           # Asking for the root nameservers or some other nameservers for a domain we are not authoritative for
           # dig . @127.0.0.1 NS +noedns
           # #########################
           # 1) Close the connection
           # todo: send proper response
           log("just closing connection")
           time.sleep(resp.sleep)
           close_conn(self)
        #####################################################################
        elif req.sld_tld_domain not in OURDOMAINS and req.tld != "arpa":
           # We are NOT authoritative, send Refused
           log("Refused")
           ### DNS header ########
           # Response, Non-Authoritative, Refused
           buffer = prep_dns_header(b'\x80\x05', req.QURR, 0, 0, 0)
           ### QUESTION SECTION ########
           if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
           # no answer section, only send out the header
           send_buf(self, buffer)
        #####################################################################
        else: # We are authoritative
           if ZONEFILE.get(req.full_domain.lower()) != None:
              # We have the domain in the zone file, so let's try to return proper record
              # Check if we have such record in our zone file for the domain
              if req.type_str not in ZONEFILE[req.full_domain.lower()]:
                 # We don't have this record, so let's respond with NXDOMAIN
                 buffer = prep_dns_header(b'\x84\x03', req.QURR, 0, 0, 0)
                 if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
                 send_buf(self, buffer)
                 log("NXDOMAIN")
                 return
              ans = ZONEFILE[req.full_domain.lower()][req.type_str]
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += req.type_bin + req.class_bin
              buffer += struct.pack(">L", resp.TTL)     ## TTL
              # # ################################### # #
              if req.type_str == "A":
                 size = 4
                 data = socket.inet_aton(ans)           ## IP
              # # # # # # # # # # # # # # # # # # # # # #
              elif req.type_str == "MX":
                 tmp = ans.split()
                 data = struct.pack(">H", int(tmp[0]))  ## preference
                 data += convDom2Bin(tmp[1])            ## mail server
                 size = len(tmp[1])+4
              # # # # # # # # # # # # # # # # # # # # # #
              elif req.type_str == "TXT":
                 size = len(ans)+1
                 data = convData2Bin(ans)               ## TXT record
              # # # # # # # # # # # # # # # # # # # # # #
              elif req.type_str == "SOA":
                 tmp = ans.split()                      ## SOA record
                 data = convDom2Bin(tmp[0])             ## Primary NS
                 data += convDom2Bin(tmp[1])            ## Primary contact
                 data += struct.pack(">L", int(tmp[2])) ## Serial
                 data += struct.pack(">L", int(tmp[3])) ## Zone refresh timer
                 data += struct.pack(">L", int(tmp[4])) ## Failed refresh retry timer
                 data += struct.pack(">L", int(tmp[5])) ## Zone expiry timer
                 data += struct.pack(">L", int(tmp[6])) ## Minimum TTL
                 size = len(data)
              # # # # # # # # # # # # # # # # # # # # # #
              else:
                 size = len(ans)+2
                 data = convDom2Bin(ans)
              # # ################################### # #
              buffer += struct.pack(">H", size)        ## Data length
              buffer += data                           ## The data
              log("%s %s" % (req.type_str, ans))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("always") or req.first_subdomain.startswith("something"):
              # Always resolve what starts with always or something
              ip = ""
              data = b''
              resp.type_str = ""
              if req.type_str == "AAAA":
                 resp.type_str = "AAAA"
                 ip = "1111:2222:3333:4444:5555:6666:7777:8888"
                 data  = struct.pack(">H", 16)                 ## Data length
                 data += socket.inet_pton(socket.AF_INET6, ip) ## IP
              else:
                 ip = "2.3.4.5"
                 resp.type_str = "A"
                 data  = struct.pack(">H", 4)      ## Data length
                 data += socket.inet_aton(ip)      ## IP
              answers = int(req.subdomains[1]) if req.subdomains[1].isnumeric() else 1
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', resp.QURR, answers, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # A or AAAA
              for i in range(answers):
                 if hasattr(resp, "nfz"):
                    buffer += name_fuzz(resp.nfz)
                 else:
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                 buffer += getTypeBin(resp.type_str) + getClassBin("IN")
                 buffer += struct.pack(">L", resp.TTL)    ## TTL
                 buffer += data
              # log and send
              log("%s %s" % (resp.type_str, ip))
              send_buf(self, buffer)
              #####################################################################
           elif req.full_domain == "version.polar" and req.type_str == "TXT" and req.class_str == "CH":
              # Version
              v = "PolarDNS " + polardns_version
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # A
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("TXT") + getClassBin("CH")
              buffer += struct.pack(">L", resp.TTL)         ## TTL
              buffer += struct.pack(">H", len(v)+1)         ## Data length
              buffer += convData2Bin(v.replace(".", "<DOT>"))
              # log and send
              log("Version %s" % (v))
              send_buf(self, buffer)
           # DO NOT REMOVE (additional features)
           else:
              # Otherwise send not found (NXDOMAIN)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x03', req.QURR, 0, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              # log and send empty answer
              log("NXDOMAIN")
              send_buf(self, buffer)
              #####################################################################

################################
# main()

def add_modules_and_rerun():
    # 1) Make a fresh copy of this script
    # 2) Add all the modules' code snippets into it
    # 3) Run the new script
    script_name = os.path.basename(__file__)
    new_script_name = script_name.replace('.py', '_real.py')
    
    with open(__file__, 'r') as original_file, open(new_script_name, 'w') as new_file:
        for line in original_file:
            # Add modules
            if line.strip().endswith("# DO NOT REMOVE (additional features)"):
                # Load additional features from *.toml files (modules) and
                # insert them to the new file with proper indentation
                desired_indent = len(line) - len(line.lstrip())
                modules_pattern = os.path.join('modules', '*.toml')
                modules_files = glob.glob(modules_pattern)
                for mod_file in sorted(modules_files):
                    print("loading", mod_file) if debug else True
                    with open(mod_file, "rb") as mf:
                        mod = tomllib.load(mf)
                        try:
                            mod_lines = mod['module']['code']['python'].splitlines()
                        except:
                            continue
                        mod_indent = len(mod_lines[0]) - len(mod_lines[0].lstrip())
                        if mod_lines[0].strip().startswith("if"):
                            # if the first line starts with "if", change it to "elif"
                            mod_lines[0] = ' ' * mod_indent + 'elif' + mod_lines[0].lstrip()[2:]
                        # now, write each line of the module code with the correct indentation
                        if mod_indent > desired_indent:
                           torm = mod_indent-desired_indent
                           fixed_code = '\n'.join([line[torm:] for line in mod_lines])
                        else:
                           indent = desired_indent - mod_indent
                           fixed_code = '\n'.join([' ' * indent + line for line in mod_lines])
                        # optimize the printing of debug messages
                        if fixed_code.strip().endswith(" if debug else True"):
                            fixed_code = fixed_code.replace(" if debug else True", " # debug") # remove the debug conditions
                            if not debug:
                               indent = len(fixed_code) - len(fixed_code.lstrip())
                               fixed_code = fixed_code[:indent] + "#" + fixed_code[indent:] # comment out the debug messages
                        new_file.write(fixed_code + '\n')
            # optimize the printing of debug messages
            elif line.strip().endswith(" if debug else True"):
                line = line.replace(" if debug else True", " # debug") # remove the debug conditions
                if not debug:
                   indent = len(line) - len(line.lstrip())
                   line = line[:indent] + "#" + line[indent:] # comment out the debug messages
            new_file.write(line)

    # Replace the current process with the new script, passing all arguments
    os.execvp(sys.executable, [sys.executable, "-u", new_script_name] + sys.argv[1:])

################################

if __name__ == "__main__":
   if not sys.argv[0].endswith("_real.py"):
      add_modules_and_rerun() 
      exit(0)

   print("%s | PolarDNS v%s server starting up" % (stamp, polardns_version))
   ip, sep, port = config['listen_addr'].rpartition(':')
   assert sep
   ip = str(ip)
   port = int(port)
   ServerAddress = (ip, port)

   # fork for TCP and UDP listeners
   pid = os.fork()
   stamp = str(time.time()).ljust(18, "0")

   # each socketserver thread will have 2 global objects:
   req = threading.local()   # the DNS request that we have received
   resp = threading.local()  # the DNS response we will send out

   if pid > 0:
      proto = "tcp"
      print("%s | Starting listener at %s://%s:%s" % (stamp, proto, ip, port))
      TCPServerObject = None
      try:
          socketserver.TCPServer.allow_reuse_address = True
          TCPServerObject = socketserver.ThreadingTCPServer(ServerAddress, MyTCPHandler)
          TCPServerObject.serve_forever()
      except KeyboardInterrupt:
          stamp = str(time.time()).ljust(18, "0")
          print("%s | Server is shutting down" % (stamp))
      except Exception as e:
          stamp = str(time.time()).ljust(18, "0")
          print("%s | An error occured: %s" % (stamp, e))
      if TCPServerObject:
          TCPServerObject.shutdown()
          TCPServerObject.server_close()
   else:
      proto = "udp"
      print("%s | Starting listener at %s://%s:%s" % (stamp, proto, ip, port))
      UDPServerObject = None
      try:
          UDPServerObject = socketserver.ThreadingUDPServer(ServerAddress, MyUDPHandler)
          UDPServerObject.serve_forever()
      except KeyboardInterrupt:
          stamp = str(time.time()).ljust(18, "0")
          print("%s | Server is shutting down" % (stamp))
      except Exception as e:
          stamp = str(time.time()).ljust(18, "0")
          print("%s | An error occured: %s" % (stamp, e))
      if UDPServerObject:
          UDPServerObject.shutdown()
          UDPServerObject.server_close()
      print("Exiting..")

