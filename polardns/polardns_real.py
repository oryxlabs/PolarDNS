import sys
MIN_VERSION = (3, 11) # required minimal Python version
if sys.version_info < MIN_VERSION:
    sys.exit(f"Python version {'.'.join(map(str, MIN_VERSION))} or later is required.")

import importlib.resources
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
from polardns import nfz
from polardns import consts

polardns_version = "1.6.1"

################################

# load config
config_file = importlib.resources.files("polardns") / "polardns.toml"
with config_file.open("rb") as f:
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

# Function to get DNS class name (string) from code (int)
def getClassName(q):
    for key, val in consts.DNSCLASS.items():
        if val == q:
            return key
    return "None"

# Function to get DNS class code (int) from name (string)
def getClassCode(q):
    return consts.DNSCLASS.get(q)

# Function to get binary DNS class from name (string)
def getClassBin(q):
    code = consts.DNSCLASS.get(q)
    return struct.pack(">H", code)

# Create a reverse dictionary of DNS types so that look ups are very fast
DNSTYPER = {}
for key, val in consts.DNSTYPE.items():
    DNSTYPER[val] = key

# Function to get DNS type name (string) from code (int)
def getTypeName(q):
    return DNSTYPER.get(q)

# Function to get DNS type code (int) from name (string)
def getTypeCode(q):
    return consts.DNSTYPE.get(q)

# Function to get binary DNS type from name (string)
def getTypeBin(q):
    code = consts.DNSTYPE.get(q)
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

   #print("new domain name:", new_domain_name) # debug
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

   #print("new domain name:", new_domain_name) # debug
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
   #print("      Sending:", buffer) # debug
   #print("        Sleep:", resp.sleep) # debug
   #print("  Orig length:", len(buffer)) # debug
   #print("Custom length:", resp.len) # debug
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
      #print("Sending:", chunk) # debug
      time.sleep(resp.sleep)
      self.request.sendall(chunk)

################################
# Send buffer without length (TCP only)

def send_buf_wo_len(self, buffer):
   #print("Sending:", buffer) # debug
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
        #req.HEX = binascii.b2a_hex(req.RAW) # debug
        #print("Request (RAW):", proto, req.RAW) # debug
        #print("Request (HEX):", proto, req.HEX) # debug

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
               #print("size: %d, label: %s" % (size, label)) # debug
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

        #print("Request from %s %s %s" % (req.info, req.type_str, req.full_domain)) # debug

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

            #print("client cookie:", req.edns_opt_opt_client_cookie.hex()) # debug
            #print("server cookie:", req.edns_opt_opt_server_cookie.hex()) # debug
            #print("dnssec:", req.edns_opt_z_do) # debug

        ###############################################
        # 3. Extract SLD+TLD to see later if we are authoritative or not

        try:
            req.sld = req.subdomains_lc[int(len(req.subdomains_lc)-2)]  # anything
            req.tld = req.subdomains_lc[int(len(req.subdomains_lc)-1)]  # com
        except:
            req.sld = ""
            req.tld = ""
        req.sld_tld_domain = req.sld + "." + req.tld  # anything.com
        #print("SLD + TLD:", req.sld_tld_domain) # debug

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
           elif req.first_subdomain.startswith("afuzz1"):
              # todo: Send A record with a slightly distorted name.
              byte = 65
              if req.subdomains[1].isnumeric():
                 byte = int(req.subdomains[1])
              if byte > 255: byte = 255
              ### DNS header #######
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              newip = "6.6.6." + str(byte)
              tmpdom = convDom2Bin(req.full_domain) # first convert to dns name notation
              newdom = tmpdom[0:3]              #  \
              newdom += struct.pack(">B", byte) #    > replace the 3rd char with chosen byte
              newdom += tmpdom[4:]              #  /
              # A
              buffer += newdom + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)               ## TTL
              buffer += struct.pack(">H", 4)                      ## Data length
              buffer += socket.inet_aton(newip)                   ## IP
              # log and send
              strdom = req.full_domain[0:2]
              strdom += "\\x%0.2x" % byte
              strdom += req.full_domain[3:]
              log("A %s -> %s" % (strdom, newip))
              send_buf(self, buffer)
           elif req.first_subdomain.startswith("afuzz2"):
              # Send many A records with a slightly distorted name. In the end, provide the correct one also
              # af<01>zz2.yourdomain.com   A   6.6.6.1
              # af<02>zz2.yourdomain.com   A   6.6.6.2
              # af<03>zz2.yourdomain.com   A   6.6.6.3
              # ...
              # af<fe>zz2.yourdomain.com   A   6.6.6.254
              # af<ff>zz2.yourdomain.com   A   6.6.6.255
              # afuzz2.yourdomain.com   A   1.2.3.4
              answers = 1
              if req.subdomains[1].isnumeric():
                 answers = int(req.subdomains[1])
              if answers > 256: answers = 256
              ### DNS header #######
              buffer = prep_dns_header(b'\x84\x00', req.QURR, answers+1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              #for b in range(1, 255):
              tmpdom = convDom2Bin(req.full_domain)
              # multiple bad A
              for b in range(1, answers+1):
                  newip = "6.6.6." + str(b-1)
                  newdom = tmpdom[0:3]
                  newdom += struct.pack(">B", b-1)
                  newdom += tmpdom[4:]
                  buffer += newdom + getTypeBin("A") + getClassBin("IN")
                  buffer += struct.pack(">L", resp.TTL)           ## TTL
                  buffer += struct.pack(">H", 4)                  ## Data length
                  buffer += socket.inet_aton(newip)               ## IP
              # good A
              buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              buffer += struct.pack(">L", resp.TTL)            ## TTL
              buffer += struct.pack(">H", 4)                   ## Data length
              buffer += socket.inet_aton("2.3.4.5")            ## IP
              # log and send
              log("%d bogus A records + legit A record" % (answers))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("alias"):
              # Send multiple random aliases in any of CNAME/DNAME/HTTPS/SVCB/SRV/MX/NS/SPF(TXT) record types
              # BEWARE: This could result in multiplication
              answers = int(req.subdomains[1]) if req.subdomains[1].isnumeric() else 1
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, answers, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              doms = []
              match req.type_str:
                 case "DNAME":
                    type = "DNAME"
                    for i in range(answers):
                        dom = name_fuzz(resp.nfz) if hasattr(resp, "nfz") else random_chain(req.full_domain)
                        bindom = convDom2Bin(dom)
                        buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                        buffer += getTypeBin("DNAME") + getClassBin("IN")
                        buffer += struct.pack(">L", resp.TTL)      ## TTL
                        buffer += struct.pack(">H", len(bindom))   ## Data length
                        buffer += bindom                           ## DNAME value
                        doms.append(dom)
                 case "HTTPS":
                    type = "HTTPS"
                    for i in range(answers):
                        dom = name_fuzz(resp.nfz) if hasattr(resp, "nfz") else random_chain(req.full_domain)
                        bindom = convDom2Bin(dom)
                        data_len = 2+len(bindom)  # SvcPriority (2 bytes) + the target name
                        buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                        buffer += getTypeBin("HTTPS") + getClassBin("IN")
                        buffer += struct.pack(">L", resp.TTL)    ## TTL
                        buffer += struct.pack(">H", data_len)    ## Data length
                        buffer += struct.pack(">H", 0)           ## SvcPriority (0 means alias mode - RFC 9460)
                        buffer += bindom                         ## TargetName
                        doms.append(dom)
                 case "SVCB":
                    type = "SVCB"
                    for i in range(answers):
                        dom = name_fuzz(resp.nfz) if hasattr(resp, "nfz") else random_chain(req.full_domain)
                        bindom = convDom2Bin(dom)
                        data_len = 2+len(bindom)  # SvcPriority (2 bytes) + the target name
                        data_len = 2+len(bindom)  # SvcPriority (2 bytes) + the target name
                        buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                        buffer += getTypeBin("SVCB") + getClassBin("IN")
                        buffer += struct.pack(">L", resp.TTL)    ## TTL
                        buffer += struct.pack(">H", data_len)    ## Data length
                        buffer += struct.pack(">H", 0)           ## SvcPriority (0 means alias mode - RFC 9460)
                        buffer += bindom                         ## TargetName
                        doms.append(dom)
                 case "SRV":
                    type = "SRV"
                    for i in range(answers):
                        dom = name_fuzz(resp.nfz) if hasattr(resp, "nfz") else random_chain(req.full_domain)
                        bindom = convDom2Bin(dom)
                        data_len = 2+len(bindom)  # SvcPriority (2 bytes) + the target name
                        port = random.getrandbits(16)
                        data_len = 2+2+2+len(bindom)  # Priority (2 bytes) + Weight (2 bytes) + Port (2 bytes) + Target domain
                        buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                        buffer += getTypeBin("SRV") + getClassBin("IN")
                        buffer += struct.pack(">L", resp.TTL)    ## TTL
                        buffer += struct.pack(">H", data_len)    ## Data length
                        buffer += struct.pack(">H", 0)           ## Priority
                        buffer += struct.pack(">H", 0)           ## Weight
                        buffer += struct.pack(">H", port)        ## Port
                        buffer += bindom                         ## TargetName
                        doms.append(dom)
                 case "MX":
                    type = "MX"
                    for i in range(answers):
                        dom = name_fuzz(resp.nfz) if hasattr(resp, "nfz") else random_chain(req.full_domain)
                        bindom = convDom2Bin(dom)
                        data_len = 2+len(bindom)  # SvcPriority (2 bytes) + the target name
                        data_len = 2+len(bindom)                 # Priority (2 bytes) + Target domain
                        buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                        buffer += getTypeBin("MX") + getClassBin("IN")
                        buffer += struct.pack(">L", resp.TTL)    ## TTL
                        buffer += struct.pack(">H", data_len)    ## Data length
                        buffer += struct.pack(">H", 0)           ## Priority
                        buffer += bindom                         ## TargetName
                        doms.append(dom)
                 case "NS":
                    type = "NS"
                    for i in range(answers):
                        dom = name_fuzz(resp.nfz) if hasattr(resp, "nfz") else random_chain(req.full_domain)
                        bindom = convDom2Bin(dom)
                        buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                        buffer += getTypeBin("NS") + getClassBin("IN")
                        buffer += struct.pack(">L", resp.TTL)      ## TTL
                        buffer += struct.pack(">H", len(bindom))   ## Data length
                        buffer += bindom                           ## NS value
                        doms.append(dom)
                 case "TXT":
                    type = "SPF(TXT)"
                    for i in range(answers):
                        dom = name_fuzz(resp.nfz) if hasattr(resp, "nfz") else random_chain(req.full_domain)
                        data = "v=spf1 include:" + dom + " ~all"
                        buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                        buffer += getTypeBin("TXT") + getClassBin("IN")
                        buffer += struct.pack(">L", resp.TTL)      ## TTL
                        buffer += struct.pack(">H", len(data)+1)   ## Data length (2B)
                        buffer += struct.pack(">B", len(data))     ## TXT length (1B)
                        buffer += data.encode("utf-8")             ## TXT SPF value
                        doms.append(dom)
                 case _:
                    type = "CNAME"
                    for i in range(answers):
                        dom = name_fuzz(resp.nfz) if hasattr(resp, "nfz") else random_chain(req.full_domain)
                        bindom = convDom2Bin(dom)
                        data_len = 2+len(bindom)  # SvcPriority (2 bytes) + the target name
                        buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                        buffer += getTypeBin("CNAME") + getClassBin("IN")
                        buffer += struct.pack(">L", resp.TTL)      ## TTL
                        buffer += struct.pack(">H", len(bindom))   ## Data length
                        buffer += bindom                           ## CNAME value
                        doms.append(dom)
              # log and send
              log("%d %s aliases: %s" % (answers, type, ', '.join(map(str, doms[:3])) + (', ...' if answers > 3 else '')))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("badcompress1"):
              # Send answer with arbitrary compression pointer in the ANSWER section in the query name
              offset = 12  # default offset is 12, which points to the domain name in the question
              if req.subdomains[1].isnumeric():
                 offset = int(req.subdomains[1])
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # CNAME
              badcomp = b"\xc0" + struct.pack(">B", offset)        ## arbitrary offset in the answer in the Name
              buffer += badcomp + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)                ## TTL
              dom = "always" + str(random.getrandbits(20) % 100000) + "." + req.sld_tld_domain
              buffer += struct.pack(">H", len(dom)+2)              ## Data length
              buffer += convDom2Bin(dom)                           ## CNAME value
              # log and send
              log("CNAME %s (badcomp 1, answer Name, offset %d)" % (dom, offset))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("badcompress2"):
              # Send answer with arbitrary compression pointer in the ANSWER section in the CNAME name
              offset = 12  # default offset is 12, which points to the domain name in the question
              if req.subdomains[1].isnumeric():
                 offset = int(req.subdomains[1])
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # CNAME
              buffer += b"\xc0\x0c" + getTypeBin("CNAME") + getClassBin("IN")  ## using compression here, no problem
              buffer += struct.pack(">L", resp.TTL)                      ## TTL
              dom = b"\x03abc" + b"\xc0" + struct.pack(">B", offset)  ## arbitrary offset in the answer in the CNAME
              buffer += struct.pack(">H", len(dom))                      ## Data length
              buffer += dom                                              ## CNAME value
              # log and send
              log("CNAME abc.%s (badcomp 2, CNAME, offset %d)" % (req.full_domain, offset))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("badcompressfwptr1"):
              # Send answer with a forward compression pointer pointing to another pointer - variant 1
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # CNAME
              offset_to_last_cname = len(req.full_domain) + 12 + 18  ## forward pointer to the CNAME in the end
              buffer += b"\xc0" + struct.pack(">B", offset_to_last_cname) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)             ## TTL
              dom = b"\x03abc" + b"\xc0\x0c"                    ## "abc" + pointer to the first domain name (in the query)
              buffer += struct.pack(">H", len(dom))             ## Data length
              buffer += dom                                     ## CNAME value
              # log and send
              log("CNAME abc.%s (badcomp with forward pointer 1)" % (req.full_domain))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("badcompressfwptr2"):
              # Send answer with a forward compression pointer pointing to another pointer - variant 2
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # CNAME
              offset_to_last_cname = len(req.full_domain) + 12 + 18 + 4 ## forward pointer to the CNAME in the end, but also
                                                                   ## skipping the "abc" portion, so it's like a small chain
              buffer += b"\xc0" + struct.pack(">B", offset_to_last_cname) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)             ## TTL
              dom = b"\x03abc" + b"\xc0\x0c"                    ## "abc" + pointer to the first domain name (in the query)
              buffer += struct.pack(">H", len(dom))             ## Data length
              buffer += dom                                     ## CNAME value
              # log and send
              log("CNAME abc.%s (badcomp with forward pointer 2)" % (req.full_domain))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("badcompressloop1"):
              # Send answer with a compression pointer loop in the Answer name - variant 1
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # CNAME
              offset_to_middle_name = len(req.full_domain) + 18   ## forward pointer to the name in the middle
              baddom = b"\xc0" + struct.pack(">B", offset_to_middle_name)
              buffer += baddom + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)                ## TTL
              dom = "always" + str(random.getrandbits(20) % 100000) + "." + req.sld_tld_domain
              buffer += struct.pack(">H", len(dom)+2)              ## Data length
              buffer += convDom2Bin(dom)                           ## CNAME value
              # log and send
              log("CNAME %s (badcomp loop 1, answer Name, <LOOP>)" % (dom))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("badcompressloop2"):
              # Send answer with a compression pointer loop in the Answer name - variant 2
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # CNAME
              offset_to_middle_name = len(req.full_domain) + 18   ## forward pointer to the name in the middle
              baddom = b"\x03abc" + b"\xc0" + struct.pack(">B", offset_to_middle_name)
              buffer += baddom + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)                ## TTL
              dom = "always" + str(random.getrandbits(20) % 100000) + "." + req.sld_tld_domain
              buffer += struct.pack(">H", len(dom)+2)              ## Data length
              buffer += convDom2Bin(dom)                           ## CNAME value
              # log and send
              log("CNAME %s (badcomp loop 2, answer Name, abc<LOOP>)" % (dom))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("badcompressloop3"):
              # Send answer with a compression pointer loop involving a forward pointer and a backward pointer
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # CNAME
              offset_to_last_cname = len(req.full_domain) + 12 + 18     ## forward pointer to the CNAME in the end
              buffer += b"\xc0" + struct.pack(">B", offset_to_last_cname) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)                ## TTL
              offset_to_middle_name = len(req.full_domain) + 18         ## backward pointer to the name in the middle
              dom = b"\x03abc" + b"\xc0" + struct.pack(">B", offset_to_middle_name)
              buffer += struct.pack(">H", len(dom))                ## Data length
              buffer += dom                                        ## CNAME value
              # log and send
              log("CNAME abc.<LOOP> (badcomp loop 3 in the answer Name and CNAME)")
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("badcompressloop4"):
              # Send answer with a compression pointer loop in the CNAME - variant 1
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # CNAME
              buffer += b"\xc0\x0c" + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)                ## TTL
              offset_to_last_cname = len(req.full_domain) + 12 + 18     ## forward pointer to the CNAME in the end
              dom = b"\xc0" + struct.pack(">B", offset_to_last_cname)
              buffer += struct.pack(">H", len(dom))                ## Data length
              buffer += dom                                        ## CNAME value with pointer to itself
              # log and send
              log("CNAME <LOOP> (badcomp loop 4 in CNAME)")
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("badcompressloop5"):
              # Send answer with a compression pointer loop in the CNAME - variant 2
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # CNAME
              buffer += b"\xc0\x0c" + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)                ## TTL
              offset_to_last_cname = len(req.full_domain) + 12 + 18     ## forward pointer to the CNAME in the end
              dom = b"\x03abc" + b"\xc0" + struct.pack(">B", offset_to_last_cname)
              buffer += struct.pack(">H", len(dom))                ## Data length
              buffer += dom                                        ## CNAME value with pointer to itself
              # log and send
              log("CNAME abc<LOOP> (badcomp loop 5 in CNAME)")
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("badcompressmid1"):
              # Send answer with a compression pointer in the CNAME in the middle, trying to
              # concatenate it with additional string
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # CNAME
              buffer += b"\xc0\x0c" + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)                ## TTL
              dom = b"\x03abc" + b"\xc0\x0c" + convDom2Bin("hello")
              buffer += struct.pack(">H", len(dom))                ## Data length
              buffer += dom                                        ## CNAME value with pointer to itself
              # log and send
              log("CNAME abc.%s.hello (bad comp mid1, appended hello)" % (req.full_domain))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("bigbintxt"):
              # Send big binary TXT record
              size = 10  # number of chunks
              if req.subdomains[1].isnumeric():
                 size = int(req.subdomains[1])
              chunksize = 255  # chunk size
              if req.subdomains[2].isnumeric():
                 chunksize = min(int(req.subdomains[2]), 255)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              data = struct.pack(">B", chunksize) + os.urandom(chunksize)
              for i in range(size-1):
                  data += struct.pack(">B", chunksize) + os.urandom(chunksize)
              # TXT
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("TXT") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)            ## TTL
              buffer += struct.pack(">H", len(data))           ## Data length
              buffer += data
              # log and send
              log("TXT with %d binary labels of %d B each (total: %d B)" % (size, chunksize, len(buffer)))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("bigtxt"):
              # Send big TXT record
              size = 10  # number of chunks
              if req.subdomains[1].isnumeric():
                 size = int(req.subdomains[1])
              chunksize = 255  # chunk size
              if req.subdomains[2].isnumeric():
                 chunksize = min(int(req.subdomains[2]), 255)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              data = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(int(chunksize)))
              for i in range(size-1):
                  data += '.' + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(int(chunksize)))
              # TXT
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("TXT") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)            ## TTL
              buffer += struct.pack(">H", len(data)+1)         ## Data length
              buffer += convData2Bin(data)
              # log and send
              log("TXT with %d labels of %d B each (total: %d B)" % (size, chunksize, len(buffer)))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("chain"):
              # Send incremented CNAME/DNAME/HTTPS/SVCB/SRV/MX/NS/SPF(TXT) alias record.
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              new_domain_name = increment_chain(req.full_domain)
              bindom = convDom2Bin(new_domain_name)
              match req.type_str:
                 case "DNAME":
                    type = "DNAME"
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin("DNAME") + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)     ## TTL
                    buffer += struct.pack(">H", len(bindom))  ## Data length
                    buffer += bindom                          ## DNAME value
                 case "HTTPS":
                    type = "HTTPS"
                    data_len = 2+len(bindom)                  # SvcPriority (2 bytes) + the target name
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin("HTTPS") + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)     ## TTL
                    buffer += struct.pack(">H", data_len)     ## Data length
                    buffer += struct.pack(">H", 0)            ## SvcPriority (0 means alias mode - RFC 9460)
                    buffer += bindom                          ## TargetName
                 case "SVCB":
                    type = "SVCB"
                    data_len = 2+len(bindom)                  # SvcPriority (2 bytes) + the target name
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin("SVCB") + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)     ## TTL
                    buffer += struct.pack(">H", data_len)     ## Data length
                    buffer += struct.pack(">H", 0)            ## SvcPriority (0 means alias mode - RFC 9460)
                    buffer += bindom                          ## TargetName
                 case "SRV":
                    type = "SRV"
                    port = random.getrandbits(16)
                    data_len = 2+2+2+len(bindom)  # Priority (2 bytes) + Weight (2 bytes) + Port (2 bytes) + Target domain
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin("SRV") + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)     ## TTL
                    buffer += struct.pack(">H", data_len)     ## Data length
                    buffer += struct.pack(">H", 0)            ## Priority
                    buffer += struct.pack(">H", 0)            ## Weight
                    buffer += struct.pack(">H", port)         ## Port
                    buffer += bindom                          ## TargetName
                 case "MX":
                    type = "MX"
                    data_len = 2+len(bindom)                  # Priority (2 bytes) + Target domain
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin("MX") + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)     ## TTL
                    buffer += struct.pack(">H", data_len)     ## Data length
                    buffer += struct.pack(">H", 0)            ## Priority
                    buffer += bindom                          ## TargetName
                 case "NS":
                    type = "NS"
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin("NS") + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)     ## TTL
                    buffer += struct.pack(">H", len(bindom))  ## Data length
                    buffer += bindom                          ## NS value
                 case "TXT":
                    type = "SPF(TXT)"
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    data = "v=spf1 include:" + new_domain_name + " ~all"
                    buffer += getTypeBin("TXT") + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)     ## TTL
                    buffer += struct.pack(">H", len(data)+1)  ## Data length (2B)
                    buffer += struct.pack(">B", len(data))    ## TXT length (1B)
                    buffer += data.encode("utf-8")            ## TXT SPF value
                 case _:
                    type = "CNAME"
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin("CNAME") + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)     ## TTL
                    buffer += struct.pack(">H", len(bindom))  ## Data length
                    buffer += bindom                          ## DNAME value
              # log and send
              log("%s %s" % (type, new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("close"):
              # Close the connection
              log("just closing connection")
              time.sleep(resp.sleep)
              close_conn(self)
              #####################################################################
           elif req.first_subdomain.startswith("cnalias"):
              # Send multiple random CNAME aliases
              # BEWARE: This could result in multiplication
              answers = int(req.subdomains[1]) if req.subdomains[1].isnumeric() else 1
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, answers, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              doms = []
              for i in range(answers):
                  # CNAME
                  dom = name_fuzz(resp.nfz) if hasattr(resp, "nfz") else random_chain(req.full_domain)
                  bindom = convDom2Bin(dom)
                  buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                  buffer += getTypeBin("CNAME") + getClassBin("IN")
                  buffer += struct.pack(">L", resp.TTL)      ## TTL
                  buffer += struct.pack(">H", len(bindom))   ## Data length
                  buffer += bindom                           ## CNAME value
                  doms.append(dom)
              # log and send
              log("%d CNAME aliases: %s" % (answers, ', '.join(map(str, doms[:3])) + (', ...' if answers > 3 else '')))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("cnchain"):
              # Send incremented CNAME alias
              new_domain_name = increment_chain(req.full_domain)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # CNAME
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)                    ## TTL
              buffer += struct.pack(">H", len(new_domain_name)+2)      ## Data length
              buffer += convDom2Bin(new_domain_name)                   ## CNAME value
              # log and send
              log("CNAME %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("cnloop"):
              # Do a CNAME loop
              if req.subdomains[1].isnumeric() and req.subdomains[2].isnumeric():
                 # we are already in a loop, e.g.:
                 # cnloop.10.4.yourdomain.com
                 max = int(req.subdomains[1])
                 cur = int(req.subdomains[2])
                 if cur >= max:
                    # go back to the beginning of the loop
                    new_domain_name = req.subdomains[0] + "." + str(max) + ".1"
                 else:
                    # increment the current index
                    new_domain_name = req.subdomains[0] + "." + str(max) + "." + str(cur+1)
                 for i in range(len(req.subdomains)-3):
                    new_domain_name += "." + req.subdomains[i+3]
              elif req.subdomains[1].isnumeric():
                 # we are in beginning of a loop with a requested max value, e.g.:
                 # cnloop.10.yourdomain.com
                 max = int(req.subdomains[1])
                 if max < 1:
                    max = 1
                 new_domain_name = req.subdomains[0] + "." + str(max) + "." + "1"
                 for i in range(len(req.subdomains)-2):
                    new_domain_name += "." + req.subdomains[i+2]
              else:
                 # just immediate loop
                 new_domain_name = req.full_domain
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # CNAME
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)                    ## TTL
              buffer += struct.pack(">H", len(new_domain_name)+2)      ## Data length
              buffer += convDom2Bin(new_domain_name)                   ## CNAME value
              # log and send
              log("CNAME LOOP %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("dnalias"):
              # Send multiple random DNAME aliases
              # BEWARE: This could result in multiplication
              answers = int(req.subdomains[1]) if req.subdomains[1].isnumeric() else 1
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, answers, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              doms = []
              for i in range(answers):
                  # DNAME
                  dom = name_fuzz(resp.nfz) if hasattr(resp, "nfz") else random_chain(req.full_domain)
                  bindom = convDom2Bin(dom)
                  buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                  buffer += getTypeBin("DNAME") + getClassBin("IN")
                  buffer += struct.pack(">L", resp.TTL)      ## TTL
                  buffer += struct.pack(">H", len(bindom))   ## Data length
                  buffer += bindom                           ## DNAME value
                  doms.append(dom)
              # log and send
              log("%d DNAME aliases: %s" % (answers, ', '.join(map(str, doms[:3])) + (', ...' if answers > 3 else '')))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("dnchain"):
              # Send incremented DNAME alias
              new_domain_name = increment_chain(req.full_domain)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # DNAME
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("DNAME") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)                    ## TTL
              buffer += struct.pack(">H", len(new_domain_name)+2)      ## Data length
              buffer += convDom2Bin(new_domain_name)                   ## DNAME value
              # log and send
              log("DNAME %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("dnloop"):
              # Do a DNAME loop
              if req.subdomains[1].isnumeric() and req.subdomains[2].isnumeric():
                 # we are already in a loop, e.g.:
                 # dnloop.10.4.yourdomain.com
                 max = int(req.subdomains[1])
                 cur = int(req.subdomains[2])
                 if cur >= max:
                    # go back to the beginning of the loop
                    new_domain_name = req.subdomains[0] + "." + str(max) + ".1"
                 else:
                    # increment the current index
                    new_domain_name = req.subdomains[0] + "." + str(max) + "." + str(cur+1)
                 for i in range(len(req.subdomains)-3):
                    new_domain_name += "." + req.subdomains[i+3]
              elif req.subdomains[1].isnumeric():
                 # we are in beginning of a loop with a requested max value, e.g.:
                 # dnloop.10.yourdomain.com
                 max = int(req.subdomains[1])
                 if max < 1:
                    max = 1
                 new_domain_name = req.subdomains[0] + "." + str(max) + "." + "1"
                 for i in range(len(req.subdomains)-2):
                    new_domain_name += "." + req.subdomains[i+2]
              else:
                 # just immediate loop
                 new_domain_name = req.full_domain
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # DNAME
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("DNAME") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)                    ## TTL
              buffer += struct.pack(">H", len(new_domain_name)+2)      ## Data length
              buffer += convDom2Bin(new_domain_name)                   ## DNAME value
              # log and send
              log("DNAME LOOP %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("empty1"):
              # Send empty packet
              log("empty packet")
              if proto == "tcp":
                 send_buf_wo_len(self, b"")
              else:
                 send_buf(self, b"")
              #####################################################################
           elif req.first_subdomain.startswith("empty2"):
              # Send arbitrary number of NULLs
              nulls = 1 # number of NULLs to send
              if req.subdomains[1].isnumeric():
                 nulls = int(req.subdomains[1])
              buffer = b"\x00" * nulls
              log("only %d NULL(s)" % (nulls))
              if proto == "tcp":
                 send_buf_wo_len(self, buffer)
              else:
                 send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("empty3"):
              # Send arbitrary number of NULLs with consideration for TCP mode.
              # In TCP there is length field in the beginning (2 bytes), so we must
              # provide proper length there
              nulls = 1 # number of NULLs to send
              if req.subdomains[1].isnumeric():
                 nulls = int(req.subdomains[1])
              buffer = b"\x00" * nulls
              if proto == "tcp":
                 log("only %d NULL(s) in TCP mode!" % (nulls))
              else:
                 log("only %d NULL(s)" % (nulls))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("empty4"):
              # Send the query ID + arbitrary number of NULLs
              nulls = 1 # number of NULLs to send
              if req.subdomains[1].isnumeric():
                 nulls = int(req.subdomains[1])
              buffer  = resp.ID
              buffer += b"\x00" * nulls
              log("only query ID and %d NULL(s)" % (nulls))
              if proto == "tcp":
                 if resp.len >= 0:
                    buffer  = struct.pack(">H", resp.len)
                    buffer += resp.ID
                    buffer += b"\x00" * nulls
                    send_buf_wo_len(self, buffer)
                 else:
                    send_buf(self, buffer)
              else:
                 send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("empty5"):
              # Send the query ID + set in DNS header that there is an ANSWER
              # + send arbitrary number of NULLs
              nulls = 1 # number of NULLs to send
              if req.subdomains[1].isnumeric():
                 nulls = int(req.subdomains[1])
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ######## - no more
              buffer += b"\x00" * nulls
              # log and send
              log("only %d NULL(s) after the DNS header" % (nulls))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("empty6"):
              # Send back a normal looking DNS response, but remove the ANSWER SECTION
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ######## - missing
              # log and send
              log("remove ANSWER section")
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("empty7"):
              # Send back a normal DNS response, but ANSWER SECTION is just NULLs
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # A                                      2                 2
              #tmp  = convDom2Bin(req.full_domain) + getTypeBin("A") + getClassBin("IN")
              #tmp += struct.pack(">L", resp.TTL)  #   4              ## TTL
              #tmp += struct.pack(">H", 4)         #   2              ## Data length
              #tmp += socket.inet_aton(ip)         #   4              ## IP
              #buffer += tmp
              buffer += b"\x00" * (len(convDom2Bin(req.full_domain)) + 14)
              # log and send
              log("replacing ANSWER section with NULLs")
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("htalias"):
              # Send multiple random HTTPS aliases (RFC 9460).
              # BEWARE: This could result in multiplication
              answers = int(req.subdomains[1]) if req.subdomains[1].isnumeric() else 1
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, answers, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              doms = []
              for i in range(answers):
                  # HTTPS alias records
                  dom = name_fuzz(resp.nfz) if hasattr(resp, "nfz") else random_chain(req.full_domain)
                  bindom = convDom2Bin(dom)
                  data_len = 2+len(bindom)  # SvcPriority (2 bytes) + the target name
                  buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                  buffer += getTypeBin("HTTPS") + getClassBin("IN")
                  buffer += struct.pack(">L", resp.TTL)    ## TTL
                  buffer += struct.pack(">H", data_len)    ## Data length
                  buffer += struct.pack(">H", 0)           ## SvcPriority (0 means alias mode - RFC 9460)
                  buffer += bindom                         ## TargetName
                  doms.append(dom)
              # log and send
              log("%d HTTPS aliases: %s" % (answers, ', '.join(map(str, doms[:3])) + (', ...' if answers > 3 else '')))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("htchain"):
              # Send incremented HTTPS alias (RFC 9460).
              new_domain_name = increment_chain(req.full_domain)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # HTTPS alias record
              bindom = convDom2Bin(new_domain_name)
              data_len = 2+len(bindom)  # SvcPriority (2 bytes) + the target name
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("HTTPS") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)    ## TTL
              buffer += struct.pack(">H", data_len)    ## Data length
              buffer += struct.pack(">H", 0)           ## SvcPriority (0 means alias mode - RFC 9460)
              buffer += bindom                         ## TargetName
              # log and send
              log("HTTPS %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("htloop"):
              # Do an alias loop in a HTTPS record (SvcPriority 0)
              if req.subdomains[1].isnumeric() and req.subdomains[2].isnumeric():
                 # we are already in a loop, e.g.:
                 # htloop.10.4.yourdomain.com
                 max = int(req.subdomains[1])
                 cur = int(req.subdomains[2])
                 if cur >= max:
                    # go back to the beginning of the loop
                    new_domain_name = req.subdomains[0] + "." + str(max) + ".1"
                 else:
                    # increment the current index
                    new_domain_name = req.subdomains[0] + "." + str(max) + "." + str(cur+1)
                 for i in range(len(req.subdomains)-3):
                    new_domain_name += "." + req.subdomains[i+3]
              elif req.subdomains[1].isnumeric():
                 # we are in beginning of a loop with a requested max value, e.g.:
                 # htloop.10.yourdomain.com
                 max = int(req.subdomains[1])
                 if max < 1:
                    max = 1
                 new_domain_name = req.subdomains[0] + "." + str(max) + "." + "1"
                 for i in range(len(req.subdomains)-2):
                    new_domain_name += "." + req.subdomains[i+2]
              else:
                 # just immediate loop
                 new_domain_name = req.full_domain
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              data_len = 2+len(convDom2Bin(new_domain_name)) # SvcPriority (2 bytes) + the target name
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("HTTPS") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)      ## TTL
              buffer += struct.pack(">H", data_len)      ## Data length
              buffer += struct.pack(">H", 0)             ## SvcPriority (0 means alias mode - RFC 9460)
              buffer += convDom2Bin(new_domain_name)     ## TargetName
              # log and send
              log("HTTPS LOOP %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("inja") and (len(req.first_subdomain) == 4 or req.first_subdomain[4:].isdigit()):
              # Send a legit record + an injected record
           
              ####################################
              # Default values of the parameters
           
              answers = 2
              reversed = 0
              allsections = 0
              addedquestions = b''
              req.inj_type_str = 'A'
           
              ####################################
              # Get all the parameters
           
              index = req.first_subdomain[4:]
           
              if "3rp" in req.subdomains:  # inject a 3rd party domain
                 injdom = "injected" + index + "." + a3rdparty_domain
                 addcustomlog("3P")
              else:
                 injdom = "injected" + index + "." + req.sld_tld_domain
           
              if "rpq" in req.subdomains:  # replace the question with our injected stuffs
                 orig_req_domain = req.full_domain
                 req.full_domain = injdom
                 req.type_bin = getTypeBin(req.inj_type_str) 
                 addcustomlog("RPQ")
           
              if "adq" in req.subdomains:  # add additional question for our injected stuffs
                 resp.QURR = req.QURR+1
                 addedquestions  = convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + req.class_bin
                 addcustomlog("ADQ")
           
              if "oi" in req.subdomains:   # only injected
                 answers = 1
                 addcustomlog("OI")
           
              if "rev" in req.subdomains:  # reversed / injected first
                 reversed = 1
                 addcustomlog("REV")
           
              if "als" in req.subdomains:  # all sections
                 allsections = 1
                 addcustomlog("ALS")
           
              ###############################
              # Now prepare the legit record based on what record type was requested in the query
           
              okdata = b''
              match req.type_str:
                case "A":
                    ip = "1.2.3.4"
                    okdata  = struct.pack(">H", 4)     ## Data length
                    okdata += socket.inet_aton(ip)     ## IP
                case "AAAA":
                    ip = "1111:2222:3333:4444:5555:6666:7777:8888"
                    okdata = struct.pack(">H", 16)                  ## Data length
                    okdata += socket.inet_pton(socket.AF_INET6, ip) ## IP
                case "PTR":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "MX":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom)+2) ## Data length
                    okdata += struct.pack(">H", 0)            ## Priority
                    okdata += bindom                          ## domain
                case "NS":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "CNAME":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "DNAME":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
           
              ###############################
              # Now prepare the injected A record
           
              injdata = b''
              injip = "6.6.6.6"
              injdata  = struct.pack(">H", 4)           ## Data length
              injdata += socket.inet_aton(injip)        ## IP
           
              ###############################
              ### DNS header ################
              if allsections:
                 buffer = prep_dns_header(b'\x84\x00', resp.QURR, answers, answers, answers)
              else:
                 buffer = prep_dns_header(b'\x84\x00', resp.QURR, answers, 0, 0)
              ###############################
              ### QUESTION SECTION ##########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              buffer += addedquestions
              ###############################
              ### ANSWER SECTION ############
              # first answer
              if "rpq" in req.subdomains:
                 req.full_domain = orig_req_domain  # switch back to the original domain
                 resp.compress = 0  # query contains the injected domain, cannot use it for compression
              if answers > 1:
                 if reversed:
                    # reversed order, first injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
                 else:
                    # normal order, first legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
              # second answer
              if reversed and answers > 1:
                 # reversed order, now legit record
                 buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                 buffer += getTypeBin(req.type_str) + getClassBin("IN")
                 buffer += struct.pack(">L", resp.TTL)
                 buffer += okdata
              else:
                 # normal order, now injected record
                 buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                 buffer += struct.pack(">L", resp.TTL)
                 buffer += injdata
              ###############################
              if allsections:
                 ### AUTHORITY SECTION #########
                 # first answer
                 if "rpq" in req.subdomains:
                    req.full_domain = orig_req_domain  # switch back to the original domain
                    resp.compress = 0  # query contains the injected domain, cannot use it for compression
                 if answers > 1:
                    if reversed:
                       # reversed order, first injected record
                       buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += injdata
                    else:
                       # normal order, first legit record
                       buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                       buffer += getTypeBin(req.type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += okdata
                 # second answer
                 if reversed and answers > 1:
                    # reversed order, now legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
                 else:
                    # normal order, now injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
                 ###############################
                 ### ADDITIONAL SECTION ########
                 # first answer
                 if "rpq" in req.subdomains:
                    req.full_domain = orig_req_domain  # switch back to the original domain
                    resp.compress = 0  # query contains the injected domain, cannot use it for compression
                 if answers > 1:
                    if reversed:
                       # reversed order, first injected record
                       buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += injdata
                    else:
                       # normal order, first legit record
                       buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                       buffer += getTypeBin(req.type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += okdata
                 # second answer
                 if reversed and answers > 1:
                    # reversed order, now legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
                 else:
                    # normal order, now injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
              ###############################
              # log and send
              log("%s + %s" % (req.type_str, req.inj_type_str))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("injaaaa") and (len(req.first_subdomain) == 7 or req.first_subdomain[7:].isdigit()):
              # Send a legit record + an injected record
           
              ####################################
              # Default values of the parameters
           
              answers = 2
              reversed = 0
              allsections = 0
              addedquestions = b''
              req.inj_type_str = 'AAAA'
           
              ####################################
              # Get all the parameters
           
              index = req.first_subdomain[7:]
           
              if "3rp" in req.subdomains:  # inject a 3rd party domain
                 injdom = "injected" + index + "." + a3rdparty_domain
                 addcustomlog("3P")
              else:
                 injdom = "injected" + index + "." + req.sld_tld_domain
           
              if "rpq" in req.subdomains:  # replace the question with our injected stuffs
                 orig_req_domain = req.full_domain
                 req.full_domain = injdom
                 req.type_bin = getTypeBin(req.inj_type_str) 
                 addcustomlog("RPQ")
           
              if "adq" in req.subdomains:  # add additional question for our injected stuffs
                 resp.QURR = req.QURR+1
                 addedquestions  = convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + req.class_bin
                 addcustomlog("ADQ")
           
              if "oi" in req.subdomains:   # only injected
                 answers = 1
                 addcustomlog("OI")
           
              if "rev" in req.subdomains:  # reversed / injected first
                 reversed = 1
                 addcustomlog("REV")
           
              if "als" in req.subdomains:  # all sections
                 allsections = 1
                 addcustomlog("ALS")
           
              ###############################
              # Now prepare the legit record based on what record type was requested in the query
           
              okdata = b''
              match req.type_str:
                case "A":
                    ip = "1.2.3.4"
                    okdata  = struct.pack(">H", 4)     ## Data length
                    okdata += socket.inet_aton(ip)     ## IP
                case "AAAA":
                    ip = "1111:2222:3333:4444:5555:6666:7777:8888"
                    okdata = struct.pack(">H", 16)                  ## Data length
                    okdata += socket.inet_pton(socket.AF_INET6, ip) ## IP
                case "PTR":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "MX":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom)+2) ## Data length
                    okdata += struct.pack(">H", 0)            ## Priority
                    okdata += bindom                          ## domain
                case "NS":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "CNAME":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "DNAME":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
           
              ###############################
              # Now prepare the injected AAAA record
           
              injdata = b''
              injip = "6666:6666:6666:6666:6666:6666:6666:6666"
              injdata = struct.pack(">H", 16)                     ## Data length
              injdata += socket.inet_pton(socket.AF_INET6, injip) ## IP
           
              ###############################
              ### DNS header ################
              if allsections:
                 buffer = prep_dns_header(b'\x84\x00', resp.QURR, answers, answers, answers)
              else:
                 buffer = prep_dns_header(b'\x84\x00', resp.QURR, answers, 0, 0)
              ###############################
              ### QUESTION SECTION ##########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              buffer += addedquestions
              ###############################
              ### ANSWER SECTION ############
              # first answer
              if "rpq" in req.subdomains:
                 req.full_domain = orig_req_domain  # switch back to the original domain
                 resp.compress = 0  # query contains the injected domain, cannot use it for compression
              if answers > 1:
                 if reversed:
                    # reversed order, first injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
                 else:
                    # normal order, first legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
              # second answer
              if reversed and answers > 1:
                 # reversed order, now legit record
                 buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                 buffer += getTypeBin(req.type_str) + getClassBin("IN")
                 buffer += struct.pack(">L", resp.TTL)
                 buffer += okdata
              else:
                 # normal order, now injected record
                 buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                 buffer += struct.pack(">L", resp.TTL)
                 buffer += injdata
              ###############################
              if allsections:
                 ### AUTHORITY SECTION #########
                 # first answer
                 if "rpq" in req.subdomains:
                    req.full_domain = orig_req_domain  # switch back to the original domain
                    resp.compress = 0  # query contains the injected domain, cannot use it for compression
                 if answers > 1:
                    if reversed:
                       # reversed order, first injected record
                       buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += injdata
                    else:
                       # normal order, first legit record
                       buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                       buffer += getTypeBin(req.type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += okdata
                 # second answer
                 if reversed and answers > 1:
                    # reversed order, now legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
                 else:
                    # normal order, now injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
                 ###############################
                 ### ADDITIONAL SECTION ########
                 # first answer
                 if "rpq" in req.subdomains:
                    req.full_domain = orig_req_domain  # switch back to the original domain
                    resp.compress = 0  # query contains the injected domain, cannot use it for compression
                 if answers > 1:
                    if reversed:
                       # reversed order, first injected record
                       buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += injdata
                    else:
                       # normal order, first legit record
                       buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                       buffer += getTypeBin(req.type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += okdata
                 # second answer
                 if reversed and answers > 1:
                    # reversed order, now legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
                 else:
                    # normal order, now injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
              ###############################
              # log and send
              log("%s + %s" % (req.type_str, req.inj_type_str))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("injcname") and (len(req.first_subdomain) == 8 or req.first_subdomain[8:].isdigit()):
              # Send a legit record + an injected record
           
              ####################################
              # Default values of the parameters
           
              answers = 2
              reversed = 0
              allsections = 0
              addedquestions = b''
              req.inj_type_str = 'CNAME'
           
              ####################################
              # Get all the parameters
           
              index = req.first_subdomain[8:]
           
              if "3rp" in req.subdomains:  # inject a 3rd party domain
                 injdom = "injected" + index + "." + a3rdparty_domain
                 addcustomlog("3P")
              else:
                 injdom = "injected" + index + "." + req.sld_tld_domain
           
              if "rpq" in req.subdomains:  # replace the question with our injected stuffs
                 orig_req_domain = req.full_domain
                 req.full_domain = injdom
                 req.type_bin = getTypeBin(req.inj_type_str) 
                 addcustomlog("RPQ")
           
              if "adq" in req.subdomains:  # add additional question for our injected stuffs
                 resp.QURR = req.QURR+1
                 addedquestions  = convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + req.class_bin
                 addcustomlog("ADQ")
           
              if "oi" in req.subdomains:   # only injected
                 answers = 1
                 addcustomlog("OI")
           
              if "rev" in req.subdomains:  # reversed / injected first
                 reversed = 1
                 addcustomlog("REV")
           
              if "als" in req.subdomains:  # all sections
                 allsections = 1
                 addcustomlog("ALS")
           
              ###############################
              # Now prepare the legit record based on what record type was requested in the query
           
              okdata = b''
              match req.type_str:
                case "A":
                    ip = "1.2.3.4"
                    okdata  = struct.pack(">H", 4)     ## Data length
                    okdata += socket.inet_aton(ip)     ## IP
                case "AAAA":
                    ip = "1111:2222:3333:4444:5555:6666:7777:8888"
                    okdata = struct.pack(">H", 16)                  ## Data length
                    okdata += socket.inet_pton(socket.AF_INET6, ip) ## IP
                case "PTR":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "MX":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom)+2) ## Data length
                    okdata += struct.pack(">H", 0)            ## Priority
                    okdata += bindom                          ## domain
                case "NS":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "CNAME":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "DNAME":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
           
              ###############################
              # Now prepare the injected CNAME record
           
              injdata = b''
              dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
              bindom = convDom2Bin(dom)
              injdata = struct.pack(">H", len(bindom))  ## Data length
              injdata += bindom                         ## domain
           
              ###############################
              ### DNS header ################
              if allsections:
                 buffer = prep_dns_header(b'\x84\x00', resp.QURR, answers, answers, answers)
              else:
                 buffer = prep_dns_header(b'\x84\x00', resp.QURR, answers, 0, 0)
              ###############################
              ### QUESTION SECTION ##########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              buffer += addedquestions
              ###############################
              ### ANSWER SECTION ############
              # first answer
              if "rpq" in req.subdomains:
                 req.full_domain = orig_req_domain  # switch back to the original domain
                 resp.compress = 0  # query contains the injected domain, cannot use it for compression
              if answers > 1:
                 if reversed:
                    # reversed order, first injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
                 else:
                    # normal order, first legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
              # second answer
              if reversed and answers > 1:
                 # reversed order, now legit record
                 buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                 buffer += getTypeBin(req.type_str) + getClassBin("IN")
                 buffer += struct.pack(">L", resp.TTL)
                 buffer += okdata
              else:
                 # normal order, now injected record
                 buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                 buffer += struct.pack(">L", resp.TTL)
                 buffer += injdata
              ###############################
              if allsections:
                 ### AUTHORITY SECTION #########
                 # first answer
                 if "rpq" in req.subdomains:
                    req.full_domain = orig_req_domain  # switch back to the original domain
                    resp.compress = 0  # query contains the injected domain, cannot use it for compression
                 if answers > 1:
                    if reversed:
                       # reversed order, first injected record
                       buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += injdata
                    else:
                       # normal order, first legit record
                       buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                       buffer += getTypeBin(req.type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += okdata
                 # second answer
                 if reversed and answers > 1:
                    # reversed order, now legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
                 else:
                    # normal order, now injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
                 ###############################
                 ### ADDITIONAL SECTION ########
                 # first answer
                 if "rpq" in req.subdomains:
                    req.full_domain = orig_req_domain  # switch back to the original domain
                    resp.compress = 0  # query contains the injected domain, cannot use it for compression
                 if answers > 1:
                    if reversed:
                       # reversed order, first injected record
                       buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += injdata
                    else:
                       # normal order, first legit record
                       buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                       buffer += getTypeBin(req.type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += okdata
                 # second answer
                 if reversed and answers > 1:
                    # reversed order, now legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
                 else:
                    # normal order, now injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
              ###############################
              # log and send
              log("%s + %s" % (req.type_str, req.inj_type_str))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("injdname") and (len(req.first_subdomain) == 8 or req.first_subdomain[8:].isdigit()):
              # Send a legit record + an injected record
           
              ####################################
              # Default values of the parameters
           
              answers = 2
              reversed = 0
              allsections = 0
              addedquestions = b''
              req.inj_type_str = 'DNAME'
           
              ####################################
              # Get all the parameters
           
              index = req.first_subdomain[8:]
           
              if "3rp" in req.subdomains:  # inject a 3rd party domain
                 injdom = "injected" + index + "." + a3rdparty_domain
                 addcustomlog("3P")
              else:
                 injdom = "injected" + index + "." + req.sld_tld_domain
           
              if "rpq" in req.subdomains:  # replace the question with our injected stuffs
                 orig_req_domain = req.full_domain
                 req.full_domain = injdom
                 req.type_bin = getTypeBin(req.inj_type_str) 
                 addcustomlog("RPQ")
           
              if "adq" in req.subdomains:  # add additional question for our injected stuffs
                 resp.QURR = req.QURR+1
                 addedquestions  = convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + req.class_bin
                 addcustomlog("ADQ")
           
              if "oi" in req.subdomains:   # only injected
                 answers = 1
                 addcustomlog("OI")
           
              if "rev" in req.subdomains:  # reversed / injected first
                 reversed = 1
                 addcustomlog("REV")
           
              if "als" in req.subdomains:  # all sections
                 allsections = 1
                 addcustomlog("ALS")
           
              ###############################
              # Now prepare the legit record based on what record type was requested in the query
           
              okdata = b''
              match req.type_str:
                case "A":
                    ip = "1.2.3.4"
                    okdata  = struct.pack(">H", 4)     ## Data length
                    okdata += socket.inet_aton(ip)     ## IP
                case "AAAA":
                    ip = "1111:2222:3333:4444:5555:6666:7777:8888"
                    okdata = struct.pack(">H", 16)                  ## Data length
                    okdata += socket.inet_pton(socket.AF_INET6, ip) ## IP
                case "PTR":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "MX":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom)+2) ## Data length
                    okdata += struct.pack(">H", 0)            ## Priority
                    okdata += bindom                          ## domain
                case "NS":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "CNAME":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "DNAME":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
           
              ###############################
              # Now prepare the injected DNAME record
           
              injdata = b''
              dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
              bindom = convDom2Bin(dom)
              injdata = struct.pack(">H", len(bindom))  ## Data length
              injdata += bindom                         ## domain
           
              ###############################
              ### DNS header ################
              if allsections:
                 buffer = prep_dns_header(b'\x84\x00', resp.QURR, answers, answers, answers)
              else:
                 buffer = prep_dns_header(b'\x84\x00', resp.QURR, answers, 0, 0)
              ###############################
              ### QUESTION SECTION ##########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              buffer += addedquestions
              ###############################
              ### ANSWER SECTION ############
              # first answer
              if "rpq" in req.subdomains:
                 req.full_domain = orig_req_domain  # switch back to the original domain
                 resp.compress = 0  # query contains the injected domain, cannot use it for compression
              if answers > 1:
                 if reversed:
                    # reversed order, first injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
                 else:
                    # normal order, first legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
              # second answer
              if reversed and answers > 1:
                 # reversed order, now legit record
                 buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                 buffer += getTypeBin(req.type_str) + getClassBin("IN")
                 buffer += struct.pack(">L", resp.TTL)
                 buffer += okdata
              else:
                 # normal order, now injected record
                 buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                 buffer += struct.pack(">L", resp.TTL)
                 buffer += injdata
              ###############################
              if allsections:
                 ### AUTHORITY SECTION #########
                 # first answer
                 if "rpq" in req.subdomains:
                    req.full_domain = orig_req_domain  # switch back to the original domain
                    resp.compress = 0  # query contains the injected domain, cannot use it for compression
                 if answers > 1:
                    if reversed:
                       # reversed order, first injected record
                       buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += injdata
                    else:
                       # normal order, first legit record
                       buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                       buffer += getTypeBin(req.type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += okdata
                 # second answer
                 if reversed and answers > 1:
                    # reversed order, now legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
                 else:
                    # normal order, now injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
                 ###############################
                 ### ADDITIONAL SECTION ########
                 # first answer
                 if "rpq" in req.subdomains:
                    req.full_domain = orig_req_domain  # switch back to the original domain
                    resp.compress = 0  # query contains the injected domain, cannot use it for compression
                 if answers > 1:
                    if reversed:
                       # reversed order, first injected record
                       buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += injdata
                    else:
                       # normal order, first legit record
                       buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                       buffer += getTypeBin(req.type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += okdata
                 # second answer
                 if reversed and answers > 1:
                    # reversed order, now legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
                 else:
                    # normal order, now injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
              ###############################
              # log and send
              log("%s + %s" % (req.type_str, req.inj_type_str))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("injmx") and (len(req.first_subdomain) == 5 or req.first_subdomain[5:].isdigit()):
              # Send a legit record + an injected record
           
              ####################################
              # Default values of the parameters
           
              answers = 2
              reversed = 0
              allsections = 0
              addedquestions = b''
              req.inj_type_str = 'MX'
           
              ####################################
              # Get all the parameters
           
              index = req.first_subdomain[5:]
           
              if "3rp" in req.subdomains:  # inject a 3rd party domain
                 injdom = "injected" + index + "." + a3rdparty_domain
                 addcustomlog("3P")
              else:
                 injdom = "injected" + index + "." + req.sld_tld_domain
           
              if "rpq" in req.subdomains:  # replace the question with our injected stuffs
                 orig_req_domain = req.full_domain
                 req.full_domain = injdom
                 req.type_bin = getTypeBin(req.inj_type_str) 
                 addcustomlog("RPQ")
           
              if "adq" in req.subdomains:  # add additional question for our injected stuffs
                 resp.QURR = req.QURR+1
                 addedquestions  = convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + req.class_bin
                 addcustomlog("ADQ")
           
              if "oi" in req.subdomains:   # only injected
                 answers = 1
                 addcustomlog("OI")
           
              if "rev" in req.subdomains:  # reversed / injected first
                 reversed = 1
                 addcustomlog("REV")
           
              if "als" in req.subdomains:  # all sections
                 allsections = 1
                 addcustomlog("ALS")
           
              ###############################
              # Now prepare the legit record based on what record type was requested in the query
           
              okdata = b''
              match req.type_str:
                case "A":
                    ip = "1.2.3.4"
                    okdata  = struct.pack(">H", 4)     ## Data length
                    okdata += socket.inet_aton(ip)     ## IP
                case "AAAA":
                    ip = "1111:2222:3333:4444:5555:6666:7777:8888"
                    okdata = struct.pack(">H", 16)                  ## Data length
                    okdata += socket.inet_pton(socket.AF_INET6, ip) ## IP
                case "PTR":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "MX":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom)+2) ## Data length
                    okdata += struct.pack(">H", 0)            ## Priority
                    okdata += bindom                          ## domain
                case "NS":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "CNAME":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "DNAME":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
           
              ###############################
              # Now prepare the injected MX record
           
              injdata = b''
              dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
              bindom = convDom2Bin(dom)
              injdata = struct.pack(">H", len(bindom)+2) ## Data length
              injdata += struct.pack(">H", 0)            ## Priority
              injdata += bindom                          ## CNAME value
           
              ###############################
              ### DNS header ################
              if allsections:
                 buffer = prep_dns_header(b'\x84\x00', resp.QURR, answers, answers, answers)
              else:
                 buffer = prep_dns_header(b'\x84\x00', resp.QURR, answers, 0, 0)
              ###############################
              ### QUESTION SECTION ##########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              buffer += addedquestions
              ###############################
              ### ANSWER SECTION ############
              # first answer
              if "rpq" in req.subdomains:
                 req.full_domain = orig_req_domain  # switch back to the original domain
                 resp.compress = 0  # query contains the injected domain, cannot use it for compression
              if answers > 1:
                 if reversed:
                    # reversed order, first injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
                 else:
                    # normal order, first legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
              # second answer
              if reversed and answers > 1:
                 # reversed order, now legit record
                 buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                 buffer += getTypeBin(req.type_str) + getClassBin("IN")
                 buffer += struct.pack(">L", resp.TTL)
                 buffer += okdata
              else:
                 # normal order, now injected record
                 buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                 buffer += struct.pack(">L", resp.TTL)
                 buffer += injdata
              ###############################
              if allsections:
                 ### AUTHORITY SECTION #########
                 # first answer
                 if "rpq" in req.subdomains:
                    req.full_domain = orig_req_domain  # switch back to the original domain
                    resp.compress = 0  # query contains the injected domain, cannot use it for compression
                 if answers > 1:
                    if reversed:
                       # reversed order, first injected record
                       buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += injdata
                    else:
                       # normal order, first legit record
                       buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                       buffer += getTypeBin(req.type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += okdata
                 # second answer
                 if reversed and answers > 1:
                    # reversed order, now legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
                 else:
                    # normal order, now injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
                 ###############################
                 ### ADDITIONAL SECTION ########
                 # first answer
                 if "rpq" in req.subdomains:
                    req.full_domain = orig_req_domain  # switch back to the original domain
                    resp.compress = 0  # query contains the injected domain, cannot use it for compression
                 if answers > 1:
                    if reversed:
                       # reversed order, first injected record
                       buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += injdata
                    else:
                       # normal order, first legit record
                       buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                       buffer += getTypeBin(req.type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += okdata
                 # second answer
                 if reversed and answers > 1:
                    # reversed order, now legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
                 else:
                    # normal order, now injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
              ###############################
              # log and send
              log("%s + %s" % (req.type_str, req.inj_type_str))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("injns") and (len(req.first_subdomain) == 5 or req.first_subdomain[5:].isdigit()):
              # Send a legit record + an injected record
           
              ####################################
              # Default values of the parameters
           
              answers = 2
              reversed = 0
              allsections = 0
              addedquestions = b''
              req.inj_type_str = 'NS'
           
              ####################################
              # Get all the parameters
           
              index = req.first_subdomain[5:]
           
              if "3rp" in req.subdomains:  # inject a 3rd party domain
                 injdom = "injected" + index + "." + a3rdparty_domain
                 addcustomlog("3P")
              else:
                 injdom = "injected" + index + "." + req.sld_tld_domain
           
              if "rpq" in req.subdomains:  # replace the question with our injected stuffs
                 orig_req_domain = req.full_domain
                 req.full_domain = injdom
                 req.type_bin = getTypeBin(req.inj_type_str) 
                 addcustomlog("RPQ")
           
              if "adq" in req.subdomains:  # add additional question for our injected stuffs
                 resp.QURR = req.QURR+1
                 addedquestions  = convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + req.class_bin
                 addcustomlog("ADQ")
           
              if "oi" in req.subdomains:   # only injected
                 answers = 1
                 addcustomlog("OI")
           
              if "rev" in req.subdomains:  # reversed / injected first
                 reversed = 1
                 addcustomlog("REV")
           
              if "als" in req.subdomains:  # all sections
                 allsections = 1
                 addcustomlog("ALS")
           
              ###############################
              # Now prepare the legit record based on what record type was requested in the query
           
              okdata = b''
              match req.type_str:
                case "A":
                    ip = "1.2.3.4"
                    okdata  = struct.pack(">H", 4)     ## Data length
                    okdata += socket.inet_aton(ip)     ## IP
                case "AAAA":
                    ip = "1111:2222:3333:4444:5555:6666:7777:8888"
                    okdata = struct.pack(">H", 16)                  ## Data length
                    okdata += socket.inet_pton(socket.AF_INET6, ip) ## IP
                case "PTR":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "MX":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom)+2) ## Data length
                    okdata += struct.pack(">H", 0)            ## Priority
                    okdata += bindom                          ## domain
                case "NS":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "CNAME":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "DNAME":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
           
              ###############################
              # Now prepare the injected NS record
           
              injdata = b''
              dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
              bindom = convDom2Bin(dom)
              injdata = struct.pack(">H", len(bindom))  ## Data length
              injdata += bindom                         ## domain
           
              ###############################
              ### DNS header ################
              if allsections:
                 buffer = prep_dns_header(b'\x84\x00', resp.QURR, answers, answers, answers)
              else:
                 buffer = prep_dns_header(b'\x84\x00', resp.QURR, answers, 0, 0)
              ###############################
              ### QUESTION SECTION ##########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              buffer += addedquestions
              ###############################
              ### ANSWER SECTION ############
              # first answer
              if "rpq" in req.subdomains:
                 req.full_domain = orig_req_domain  # switch back to the original domain
                 resp.compress = 0  # query contains the injected domain, cannot use it for compression
              if answers > 1:
                 if reversed:
                    # reversed order, first injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
                 else:
                    # normal order, first legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
              # second answer
              if reversed and answers > 1:
                 # reversed order, now legit record
                 buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                 buffer += getTypeBin(req.type_str) + getClassBin("IN")
                 buffer += struct.pack(">L", resp.TTL)
                 buffer += okdata
              else:
                 # normal order, now injected record
                 buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                 buffer += struct.pack(">L", resp.TTL)
                 buffer += injdata
              ###############################
              if allsections:
                 ### AUTHORITY SECTION #########
                 # first answer
                 if "rpq" in req.subdomains:
                    req.full_domain = orig_req_domain  # switch back to the original domain
                    resp.compress = 0  # query contains the injected domain, cannot use it for compression
                 if answers > 1:
                    if reversed:
                       # reversed order, first injected record
                       buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += injdata
                    else:
                       # normal order, first legit record
                       buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                       buffer += getTypeBin(req.type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += okdata
                 # second answer
                 if reversed and answers > 1:
                    # reversed order, now legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
                 else:
                    # normal order, now injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
                 ###############################
                 ### ADDITIONAL SECTION ########
                 # first answer
                 if "rpq" in req.subdomains:
                    req.full_domain = orig_req_domain  # switch back to the original domain
                    resp.compress = 0  # query contains the injected domain, cannot use it for compression
                 if answers > 1:
                    if reversed:
                       # reversed order, first injected record
                       buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += injdata
                    else:
                       # normal order, first legit record
                       buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                       buffer += getTypeBin(req.type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += okdata
                 # second answer
                 if reversed and answers > 1:
                    # reversed order, now legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
                 else:
                    # normal order, now injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
              ###############################
              # log and send
              log("%s + %s" % (req.type_str, req.inj_type_str))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("injptr") and (len(req.first_subdomain) == 6 or req.first_subdomain[6:].isdigit()):
              # Send a legit record + an injected record
           
              ####################################
              # Default values of the parameters
           
              answers = 2
              reversed = 0
              allsections = 0
              addedquestions = b''
              req.inj_type_str = 'PTR'
           
              ####################################
              # Get all the parameters
           
              index = req.first_subdomain[6:]
           
              if "3rp" in req.subdomains:  # inject a 3rd party domain
                 injdom = "injected" + index + "." + a3rdparty_domain
                 addcustomlog("3P")
              else:
                 injdom = "injected" + index + "." + req.sld_tld_domain
           
              if "rpq" in req.subdomains:  # replace the question with our injected stuffs
                 orig_req_domain = req.full_domain
                 req.full_domain = injdom
                 req.type_bin = getTypeBin(req.inj_type_str) 
                 addcustomlog("RPQ")
           
              if "adq" in req.subdomains:  # add additional question for our injected stuffs
                 resp.QURR = req.QURR+1
                 addedquestions  = convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + req.class_bin
                 addcustomlog("ADQ")
           
              if "oi" in req.subdomains:   # only injected
                 answers = 1
                 addcustomlog("OI")
           
              if "rev" in req.subdomains:  # reversed / injected first
                 reversed = 1
                 addcustomlog("REV")
           
              if "als" in req.subdomains:  # all sections
                 allsections = 1
                 addcustomlog("ALS")
           
              ###############################
              # Now prepare the legit record based on what record type was requested in the query
           
              okdata = b''
              match req.type_str:
                case "A":
                    ip = "1.2.3.4"
                    okdata  = struct.pack(">H", 4)     ## Data length
                    okdata += socket.inet_aton(ip)     ## IP
                case "AAAA":
                    ip = "1111:2222:3333:4444:5555:6666:7777:8888"
                    okdata = struct.pack(">H", 16)                  ## Data length
                    okdata += socket.inet_pton(socket.AF_INET6, ip) ## IP
                case "PTR":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "MX":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom)+2) ## Data length
                    okdata += struct.pack(">H", 0)            ## Priority
                    okdata += bindom                          ## domain
                case "NS":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "CNAME":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
                case "DNAME":
                    dom = "always" + str(random.getrandbits(20) % 1000000).zfill(6) + "." + req.sld_tld_domain
                    bindom = convDom2Bin(dom)
                    okdata = struct.pack(">H", len(bindom))   ## Data length
                    okdata += bindom                          ## domain
           
              ###############################
              # Now prepare the injected PTR record
           
              injdata = b''
              bindom = convDom2Bin(injdom)
              injdata = struct.pack(">H", len(bindom))     ## Data length
              injdata += bindom                            ## domain
              injdom = "6.6.6.6.in-addr.arpa"
           
              ###############################
              ### DNS header ################
              if allsections:
                 buffer = prep_dns_header(b'\x84\x00', resp.QURR, answers, answers, answers)
              else:
                 buffer = prep_dns_header(b'\x84\x00', resp.QURR, answers, 0, 0)
              ###############################
              ### QUESTION SECTION ##########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              buffer += addedquestions
              ###############################
              ### ANSWER SECTION ############
              # first answer
              if "rpq" in req.subdomains:
                 req.full_domain = orig_req_domain  # switch back to the original domain
                 resp.compress = 0  # query contains the injected domain, cannot use it for compression
              if answers > 1:
                 if reversed:
                    # reversed order, first injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
                 else:
                    # normal order, first legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
              # second answer
              if reversed and answers > 1:
                 # reversed order, now legit record
                 buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                 buffer += getTypeBin(req.type_str) + getClassBin("IN")
                 buffer += struct.pack(">L", resp.TTL)
                 buffer += okdata
              else:
                 # normal order, now injected record
                 buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                 buffer += struct.pack(">L", resp.TTL)
                 buffer += injdata
              ###############################
              if allsections:
                 ### AUTHORITY SECTION #########
                 # first answer
                 if "rpq" in req.subdomains:
                    req.full_domain = orig_req_domain  # switch back to the original domain
                    resp.compress = 0  # query contains the injected domain, cannot use it for compression
                 if answers > 1:
                    if reversed:
                       # reversed order, first injected record
                       buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += injdata
                    else:
                       # normal order, first legit record
                       buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                       buffer += getTypeBin(req.type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += okdata
                 # second answer
                 if reversed and answers > 1:
                    # reversed order, now legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
                 else:
                    # normal order, now injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
                 ###############################
                 ### ADDITIONAL SECTION ########
                 # first answer
                 if "rpq" in req.subdomains:
                    req.full_domain = orig_req_domain  # switch back to the original domain
                    resp.compress = 0  # query contains the injected domain, cannot use it for compression
                 if answers > 1:
                    if reversed:
                       # reversed order, first injected record
                       buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += injdata
                    else:
                       # normal order, first legit record
                       buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                       buffer += getTypeBin(req.type_str) + getClassBin("IN")
                       buffer += struct.pack(">L", resp.TTL)
                       buffer += okdata
                 # second answer
                 if reversed and answers > 1:
                    # reversed order, now legit record
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin(req.type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += okdata
                 else:
                    # normal order, now injected record
                    buffer += convDom2Bin(injdom) + getTypeBin(req.inj_type_str) + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)
                    buffer += injdata
              ###############################
              # log and send
              log("%s + %s" % (req.type_str, req.inj_type_str))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("loop"):
              # Do an alias loop in a CNAME/DNAME/HTTPS/SVCB/SRV/MX/NS/SPF(TXT) record type
              if req.subdomains[1].isnumeric() and req.subdomains[2].isnumeric():
                 # we are already in a loop, e.g.:
                 # loop.10.4.yourdomain.com
                 max = int(req.subdomains[1])
                 cur = int(req.subdomains[2])
                 if cur >= max:
                    # go back to the beginning of the loop
                    new_domain_name = req.subdomains[0] + "." + str(max) + ".1"
                 else:
                    # increment the current index
                    new_domain_name = req.subdomains[0] + "." + str(max) + "." + str(cur+1)
                 for i in range(len(req.subdomains)-3):
                    new_domain_name += "." + req.subdomains[i+3]
              elif req.subdomains[1].isnumeric():
                 # we are in beginning of a loop with a requested max value, e.g.:
                 # loop.10.yourdomain.com
                 max = int(req.subdomains[1])
                 if max < 1:
                    max = 1
                 new_domain_name = req.subdomains[0] + "." + str(max) + "." + "1"
                 for i in range(len(req.subdomains)-2):
                    new_domain_name += "." + req.subdomains[i+2]
              else:
                 # just immediate loop
                 new_domain_name = req.full_domain
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              bindom = convDom2Bin(new_domain_name)
              match req.type_str:
                 case "DNAME":
                    type = "DNAME"
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin("DNAME") + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)     ## TTL
                    buffer += struct.pack(">H", len(bindom))  ## Data length
                    buffer += bindom                          ## DNAME value
                 case "HTTPS":
                    type = "HTTPS"
                    data_len = 2+len(bindom)                  # SvcPriority (2 bytes) + the target name
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin("HTTPS") + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)     ## TTL
                    buffer += struct.pack(">H", data_len)     ## Data length
                    buffer += struct.pack(">H", 0)            ## SvcPriority (0 means alias mode - RFC 9460)
                    buffer += bindom                          ## TargetName
                 case "SVCB":
                    type = "SVCB"
                    data_len = 2+len(bindom)                  # SvcPriority (2 bytes) + the target name
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin("SVCB") + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)     ## TTL
                    buffer += struct.pack(">H", data_len)     ## Data length
                    buffer += struct.pack(">H", 0)            ## SvcPriority (0 means alias mode - RFC 9460)
                    buffer += bindom                          ## TargetName
                 case "SRV":
                    type = "SRV"
                    port = random.getrandbits(16)
                    data_len = 2+2+2+len(bindom)  # Priority (2 bytes) + Weight (2 bytes) + Port (2 bytes) + Target domain
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin("SRV") + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)     ## TTL
                    buffer += struct.pack(">H", data_len)     ## Data length
                    buffer += struct.pack(">H", 0)            ## Priority
                    buffer += struct.pack(">H", 0)            ## Weight
                    buffer += struct.pack(">H", port)         ## Port
                    buffer += bindom                          ## TargetName
                 case "MX":
                    type = "MX"
                    data_len = 2+len(bindom)                  # Priority (2 bytes) + Target domain
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin("MX") + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)     ## TTL
                    buffer += struct.pack(">H", data_len)     ## Data length
                    buffer += struct.pack(">H", 0)            ## Priority
                    buffer += bindom                          ## TargetName
                 case "NS":
                    type = "NS"
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin("NS") + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)     ## TTL
                    buffer += struct.pack(">H", len(bindom))  ## Data length
                    buffer += bindom                          ## NS value
                 case "TXT":
                    type = "SPF(TXT)"
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    data = "v=spf1 include:" + new_domain_name + " ~all"
                    buffer += getTypeBin("TXT") + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)     ## TTL
                    buffer += struct.pack(">H", len(data)+1)  ## Data length (2B)
                    buffer += struct.pack(">B", len(data))    ## TXT length (1B)
                    buffer += data.encode("utf-8")            ## TXT SPF value
                 case _:
                    type = "CNAME"
                    buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                    buffer += getTypeBin("CNAME") + getClassBin("IN")
                    buffer += struct.pack(">L", resp.TTL)     ## TTL
                    buffer += struct.pack(">H", len(bindom))  ## Data length
                    buffer += bindom                          ## DNAME value
              # log and send
              log("%s LOOP %s" % (type, new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("manybintxt"):
              # Send many random binary TXT records
              nans = 10  # number of TXT records to send
              if req.subdomains[1].isnumeric():
                 nans = int(req.subdomains[1])
              chunksize = 255  # chunk size
              if req.subdomains[2].isnumeric():
                 chunksize = int(req.subdomains[2])
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, nans, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              for i in range(nans):
                  # max label size is 255 bytes, so chunk it
                  parts = []
                  for i in range(0, chunksize, 255):
                     size = min(255, chunksize - i)
                     part = struct.pack(">B", size)
                     part += os.urandom(size)
                     parts.append(part)
                  data = b''.join(parts)
           
                  buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                  buffer += getTypeBin("TXT") + getClassBin("IN")
                  buffer += struct.pack(">L", resp.TTL)           ## TTL
                  buffer += struct.pack(">H", len(data))          ## Data length
                  buffer += data
              # log and send
              log("%d binary TXT records of %d B (total: %d B)" % (nans, chunksize, len(buffer)))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("manytxt"):
              # Send many random TXT records
              nans = 10  # number of TXT records to send
              if req.subdomains[1].isnumeric():
                 nans = int(req.subdomains[1])
              chunksize = 255  # chunk size
              if req.subdomains[2].isnumeric():
                 chunksize = int(req.subdomains[2])
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, nans, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              for i in range(nans):
                  # max label size is 255 bytes, so chunk it
                  parts = []
                  for i in range(0, chunksize, 255):
                     part = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(min(255, chunksize - i)))
                     parts.append(part)
                  data = '.'.join(parts)
           
                  buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                  buffer += getTypeBin("TXT") + getClassBin("IN")
                  buffer += struct.pack(">L", resp.TTL)            ## TTL
                  buffer += struct.pack(">H", len(data)+1)         ## Data length
                  buffer += convData2Bin(data)
              # log and send
              log("%d TXT records of %d B (total: %d B)" % (nans, chunksize, len(buffer)))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("mxalias"):
              # Send multiple random MX aliases
              # BEWARE: This could result in multiplication
              answers = int(req.subdomains[1]) if req.subdomains[1].isnumeric() else 1
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, answers, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              doms = []
              for i in range(answers):
                  # MX records
                  dom = name_fuzz(resp.nfz) if hasattr(resp, "nfz") else random_chain(req.full_domain)
                  bindom = convDom2Bin(dom)
                  data_len = 2+len(bindom)                 # Priority (2 bytes) + Target domain
                  buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                  buffer += getTypeBin("MX") + getClassBin("IN")
                  buffer += struct.pack(">L", resp.TTL)    ## TTL
                  buffer += struct.pack(">H", data_len)    ## Data length
                  buffer += struct.pack(">H", 0)           ## Priority
                  buffer += bindom                         ## TargetName
                  doms.append(dom)
              # log and send
              log("%d MX aliases: %s" % (answers, ', '.join(map(str, doms[:3])) + (', ...' if answers > 3 else '')))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("mxchain"):
              # Send incremented MX alias record.
              new_domain_name = increment_chain(req.full_domain)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # MX alias record
              bindom = convDom2Bin(new_domain_name)
              data_len = 2+len(bindom)                 # Priority (2 bytes) + Target domain
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("MX") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)    ## TTL
              buffer += struct.pack(">H", data_len)    ## Data length
              buffer += struct.pack(">H", 0)           ## Priority
              buffer += bindom                         ## TargetName
              # log and send
              log("MX %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("mxloop"):
              # Do an alias loop in a MX record
              if req.subdomains[1].isnumeric() and req.subdomains[2].isnumeric():
                 # we are already in a loop, e.g.:
                 # mxloop.10.4.yourdomain.com
                 max = int(req.subdomains[1])
                 cur = int(req.subdomains[2])
                 if cur >= max:
                    # go back to the beginning of the loop
                    new_domain_name = req.subdomains[0] + "." + str(max) + ".1"
                 else:
                    # increment the current index
                    new_domain_name = req.subdomains[0] + "." + str(max) + "." + str(cur+1)
                 for i in range(len(req.subdomains)-3):
                    new_domain_name += "." + req.subdomains[i+3]
              elif req.subdomains[1].isnumeric():
                 # we are in beginning of a loop with a requested max value, e.g.:
                 # mxloop.10.yourdomain.com
                 max = int(req.subdomains[1])
                 if max < 1:
                    max = 1
                 new_domain_name = req.subdomains[0] + "." + str(max) + "." + "1"
                 for i in range(len(req.subdomains)-2):
                    new_domain_name += "." + req.subdomains[i+2]
              else:
                 # just immediate loop
                 new_domain_name = req.full_domain
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              bindom = convDom2Bin(new_domain_name)
              data_len = 2+len(bindom)                 # Priority (2 bytes) + Target domain
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("MX") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)    ## TTL
              buffer += struct.pack(">H", data_len)    ## Data length
              buffer += struct.pack(">H", 0)           ## Priority
              buffer += bindom                         ## TargetName
              # log and send
              log("MX LOOP %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain == "1" and req.full_domain.endswith(".e164.arpa"):
              # Requesting to translate an E.164 telephone number ending with the digit 1 (e.g., a NAPTR
              # record for 1.<anything>.e164.arpa in reverse). The response will be a SIP service URI
              # pointing to another random E.164 telephone number also ending with the digit 1 (leading
              # here again, producing another alias). While NAPTR ENUM records do not contain aliases
              # like CNAME records, this could achieve similar results by prompting the client to
              # perform consecutive queries to resolve it.
              # BEWARE: This could result in multiplication

              answers = int(req.subdomains[1]) if req.subdomains[1].isnumeric() else 1

              # figure out the ending part of the domain which is not a number any more
              # in order to preserve the parameters if any
              for i, part in enumerate(req.subdomains):
                  if not part.isnumeric():
                     dom_end = '.' + '.'.join(req.subdomains[i:])
                     break
              else:
                  dom_end = req.full_domain

              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, answers, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              doms = []
              for i in range(answers):
                  random_number = random.getrandbits(30) % 1000000000
                  new_dom     = '1.' + str(answers) + '.' + '.'.join(str(random_number)) + dom_end
                  order       = 0
                  pref        = 0
                  flags       = b'U'          # Flags = "U" (URI)
                  service     = b'E2U+sip'    # Service = SIP
                  regex       = bytes("!^.*$!" + new_dom + "!", "utf-8")
                  replacement = b'\x00'

                  data_len = 2+2+1+len(flags)+1+len(service)+1+len(regex)+len(replacement)
                  buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)  ## Name
                  buffer += getTypeBin("NAPTR") + getClassBin("IN")
                  buffer += struct.pack(">L", resp.TTL)     ## TTL
                  buffer += struct.pack(">H", data_len)     ## Data length (2B)
                  buffer += struct.pack(">H", order)        ## Order (2B)
                  buffer += struct.pack(">H", pref)         ## Preference (2B)
                  buffer += struct.pack(">B", len(flags))   ## Flags Length (1B)
                  buffer += flags                           ## Flags
                  buffer += struct.pack(">B", len(service)) ## Service Length (1B)
                  buffer += service                         ## Service
                  buffer += struct.pack(">B", len(regex))   ## Regex Length (1B)
                  buffer += regex                           ## Regex
                  buffer += replacement                     ## Replacement
                  doms.append(new_dom)
              # log and send
              log("%d NAPTR ENUM aliases: %s" % (answers, ', '.join(map(str, doms[:3])) + (', ...' if answers > 3 else '')))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain == "2" and req.full_domain.endswith(".e164.arpa"):
              # Requesting to translate an E.164 telephone number ending with the digit 2 (e.g., a NAPTR
              # record for 2.<anything>.e164.arpa in reverse). The response will be a SIP service URI
              # pointing to the same exact E.164 telephone number, effectively creating a direct loop.
              # While NAPTR ENUM records do not contain aliases like CNAME records, this could achieve
              # similar results by prompting the client to perform consecutive queries to resolve it.
              # BEWARE: This could potentially lead to a domain lock-up (DoS)

              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              order       = 0
              pref        = 0
              flags       = b'U'          # Flags = "U" (URI)
              service     = b'E2U+sip'    # Service = SIP
              regex       = bytes("!^.*$!" + req.full_domain + "!", "utf-8")
              replacement = b'\x00'

              data_len = 2+2+1+len(flags)+1+len(service)+1+len(regex)+len(replacement)
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)  ## Name
              buffer += getTypeBin("NAPTR") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)     ## TTL
              buffer += struct.pack(">H", data_len)     ## Data length (2B)
              buffer += struct.pack(">H", order)        ## Order (2B)
              buffer += struct.pack(">H", pref)         ## Preference (2B)
              buffer += struct.pack(">B", len(flags))   ## Flags Length (1B)
              buffer += flags                           ## Flags
              buffer += struct.pack(">B", len(service)) ## Service Length (1B)
              buffer += service                         ## Service
              buffer += struct.pack(">B", len(regex))   ## Regex Length (1B)
              buffer += regex                           ## Regex
              buffer += replacement                     ## Replacement
              # log and send
              log("NAPTR ENUM loop %s" % (req.full_domain))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("nsalias"):
              # Send multiple random NS aliases
              # BEWARE: This could result in multiplication
              answers = int(req.subdomains[1]) if req.subdomains[1].isnumeric() else 1
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, answers, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              doms = []
              for i in range(answers):
                  # NS
                  dom = name_fuzz(resp.nfz) if hasattr(resp, "nfz") else random_chain(req.full_domain)
                  bindom = convDom2Bin(dom)
                  buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                  buffer += getTypeBin("NS") + getClassBin("IN")
                  buffer += struct.pack(">L", resp.TTL)      ## TTL
                  buffer += struct.pack(">H", len(bindom))   ## Data length
                  buffer += bindom                           ## NS value
                  doms.append(dom)
              # log and send
              log("%d NS aliases: %s" % (answers, ', '.join(map(str, doms[:3])) + (', ...' if answers > 3 else '')))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("nschain"):
              # Send incremented NS alias
              new_domain_name = increment_chain(req.full_domain)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # NS
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("NS") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)                    ## TTL
              buffer += struct.pack(">H", len(new_domain_name)+2)      ## Data length
              buffer += convDom2Bin(new_domain_name)                   ## NS value
              # log and send
              log("NS %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("nsloop"):
              # Do a NS loop
              if req.subdomains[1].isnumeric() and req.subdomains[2].isnumeric():
                 # we are already in a loop, e.g.:
                 # nsloop.10.4.yourdomain.com
                 max = int(req.subdomains[1])
                 cur = int(req.subdomains[2])
                 if cur >= max:
                    # go back to the beginning of the loop
                    new_domain_name = req.subdomains[0] + "." + str(max) + ".1"
                 else:
                    # increment the current index
                    new_domain_name = req.subdomains[0] + "." + str(max) + "." + str(cur+1)
                 for i in range(len(req.subdomains)-3):
                    new_domain_name += "." + req.subdomains[i+3]
              elif req.subdomains[1].isnumeric():
                 # we are in beginning of a loop with a requested max value, e.g.:
                 # nsloop.10.yourdomain.com
                 max = int(req.subdomains[1])
                 if max < 1:
                    max = 1
                 new_domain_name = req.subdomains[0] + "." + str(max) + "." + "1"
                 for i in range(len(req.subdomains)-2):
                    new_domain_name += "." + req.subdomains[i+2]
              else:
                 # just immediate loop
                 new_domain_name = req.full_domain
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # NS
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("NS") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)                    ## TTL
              buffer += struct.pack(">H", len(new_domain_name)+2)      ## Data length
              buffer += convDom2Bin(new_domain_name)                   ## NS value
              # log and send
              log("NS LOOP %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.full_domain.lower().endswith(".10.in-addr.arpa"):
              # Asking for a reverse record for the IP address 10.x.y.z (z.y.x.10.in-arpa.addr PTR record).
              # The 10.0.0.0/8 network range is a private network range for internal use only.
              # Let's respond with x number of PTR records containing 10.x.<RANDOM>.<RANDOM>.in-addr.arpa
              # domains (from the same range). This means that if the client/resolver will attempt to resolve
              # any of them, it will again end up here, producing even more PTR records from the same range.
              # BEWARE: This could result in multiplication
              answers = int(req.subdomains[2]) if req.subdomains[2].isnumeric() else 1
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, answers, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              doms = []
              for i in range(answers):
                  # PTR alias records
                  r1 = str(random.getrandbits(8))
                  r2 = str(random.getrandbits(8))
                  #      z    .     y    .           x             .     10
                  dom = r2 + "." + r1 + "." + req.subdomains[2] + "." + "10.in-addr.arpa"
                  bindom = convDom2Bin(dom)
                  buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                  buffer += getTypeBin("PTR") + getClassBin("IN")
                  buffer += struct.pack(">L", resp.TTL)           ## TTL
                  buffer += struct.pack(">H", len(bindom))        ## Data length
                  buffer += bindom                                ## TargetName
                  doms.append(dom)
              # log and send
              log("%d PTR aliases: %s" % (answers, ', '.join(map(str, doms[:3])) + (', ...' if answers > 3 else '')))
              send_buf(self, buffer)
              #####################################################################
           elif req.full_domain.lower().endswith(".2.0.192.in-addr.arpa"):
              # Asking for a reverse record for the IP address 192.0.2.x (x.2.0.192.in-addr.arpa PTR record).
              # The 192.0.2.0/24 network range is TEST-NET-1 typically used for documentation/examples.
              # Let's respond back with the same exact domain name, effectively creating an immediate loop.
              bindom = b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # PTR alias records
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("PTR") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)    ## TTL
              buffer += struct.pack(">H", len(bindom)) ## Data length
              buffer += bindom                         ## TargetName
              # log and send
              log("PTR loop %s" % (req.full_domain))
              send_buf(self, buffer)
              #####################################################################
           elif req.full_domain.lower().endswith(".100.51.198.in-addr.arpa"):
              # Asking for a reverse record for the IP address 198.51.100.x (x.100.51.198.in-addr.arpa PTR record).
              # The 198.51.100.0/24 network range is TEST-NET-2 typically used for documentation/examples.
              # Let's respond back with the incremented domain name, all the way up to 198.51.100.255 and then
              # back to 198.51.100.0 indefinitely, effectively creating a loop.
              host = int(req.first_subdomain)
              host = 0 if host >= 255 else host + 1
              dom = str(host) + "." + ".".join(req.subdomains[1:])
              bindom = convDom2Bin(dom)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # PTR alias records
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("PTR") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)    ## TTL
              buffer += struct.pack(">H", len(bindom)) ## Data length
              buffer += bindom                         ## TargetName
              # log and send
              log("PTR %s" % (dom))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("queryback1"):
              # Domain starts with "queryback1", let's send back the same query
              buffer = resp.ID + req.RAW[2:]
              # log and send
              log("sending back the same query")
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("queryback2"):
              # Domain starts with "queryback2", let's send back the same query - stripped, with only
              # the question without any additional sections (like e.g. the OPT / EDNS0)
              ### DNS header ########
              buffer = prep_dns_header(req.FLAGS, req.QURR, 0, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              # log and send
              log("sending back the same query - stripped")
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("queryback3"):
              # Domain starts with "queryback3", let's send back the same query to the sender
              # to udp/53 port, as an attempt to make a loop.
              # Don't send any response to the original query (let it timeout)
              sender = self.client_address[0]
              if sender != "127.0.0.1":
                  buffer = resp.ID + req.RAW[2:]
                  log("sending back the same query to udp://" + sender + ":53")
                  # send back the query to port udp 53
                  s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
                  s.sendto(buffer, ((sender, 53)))
              else:
                  log("not sending back the same query to myself")
              # don't send anything back in this connection
              timeout_conn(self)
              #####################################################################
           elif req.first_subdomain.startswith("queryback4"):
              sender = self.client_address[0]
              if sender != "127.0.0.1":
                  ### DNS header ########
                  buffer = prep_dns_header(req.FLAGS, req.QURR, 0, 0, 0)
                  ### QUESTION SECTION ########
                  newname = "queryback4" + str(random.getrandbits(66)) + "." + ".".join(req.subdomains[1:])
                  if resp.noq: buffer += convDom2Bin(newname) + req.type_bin + req.class_bin
                  log("sending back new similar query to udp://" + sender + ":53")
                  # send back the query to port udp 53
                  s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
                  s.sendto(buffer, ((sender, 53)))
              else:
                  log("not sending back the query to myself")
              # don't send anything back in this connection
              timeout_conn(self)
              #####################################################################
           elif req.first_subdomain.startswith("self") or req.first_subdomain.startswith("whatismyip"):
              # Respond with the client's IP address in A record and in TXT record (IP:port)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', resp.QURR, 1, 0, 1)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              if req.type_str == "TXT":
                 # TXT
                 ipport = str(self.client_address[0]) + ":" + str(self.client_address[1])
                 buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                 buffer += getTypeBin("TXT") + getClassBin("IN")
                 buffer += struct.pack(">L", resp.TTL)      ## TTL
                 buffer += struct.pack(">H", len(ipport)+1) ## Data length
                 buffer += struct.pack(">B", len(ipport))   ## TXT length
                 buffer += bytes(ipport, "utf-8")
                 # A
                 ip = self.client_address[0]
                 buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                 buffer += getTypeBin("A") + getClassBin("IN")
                 buffer += struct.pack(">L", self.client_address[1])    ## TTL (the port number)
                 buffer += struct.pack(">H", 4)           ## Data length
                 buffer += socket.inet_aton(ip)           ## IP
                 log("TXT + A with the client address")
              else:
                 # A
                 ip = self.client_address[0]
                 buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                 buffer += getTypeBin("A") + getClassBin("IN")
                 buffer += struct.pack(">L", self.client_address[1])    ## TTL (the port number)
                 buffer += struct.pack(">H", 4)           ## Data length
                 buffer += socket.inet_aton(ip)           ## IP
                 # TXT
                 ipport = str(self.client_address[0]) + ":" + str(self.client_address[1])
                 buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                 buffer += getTypeBin("TXT") + getClassBin("IN")
                 buffer += struct.pack(">L", resp.TTL)      ## TTL
                 buffer += struct.pack(">H", len(ipport)+1) ## Data length
                 buffer += struct.pack(">B", len(ipport))   ## TXT length
                 buffer += bytes(ipport, "utf-8")
                 log("A + TXT with the client address")
              # send
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("size"):
              # Send as many A records as we can possibly fit into a desired max size
              desired_size = int(req.subdomains[1]) if req.subdomains[1].isnumeric() else 512
           
              # compute how much space we have left after we add the necessities
              req.full_domain_bin = convDom2Bin(req.full_domain)
              req_name_len = len(req.full_domain_bin)
           
              resp.type_str = "A"
              record_size = 14  # A record without name
              if req.type_str == "AAAA":
                 resp.type_str = "AAAA"
                 record_size = 26 # AAAA record without name
           
              #                         header + query section
              space_left = desired_size - 12 - 4 - req_name_len
              if proto == "tcp": space_left -= 2
              if space_left < 0: space_left = 0
           
              # compute how many answers we can fit
              answers = int(space_left/(record_size+2)) if resp.compress else int(space_left/(record_size+req_name_len))
           
              print("space left: %d, can fit: %d" % (space_left, answers)) if debug else True
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', resp.QURR, answers, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += req.full_domain_bin + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              if resp.type_str == "AAAA":
                 # AAAA
                 for i in range(answers):
                     buffer += b'\xc0\x0c' if resp.compress else req.full_domain_bin
                     buffer += getTypeBin(resp.type_str) + getClassBin("IN")
                     buffer += struct.pack(">L", resp.TTL)    ## TTL
                     buffer += struct.pack(">H", 16)           ## Data length
                     buffer += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     buffer += random.getrandbits(16).to_bytes(2, 'big') ## 0000:0000:0000:0000:0000:0000:0000:<RANDOM>
              else:
                 # A
                 for i in range(answers):
                     buffer += b'\xc0\x0c' if resp.compress else req.full_domain_bin
                     buffer += getTypeBin(resp.type_str) + getClassBin("IN")
                     buffer += struct.pack(">L", resp.TTL)    ## TTL
                     buffer += struct.pack(">H", 4)           ## Data length
                     buffer += b'\x7f\x00\x00' + random.getrandbits(8).to_bytes(1, 'big') ## 127.0.0.<RANDOM>
              # log and send
              log("%d %s records in %d B packet size limit" % (answers, resp.type_str, desired_size))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("spfalias1"):
              # Send multiple SPF (TXT) records with a random alias in the include parameter
              # BEWARE: This could result in multiplication
              answers = int(req.subdomains[1]) if req.subdomains[1].isnumeric() else 1
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, answers, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              doms = []
              for i in range(answers):
                  # TXT SPF
                  dom = name_fuzz(resp.nfz) if hasattr(resp, "nfz") else "spfalias1" + str(random.getrandbits(20) % 100000) + "." + ".".join(req.subdomains[1:])
                  data = "v=spf1 include:" + dom + " ~all"
                  buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                  buffer += getTypeBin("TXT") + getClassBin("IN")
                  buffer += struct.pack(">L", resp.TTL)      ## TTL
                  buffer += struct.pack(">H", len(data)+1)   ## Data length (2B)
                  buffer += struct.pack(">B", len(data))     ## TXT length (1B)
                  buffer += data.encode("utf-8")             ## TXT SPF value
                  doms.append(dom)
              # log and send
              log("%d SPF(TXT) aliases: %s" % (answers, ', '.join(map(str, doms[:3])) + (', ...' if answers > 3 else '')))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("spfalias2"):
              # Send a single SPF (TXT) record with multiple random aliases included one by one
              # BEWARE: This could result in multiplication
              aliases = int(req.subdomains[1]) if req.subdomains[1].isnumeric() else 1
              buffer = b''
              answers = []
              doms = []
              data = "v=spf1"
              for i in range(aliases):
                  dom = name_fuzz(resp.nfz) if hasattr(resp, "nfz") else "spfalias2" + str(random.getrandbits(20) % 100000) + "." + ".".join(req.subdomains[1:])
                  doms.append(dom)
                  tmpdata = data + " include:" + dom
                  if len(tmpdata) > 250:
                     # we need another answer record since
                     # the max size for TXT label is 255 bytes
                     data += " ~all"  # the additional 5 bytes
                     buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                     buffer += getTypeBin("TXT") + getClassBin("IN")
                     buffer += struct.pack(">L", resp.TTL)      ## TTL
                     buffer += struct.pack(">H", len(data)+1)   ## Data length (2B)
                     buffer += struct.pack(">B", len(data))     ## TXT length (1B)
                     buffer += data.encode("utf-8")             ## TXT SPF value
                     answers.append(buffer)
                     data = "v=spf1 include:" + dom
                     buffer = b''
                     if i == aliases-1:
                        # this is also the last alias
                        data += " ~all"
                        buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                        buffer += getTypeBin("TXT") + getClassBin("IN")
                        buffer += struct.pack(">L", resp.TTL)      ## TTL
                        buffer += struct.pack(">H", len(data)+1)   ## Data length (2B)
                        buffer += struct.pack(">B", len(data))     ## TXT length (1B)
                        buffer += data.encode("utf-8")             ## TXT SPF value
                        answers.append(buffer)
                     continue
                  data = tmpdata
                  if i == aliases-1:
                     # this is the last alias
                     data += " ~all"
                     buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                     buffer += getTypeBin("TXT") + getClassBin("IN")
                     buffer += struct.pack(">L", resp.TTL)      ## TTL
                     buffer += struct.pack(">H", len(data)+1)   ## Data length (2B)
                     buffer += struct.pack(">B", len(data))     ## TXT length (1B)
                     buffer += data.encode("utf-8")             ## TXT SPF value
                     answers.append(buffer)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, len(answers), 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              for i in range(len(answers)):
                  buffer += answers[i]
              # log and send
              log("%d aliases in %d SPF(TXT) records: %s" % (aliases, len(answers), ', '.join(map(str, doms[:3])) + (', ...' if aliases > 3 else '')))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("spfchain"):
              # Send incremented SPF(TXT) alias
              new_domain_name = increment_chain(req.full_domain)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # TXT SPF
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              data = "v=spf1 include:" + new_domain_name + " ~all"
              buffer += getTypeBin("TXT") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)       ## TTL
              buffer += struct.pack(">H", len(data)+1)    ## Data length (2B)
              buffer += struct.pack(">B", len(data))      ## TXT length (1B)
              buffer += data.encode("utf-8")              ## TXT SPF value
              # log and send
              log("SPF(TXT) %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("spfloop"):
              # Do a SPF(TXT) loop
              if req.subdomains[1].isnumeric() and req.subdomains[2].isnumeric():
                 # we are already in a loop, e.g.:
                 # spfloop.10.4.yourdomain.com
                 max = int(req.subdomains[1])
                 cur = int(req.subdomains[2])
                 if cur >= max:
                    # go back to the beginning of the loop
                    new_domain_name = req.subdomains[0] + "." + str(max) + ".1"
                 else:
                    # increment the current index
                    new_domain_name = req.subdomains[0] + "." + str(max) + "." + str(cur+1)
                 for i in range(len(req.subdomains)-3):
                    new_domain_name += "." + req.subdomains[i+3]
              elif req.subdomains[1].isnumeric():
                 # we are in beginning of a loop with a requested max value, e.g.:
                 # spfloop.10.yourdomain.com
                 max = int(req.subdomains[1])
                 if max < 1:
                    max = 1
                 new_domain_name = req.subdomains[0] + "." + str(max) + "." + "1"
                 for i in range(len(req.subdomains)-2):
                    new_domain_name += "." + req.subdomains[i+2]
              else:
                 # just immediate loop
                 new_domain_name = req.full_domain
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # TXT SPF
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              data = "v=spf1 include:" + new_domain_name + " ~all"
              buffer += getTypeBin("TXT") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)         ## TTL
              buffer += struct.pack(">H", len(data)+1)      ## Data length (2B)
              buffer += struct.pack(">B", len(data))        ## TXT length (1B)
              buffer += data.encode("utf-8")                ## TXT SPF value
              # log and send
              log("SPF(TXT) LOOP %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("sralias"):
              # Send multiple random SRV aliases (RFC 2782).
              # BEWARE: This could result in multiplication
              answers = int(req.subdomains[1]) if req.subdomains[1].isnumeric() else 1
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, answers, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              doms = []
              for i in range(answers):
                  # SRV alias records
                  dom = name_fuzz(resp.nfz) if hasattr(resp, "nfz") else random_chain(req.full_domain)
                  port = random.getrandbits(16)
                  bindom = convDom2Bin(dom)
                  data_len = 2+2+2+len(bindom)  # Priority (2 bytes) + Weight (2 bytes) + Port (2 bytes) + Target domain
                  buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                  buffer += getTypeBin("SRV") + getClassBin("IN")
                  buffer += struct.pack(">L", resp.TTL)    ## TTL
                  buffer += struct.pack(">H", data_len)    ## Data length
                  buffer += struct.pack(">H", 0)           ## Priority
                  buffer += struct.pack(">H", 0)           ## Weight
                  buffer += struct.pack(">H", port)        ## Port
                  buffer += bindom                         ## TargetName
                  doms.append(dom)
              # log and send
              log("%d SRV aliases: %s" % (answers, ', '.join(map(str, doms[:3])) + (', ...' if answers > 3 else '')))
              send_buf(self, buffer)
              #####################################################################
           elif req.subdomains[0][0:1] == "_" and (req.subdomains_lc[1].startswith("sralias") or req.subdomains_lc[2].startswith("sralias") or (len(req.subdomains_lc) > 3 and req.subdomains_lc[3].startswith("sralias"))):
              # Send multiple random SRV aliases (RFC 2782) for any domain name with attribute leaves 
              # (domains prefixed with an underscore), up to 3 levels e.g., '_sub._service._proto.sralias...'
              # BEWARE: This could result in multiplication
              offset = 1      # _a.sralias.10.yourdomain.com
              if req.subdomains_lc[2].startswith("sralias"):
                 offset = 2   # _a._b.sralias.10.yourdomain.com
              elif req.subdomains_lc[3].startswith("sralias"):
                 offset = 3   # _a._b._c.sralias.10.yourdomain.com
              answers = int(req.subdomains[offset+1]) if req.subdomains[offset+1].isnumeric() else 1
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, answers, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              doms = []
              for i in range(answers):
                  # SRV alias records
                  dom = name_fuzz(resp.nfz) if hasattr(resp, "nfz") else random_chain(req.full_domain)
                  port = random.getrandbits(16)
                  bindom = convDom2Bin(dom)
                  data_len = 2+2+2+len(bindom)  # Priority (2 bytes) + Weight (2 bytes) + Port (2 bytes) + Target domain
                  buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                  buffer += getTypeBin("SRV") + getClassBin("IN")
                  buffer += struct.pack(">L", resp.TTL)    ## TTL
                  buffer += struct.pack(">H", data_len)    ## Data length
                  buffer += struct.pack(">H", 0)           ## Priority
                  buffer += struct.pack(">H", 0)           ## Weight
                  buffer += struct.pack(">H", port)        ## Port
                  buffer += bindom                         ## TargetName
                  doms.append(dom)
              # log and send
              log("%d SRV aliases: %s" % (answers, ', '.join(map(str, doms[:3])) + (', ...' if answers > 3 else '')))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("srchain"):
              # Send incremented SRV alias record.
              new_domain_name = increment_chain(req.full_domain)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # SRV alias record
              port = random.getrandbits(16)
              bindom = convDom2Bin(new_domain_name)
              data_len = 2+2+2+len(bindom)  # Priority (2 bytes) + Weight (2 bytes) + Port (2 bytes) + Target domain
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("SRV") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)    ## TTL
              buffer += struct.pack(">H", data_len)    ## Data length
              buffer += struct.pack(">H", 0)           ## Priority
              buffer += struct.pack(">H", 0)           ## Weight
              buffer += struct.pack(">H", port)        ## Port
              buffer += bindom                         ## TargetName
              # log and send
              log("SRV %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.subdomains[0][0:1] == "_" and (req.subdomains_lc[1].startswith("srchain") or req.subdomains_lc[2].startswith("srchain") or (len(req.subdomains_lc) > 3 and req.subdomains_lc[3].startswith("srchain"))):
              # Send incremented SRV alias record for any domain name with attribute leaves (domains
              # prefixed with an underscore), up to 3 levels e.g., '_sub._service._proto.srchain...'
              new_domain_name = increment_chain(req.full_domain)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # SRV alias record
              port = random.getrandbits(16)
              bindom = convDom2Bin(new_domain_name)
              data_len = 2+2+2+len(bindom)  # Priority (2 bytes) + Weight (2 bytes) + Port (2 bytes) + Target domain
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("SRV") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)    ## TTL
              buffer += struct.pack(">H", data_len)    ## Data length
              buffer += struct.pack(">H", 0)           ## Priority
              buffer += struct.pack(">H", 0)           ## Weight
              buffer += struct.pack(">H", port)        ## Port
              buffer += bindom                         ## TargetName
              # log and send
              log("SRV %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("srloop"):
              # Do an alias loop in a SRV record.
              if req.subdomains[1].isnumeric() and req.subdomains[2].isnumeric():
                 # we are already in a loop, e.g.:
                 # srloop.10.4.yourdomain.com
                 max = int(req.subdomains[1])
                 cur = int(req.subdomains[2])
                 if cur >= max:
                    # go back to the beginning of the loop
                    new_domain_name = req.subdomains[0] + "." + str(max) + ".1"
                 else:
                    # increment the current index
                    new_domain_name = req.subdomains[0] + "." + str(max) + "." + str(cur+1)
                 for i in range(len(req.subdomains)-3):
                    new_domain_name += "." + req.subdomains[i+3]
              elif req.subdomains[1].isnumeric():
                 # we are in beginning of a loop with a requested max value, e.g.:
                 # srloop.10.yourdomain.com
                 max = int(req.subdomains[1])
                 if max < 1:
                    max = 1
                 new_domain_name = req.subdomains[0] + "." + str(max) + "." + "1"
                 for i in range(len(req.subdomains)-2):
                    new_domain_name += "." + req.subdomains[i+2]
              else:
                 # just immediate loop
                 new_domain_name = req.full_domain
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              port = random.getrandbits(16)
              bindom = convDom2Bin(new_domain_name)
              data_len = 2+2+2+len(bindom)  # Priority (2 bytes) + Weight (2 bytes) + Port (2 bytes) + Target domain
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("SRV") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)    ## TTL
              buffer += struct.pack(">H", data_len)    ## Data length
              buffer += struct.pack(">H", 0)           ## Priority
              buffer += struct.pack(">H", 0)           ## Weight
              buffer += struct.pack(">H", port)        ## Port
              buffer += bindom                         ## TargetName
              # log and send
              log("SRV LOOP %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.subdomains[0][0:1] == "_" and (req.subdomains_lc[1].startswith("srloop") or req.subdomains_lc[2].startswith("srloop") or (len(req.subdomains_lc) > 3 and req.subdomains_lc[3].startswith("srloop"))):
              # Do an alias loop in a SRV record for any domain name with attribute leaves (domains
              # prefixed with an underscore), up to 3 levels e.g., '_sub._service._proto.srloop...'
           
              offset=1        # _a.srloop.10.yourdomain.com
              if req.subdomains_lc[2].startswith("srloop"):
                 offset = 2   # _a._b.srloop.10.yourdomain.com
              elif req.subdomains_lc[3].startswith("srloop"):
                 offset = 3   # _a._b._c.srloop.10.yourdomain.com
           
              new_domain_name = ""
              for i in range(offset+1):
                 new_domain_name += req.subdomains[i] + "."
           
              if req.subdomains[offset+1].isnumeric() and req.subdomains[offset+2].isnumeric():
                 # we are already in a loop, e.g.:
                 # _abc.srloop.10.4.yourdomain.com
                 max = int(req.subdomains[offset+1])
                 cur = int(req.subdomains[offset+2])
                 if cur >= max:
                    # go back to the beginning of the loop
                    new_domain_name += str(max) + ".1"
                 else:
                    # increment the current index
                    new_domain_name += str(max) + "." + str(cur+1)
                 for i in range(len(req.subdomains)-3-offset):
                    new_domain_name += "." + req.subdomains[i+3+offset]
              elif req.subdomains[offset+1].isnumeric():
                 # we are in beginning of a loop with a requested max value, e.g.:
                 # _abc.srloop.10.yourdomain.com
                 max = int(req.subdomains[offset+1])
                 if max < 1:
                    max = 1
                 new_domain_name += str(max) + "." + "1"
                 for i in range(len(req.subdomains)-2-offset):
                    new_domain_name += "." + req.subdomains[i+2+offset]
              else:
                 # just immediate loop
                 new_domain_name = req.full_domain
           
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              port = random.getrandbits(16)
              bindom = convDom2Bin(new_domain_name)
              data_len = 2+2+2+len(bindom)  # Priority (2 bytes) + Weight (2 bytes) + Port (2 bytes) + Target domain
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("SRV") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)    ## TTL
              buffer += struct.pack(">H", data_len)    ## Data length
              buffer += struct.pack(">H", 0)           ## Priority
              buffer += struct.pack(">H", 0)           ## Weight
              buffer += struct.pack(">H", port)        ## Port
              buffer += bindom                         ## TargetName
              # log and send
              log("SRV LOOP %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("svalias"):
              # Send multiple random SVCB aliases (RFC 9460).
              # BEWARE: This could result in multiplication
              answers = int(req.subdomains[1]) if req.subdomains[1].isnumeric() else 1
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, answers, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              doms = []
              for i in range(answers):
                  # SVCB alias records
                  dom = name_fuzz(resp.nfz) if hasattr(resp, "nfz") else random_chain(req.full_domain)
                  bindom = convDom2Bin(dom)
                  data_len = 2+len(bindom)  # SvcPriority (2 bytes) + the target name
                  buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                  buffer += getTypeBin("SVCB") + getClassBin("IN")
                  buffer += struct.pack(">L", resp.TTL)    ## TTL
                  buffer += struct.pack(">H", data_len)    ## Data length
                  buffer += struct.pack(">H", 0)           ## SvcPriority (0 means alias mode - RFC 9460)
                  buffer += bindom                         ## TargetName
                  doms.append(dom)
              # log and send
              log("%d SVCB aliases: %s" % (answers, ', '.join(map(str, doms[:3])) + (', ...' if answers > 3 else '')))
              send_buf(self, buffer)
              #####################################################################
           elif req.subdomains[0][0:1] == "_" and (req.subdomains_lc[1].startswith("svalias") or req.subdomains_lc[2].startswith("svalias") or (len(req.subdomains_lc) > 3 and req.subdomains_lc[3].startswith("svalias"))):
              # Send multiple random SVCB aliases (RFC 9460) for any domain name with attribute leaves
              # (domains prefixed with an underscore), up to 3 levels e.g., '_sub._service._proto.svalias...'
              # BEWARE: This could result in multiplication
              offset = 1      # _a.svalias.10.yourdomain.com
              if req.subdomains_lc[2].startswith("svalias"):
                 offset = 2   # _a._b.svalias.10.yourdomain.com
              elif req.subdomains_lc[3].startswith("svalias"):
                 offset = 3   # _a._b._c.svalias.10.yourdomain.com
              answers = int(req.subdomains[offset+1]) if req.subdomains[offset+1].isnumeric() else 1
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, answers, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              doms = []
              for i in range(answers):
                  # SVCB alias records
                  dom = name_fuzz(resp.nfz) if hasattr(resp, "nfz") else random_chain(req.full_domain)
                  bindom = convDom2Bin(dom)
                  data_len = 2+len(bindom)  # SvcPriority (2 bytes) + the target name
                  buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
                  buffer += getTypeBin("SVCB") + getClassBin("IN")
                  buffer += struct.pack(">L", resp.TTL)    ## TTL
                  buffer += struct.pack(">H", data_len)    ## Data length
                  buffer += struct.pack(">H", 0)           ## SvcPriority (0 means alias mode - RFC 9460)
                  buffer += bindom                         ## TargetName
                  doms.append(dom)
              # log and send
              log("%d SVCB aliases: %s" % (answers, ', '.join(map(str, doms[:3])) + (', ...' if answers > 3 else '')))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("svchain"):
              # Send incremented SVCB alias (RFC 9460).
              new_domain_name = increment_chain(req.full_domain)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # SVCB alias record
              bindom = convDom2Bin(new_domain_name)
              data_len = 2+len(bindom)  # SvcPriority (2 bytes) + the target name
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("SVCB") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)    ## TTL
              buffer += struct.pack(">H", data_len)    ## Data length
              buffer += struct.pack(">H", 0)           ## SvcPriority (0 means alias mode - RFC 9460)
              buffer += bindom                         ## TargetName
              # log and send
              log("SVCB %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.subdomains[0][0:1] == "_" and (req.subdomains_lc[1].startswith("svchain") or req.subdomains_lc[2].startswith("svchain") or (len(req.subdomains_lc) > 3 and req.subdomains_lc[3].startswith("svchain"))):
              # Send incremented SVCB alias (RFC 9460) for any domain name with attribute leaves (domains
              # prefixed with an underscore), up to 3 levels e.g., '_sub._service._proto.svchain...'
              new_domain_name = increment_chain(req.full_domain)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # SVCB alias record
              bindom = convDom2Bin(new_domain_name)
              data_len = 2+len(bindom)  # SvcPriority (2 bytes) + the target name
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("SVCB") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)    ## TTL
              buffer += struct.pack(">H", data_len)    ## Data length
              buffer += struct.pack(">H", 0)           ## SvcPriority (0 means alias mode - RFC 9460)
              buffer += bindom                         ## TargetName
              # log and send
              log("SVCB %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("svloop"):
              # Do an alias loop in a SVCB record (SvcPriority 0).
              if req.subdomains[1].isnumeric() and req.subdomains[2].isnumeric():
                 # we are already in a loop, e.g.:
                 # svloop.10.4.yourdomain.com
                 max = int(req.subdomains[1])
                 cur = int(req.subdomains[2])
                 if cur >= max:
                    # go back to the beginning of the loop
                    new_domain_name = req.subdomains[0] + "." + str(max) + ".1"
                 else:
                    # increment the current index
                    new_domain_name = req.subdomains[0] + "." + str(max) + "." + str(cur+1)
                 for i in range(len(req.subdomains)-3):
                    new_domain_name += "." + req.subdomains[i+3]
              elif req.subdomains[1].isnumeric():
                 # we are in beginning of a loop with a requested max value, e.g.:
                 # svloop.10.yourdomain.com
                 max = int(req.subdomains[1])
                 if max < 1:
                    max = 1
                 new_domain_name = req.subdomains[0] + "." + str(max) + "." + "1"
                 for i in range(len(req.subdomains)-2):
                    new_domain_name += "." + req.subdomains[i+2]
              else:
                 # just immediate loop
                 new_domain_name = req.full_domain
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              data_len = 2+len(convDom2Bin(new_domain_name)) # SvcPriority (2 bytes) + the target name
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("SVCB") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)      ## TTL
              buffer += struct.pack(">H", data_len)      ## Data length
              buffer += struct.pack(">H", 0)             ## SvcPriority (0 means alias mode - RFC 9460)
              buffer += convDom2Bin(new_domain_name)     ## TargetName
              # log and send
              log("SVCB LOOP %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.subdomains[0][0:1] == "_" and (req.subdomains_lc[1].startswith("svloop") or req.subdomains_lc[2].startswith("svloop") or (len(req.subdomains_lc) > 3 and req.subdomains_lc[3].startswith("svloop"))):
              # Do an alias loop in a SVCB record (SvcPriority 0) for any domain name with attribute leaves
              # (domains prefixed with an underscore), up to 3 levels e.g., '_sub._service._proto.svloop...'
           
              offset=1        # _a.svloop.10.yourdomain.com
              if req.subdomains_lc[2].startswith("svloop"):
                 offset = 2   # _a._b.svloop.10.yourdomain.com
              elif req.subdomains_lc[3].startswith("svloop"):
                 offset = 3   # _a._b._c.svloop.10.yourdomain.com
           
              new_domain_name = ""
              for i in range(offset+1):
                 new_domain_name += req.subdomains[i] + "."
           
              if req.subdomains[offset+1].isnumeric() and req.subdomains[offset+2].isnumeric():
                 # we are already in a loop, e.g.:
                 # _abc.svloop.10.4.yourdomain.com
                 max = int(req.subdomains[offset+1])
                 cur = int(req.subdomains[offset+2])
                 if cur >= max:
                    # go back to the beginning of the loop
                    new_domain_name += str(max) + ".1"
                 else:
                    # increment the current index
                    new_domain_name += str(max) + "." + str(cur+1)
                 for i in range(len(req.subdomains)-3-offset):
                    new_domain_name += "." + req.subdomains[i+3+offset]
              elif req.subdomains[offset+1].isnumeric():
                 # we are in the beginning of a loop with a requested max value, e.g.:
                 # _abc.svloop.10.yourdomain.com
                 max = int(req.subdomains[offset+1])
                 if max < 1:
                    max = 1
                 new_domain_name += str(max) + "." + "1"
                 for i in range(len(req.subdomains)-2-offset):
                    new_domain_name += "." + req.subdomains[i+2+offset]
              else:
                 # just immediate loop
                 new_domain_name = req.full_domain
           
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              data_len = 2+len(convDom2Bin(new_domain_name)) # SvcPriority (2 bytes) + the target name
              buffer += b'\xc0\x0c' if resp.compress else convDom2Bin(req.full_domain)
              buffer += getTypeBin("SVCB") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)      ## TTL
              buffer += struct.pack(">H", data_len)      ## Data length
              buffer += struct.pack(">H", 0)             ## SvcPriority (0 means alias mode - RFC 9460)
              buffer += convDom2Bin(new_domain_name)     ## TargetName
              # log and send
              log("SVCB LOOP %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif req.first_subdomain.startswith("timeout"):
              # Timeout the connection
              log("sending nothing (timeout)")
              timeout_conn(self)
              #####################################################################
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
    #script_name = os.path.basename(__file__)
    #new_script_name = script_name.replace('.py', '_real.py')
    new_script_name = 'polardns_real.py'
    
    with open(__file__, 'r') as original_file, open(new_script_name, 'w') as new_file:
        for line in original_file:
            # Add modules
            if line.strip().endswith("# DO NOT REMOVE (additional features)"):
                # Load additional features from *.toml files (modules) and
                # insert them to the new file with proper indentation
                desired_indent = len(line) - len(line.lstrip())
                modules_dir = importlib.resources.files('polardns.modules')
                modules_files = modules_dir.glob('*.toml')
                for mod_file in sorted(modules_files):
                    #print("loading", mod_file) # debug
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

def main():
   if not sys.argv[0].endswith("_real.py"):
      add_modules_and_rerun() 
      exit(0)

   stamp = str(time.time()).ljust(18, "0")
   print("%s | PolarDNS v%s server starting up" % (stamp, polardns_version))
   print("%s | Using '%s' config file" % (stamp, config_file))
   ip, sep, port = config['listen_addr'].rpartition(':')
   assert sep
   ip = str(ip)
   port = int(port)
   ServerAddress = (ip, port)

   # fork for TCP and UDP listeners
   pid = os.fork()

   # each socketserver thread will have 2 global objects:
   global req
   global resp
   global proto
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

if __name__ == "__main__":
   main()
