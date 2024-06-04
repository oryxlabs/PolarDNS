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

polardns_version = "1.3"

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

globalttl = int(config['ttl'])
globalsleep = float(config['sleep'])

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
# Name fuzzer function (nfz)

def name_fuzz(n):
    rand_suffix = '{:06d}'.format(random.getrandbits(20) % 1000000)
    match n:
      ######################
      case 0:
         # NULL byte(s)
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            tmp = b'\x00' * resp.nfz_sv
            dom = struct.pack(">B", resp.nfz_sv) + tmp + b'\x00'
         else:
            dom = b'\x01\x00\x00'
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 1:
         # <ROOT> domain
         dom = b'\x00'
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 2:
         # random byte(s)
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            tmp = b''.join(random.getrandbits(8).to_bytes(1, 'big') for _ in range(resp.nfz_sv))
            dom = struct.pack(">B", resp.nfz_sv) + tmp + b'\x00'
         else:
            dom = b'\x01' + random.getrandbits(8).to_bytes(1, 'big') + b'\x00'
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 3:
         # random byte(s) - repeated
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            tmp = random.getrandbits(8).to_bytes(1, 'big') * resp.nfz_sv
            dom = struct.pack(">B", resp.nfz_sv) + tmp + b'\x00'
         else:
            dom = b'\x01' + random.getrandbits(8).to_bytes(1, 'big') + b'\x00'
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 4:
         # byte(s) starting from 0 to 255 (incremental)
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            tmp = b''
            for _ in range(resp.nfz_sv):
               tmp += resp.nfz_byte_iterator.to_bytes(1, 'big')
               resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
            dom = struct.pack(">B", resp.nfz_sv) + tmp + b'\x00'
         else:
            dom = b'\x01' + resp.nfz_byte_iterator.to_bytes(1, 'big') + b'\x00'
            resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 5:
         # byte(s) starting from 0 to 255 (repeated)
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            tmp = resp.nfz_byte_iterator.to_bytes(1, 'big') * resp.nfz_sv
            dom = struct.pack(">B", resp.nfz_sv) + tmp + b'\x00'
         else:
            dom = b'\x01' + resp.nfz_byte_iterator.to_bytes(1, 'big') + b'\x00'
         resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 6:
         # max label sized (63) random binary string
         siz = 63
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the string more times
            # Note: subvariant 4 and above will already exceed the max domain size (255)
            dom = b''
            for _ in range(resp.nfz_sv):
               data = bytes([random.getrandbits(8) for _ in range(siz)])
               dom += struct.pack(">B", len(data)) + data
            dom += b"\x00"
         else:
            data = bytes([random.getrandbits(8) for _ in range(siz)])
            dom = struct.pack(">B", len(data)) + data + b"\x00"
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 7:
         # max label sized (63) random string made of printable characters
         siz = 63
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the string more times
            # Note: subvariant 4 and above will already exceed the max domain size (255)
            dom = ''.join(random.choice(string.printable) for _ in range(siz))
            for _ in range(resp.nfz_sv-1):
               dom += "." + ''.join(random.choice(string.printable) for _ in range(siz))
         else:
            dom = ''.join(random.choice(string.printable) for _ in range(siz))
      ######################
      case 8:
         # max label sized (63) random string made of letters and numbers
         siz = 63
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the string more times
            # Note: subvariant 4 and above will already exceed the max domain size (255)
            dom = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(siz))
            for _ in range(resp.nfz_sv-1):
               dom += "." + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(siz))
         else:
            dom = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(siz))
      ######################
      case 9:
         # random 1 byte long subdomain(s)
         dom = b'\x01' + random.getrandbits(8).to_bytes(1, 'big')
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            for _ in range(resp.nfz_sv-1):
               dom += b'\x01' + random.getrandbits(8).to_bytes(1, 'big')
         dom += b'\x00'
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 10:
         # random 1 byte long subdomain(s) made of printable character
         siz = 1
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the string more times
            # Note: subvariant 4 and above will already exceed the max domain size (255)
            dom = ''.join(random.choice(string.printable) for _ in range(siz))
            for _ in range(resp.nfz_sv-1):
               dom += "." + ''.join(random.choice(string.printable) for _ in range(siz))
         else:
            dom = ''.join(random.choice(string.printable) for _ in range(siz))
      ######################
      case 11:
         # random 1 byte long subdomain(s) made of letters and numbers
         siz = 1
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the string more times
            # Note: subvariant 4 and above will already exceed the max domain size (255)
            dom = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(siz))
            for _ in range(resp.nfz_sv-1):
               dom += "." + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(siz))
         else:
            dom = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(siz))
      ######################
      case 12:
         # 1 byte long subdomain(s) from \x00 to \xff (incremental)
         dom = b'\x01' + resp.nfz_byte_iterator.to_bytes(1, 'big')
         resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            for _ in range(resp.nfz_sv-1):
               dom += b'\x01' + resp.nfz_byte_iterator.to_bytes(1, 'big')
               resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
         dom += b'\x00'
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 13:
         # 1 byte long subdomain(s) from \x00 to \xff (repeated)
         dom = b'\x01' + resp.nfz_byte_iterator.to_bytes(1, 'big')
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            for _ in range(resp.nfz_sv-1):
               dom += b'\x01' + resp.nfz_byte_iterator.to_bytes(1, 'big')
         dom += b'\x00'
         resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 14:
         # always123456.<NULL byte(s)>.yourdomain.com
         dom = b'\x0c' + bytes("always" + rand_suffix, "utf-8")
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            tmp = b'\x00' * resp.nfz_sv
            dom += struct.pack(">B", resp.nfz_sv) + tmp
         else:
            dom += b'\x01\x00'
         dom += convDom2Bin(req.sld_tld_domain)
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 15:
         # always123456.<random byte(s)>.yourdomain.com
         dom = b'\x0c' + bytes("always" + rand_suffix, "utf-8")
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            tmp = b''.join(random.getrandbits(8).to_bytes(1, 'big') for _ in range(resp.nfz_sv))
            dom += struct.pack(">B", resp.nfz_sv) + tmp
         else:
            dom += b'\x01' + random.getrandbits(8).to_bytes(1, 'big')
         dom += convDom2Bin(req.sld_tld_domain)
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 16:
         # always123456.<random byte(s)>.yourdomain.com (repeated)
         dom = b'\x0c' + bytes("always" + rand_suffix, "utf-8")
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            tmp = random.getrandbits(8).to_bytes(1, 'big') * resp.nfz_sv
            dom += struct.pack(">B", resp.nfz_sv) + tmp
         else:
            dom += b'\x01' + random.getrandbits(8).to_bytes(1, 'big')
         dom += convDom2Bin(req.sld_tld_domain)
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 17:
         # always123456.<byte(s) starting from 0 to 255>.yourdomain.com (incremental)
         dom = b'\x0c' + bytes("always" + rand_suffix, "utf-8")
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            tmp = b''
            for _ in range(resp.nfz_sv):
               tmp += resp.nfz_byte_iterator.to_bytes(1, 'big')
               resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
            dom += struct.pack(">B", resp.nfz_sv) + tmp
         else:
            dom += b'\x01' + resp.nfz_byte_iterator.to_bytes(1, 'big')
            resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
         dom += convDom2Bin(req.sld_tld_domain)
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 18:
         # always123456.<byte(s) starting from 0 to 255>.yourdomain.com (repeated)
         dom = b'\x0c' + bytes("always" + rand_suffix, "utf-8")
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            tmp = resp.nfz_byte_iterator.to_bytes(1, 'big') * resp.nfz_sv
            dom += struct.pack(">B", resp.nfz_sv) + tmp
         else:
            dom += b'\x01' + resp.nfz_byte_iterator.to_bytes(1, 'big')
         dom += convDom2Bin(req.sld_tld_domain)
         resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 19:
         # always.123456.<random 1 byte long subdomain(s)>.yourdomain.com
         dom = b'\x0c' + bytes("always" + rand_suffix, "utf-8")
         dom += b'\x01' + random.getrandbits(8).to_bytes(1, 'big')
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            for _ in range(resp.nfz_sv-1):
               dom += b'\x01' + random.getrandbits(8).to_bytes(1, 'big')
         dom += convDom2Bin(req.sld_tld_domain)
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 20:
         # always123456.<random 1 byte long subdomain(s) made of printable character>.yourdomain.com
         siz = 1
         dom = "always" + rand_suffix + "."
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the string more times
            # Note: subvariant 4 and above will already exceed the max domain size (255)
            dom += ''.join(random.choice(string.printable) for _ in range(siz))
            for _ in range(resp.nfz_sv-1):
               dom += "." + ''.join(random.choice(string.printable) for _ in range(siz))
         else:
            dom += ''.join(random.choice(string.printable) for _ in range(siz))
         dom += "." + req.sld_tld_domain
      ######################
      case 21:
         # always123456.<random 1 byte long subdomain(s) made of a letter or a number>.yourdomain.com
         siz = 1
         dom = "always" + rand_suffix + "."
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the string more times
            # Note: subvariant 4 and above will already exceed the max domain size (255)
            dom += ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(siz))
            for _ in range(resp.nfz_sv-1):
               dom += "." + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(siz))
         else:
            dom += ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(siz))
         dom += "." + req.sld_tld_domain
      ######################
      case 22:
         # always123456.<1 byte long subdomain(s) from \x00 to \xff>.yourdomain.com (incremental)
         dom = b'\x0c' + bytes("always" + rand_suffix, "utf-8")
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            for _ in range(resp.nfz_sv):
               dom += b'\x01' + resp.nfz_byte_iterator.to_bytes(1, 'big')
               resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
         dom += convDom2Bin(req.sld_tld_domain)
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 23:
         # always123456.<1 byte long subdomain(s) from \x00 to \xff>.yourdomain.com (repeated)
         dom = b'\x0c' + bytes("always" + rand_suffix, "utf-8")
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            for _ in range(resp.nfz_sv):
               dom += b'\x01' + resp.nfz_byte_iterator.to_bytes(1, 'big')
         dom += convDom2Bin(req.sld_tld_domain)
         resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 24:
         # <NULL byte(s)>always123456.yourdomain.com
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            tmp = b'\x00' * resp.nfz_sv
            dom = struct.pack(">B", resp.nfz_sv+12) + tmp
         else:
            dom = struct.pack(">B", 1+12) + b'\x00'
         dom += bytes("always" + rand_suffix, "utf-8")
         dom += convDom2Bin(req.sld_tld_domain)
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 25:
         # <random byte(s)>always123456.yourdomain.com (truly random)
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            tmp = b''.join(random.getrandbits(8).to_bytes(1, 'big') for _ in range(resp.nfz_sv))
            dom = struct.pack(">B", resp.nfz_sv+12) + tmp
         else:
            dom = struct.pack(">B", 1+12) + random.getrandbits(8).to_bytes(1, 'big')
         dom += bytes("always" + rand_suffix, "utf-8")
         dom += convDom2Bin(req.sld_tld_domain)
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 26:
         # <random byte(s)>always123456.yourdomain.com (repeated)
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            tmp = random.getrandbits(8).to_bytes(1, 'big') * resp.nfz_sv
            dom = struct.pack(">B", resp.nfz_sv+12) + tmp
         else:
            dom = struct.pack(">B", 1+12) + random.getrandbits(8).to_bytes(1, 'big')
         dom += bytes("always" + rand_suffix, "utf-8")
         dom += convDom2Bin(req.sld_tld_domain)
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 27:
         # <random byte(s) starting from 0 to 255>always123456.yourdomain.com (incremental)
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            tmp = b''
            for _ in range(resp.nfz_sv):
               tmp += resp.nfz_byte_iterator.to_bytes(1, 'big')
               resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
            dom = struct.pack(">B", resp.nfz_sv+12) + tmp
         else:
            dom = struct.pack(">B", 1+12) + resp.nfz_byte_iterator.to_bytes(1, 'big')
            resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
         dom += bytes("always" + rand_suffix, "utf-8")
         dom += convDom2Bin(req.sld_tld_domain)
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 28:
         # <random byte(s) starting from 0 to 255>always123456.yourdomain.com (repeated)
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            tmp = resp.nfz_byte_iterator.to_bytes(1, 'big') * resp.nfz_sv
            dom = struct.pack(">B", resp.nfz_sv+12) + tmp
         else:
            dom = struct.pack(">B", 1+12) + resp.nfz_byte_iterator.to_bytes(1, 'big')
         dom += bytes("always" + rand_suffix, "utf-8")
         dom += convDom2Bin(req.sld_tld_domain)
         resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 29:
         # always123456.yourdomain.com<NULL byte(s)>
         dom = b'\x0c' + bytes("always" + rand_suffix, "utf-8")
         dom += struct.pack(">B", len(req.sld)) + bytes(req.sld, "utf-8")
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            tmp = b'\x00' * resp.nfz_sv
            dom += struct.pack(">B", resp.nfz_sv+len(req.tld)) + bytes(req.tld, "utf-8") + tmp
         else:
            dom += struct.pack(">B", 1+len(req.tld)) + bytes(req.tld, "utf-8") + b'\x00'
         dom += b'\x00'
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 30:
         # always123456.yourdomain.com<random byte(s)> (truly random)
         dom = b'\x0c' + bytes("always" + rand_suffix, "utf-8")
         dom += struct.pack(">B", len(req.sld)) + bytes(req.sld, "utf-8")
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            tmp = b''.join(random.getrandbits(8).to_bytes(1, 'big') for _ in range(resp.nfz_sv))
            dom += struct.pack(">B", resp.nfz_sv+len(req.tld)) + bytes(req.tld, "utf-8") + tmp
         else:
            dom += struct.pack(">B", 1+len(req.tld)) + bytes(req.tld, "utf-8") + random.getrandbits(8).to_bytes(1, 'big')
         dom += b'\x00'
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 31:
         # always123456.yourdomain.com<random byte(s)> (repeated)
         dom = b'\x0c' + bytes("always" + rand_suffix, "utf-8")
         dom += struct.pack(">B", len(req.sld)) + bytes(req.sld, "utf-8")
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            tmp = random.getrandbits(8).to_bytes(1, 'big') * resp.nfz_sv
            dom += struct.pack(">B", resp.nfz_sv+len(req.tld)) + bytes(req.tld, "utf-8") + tmp
         else:
            dom += struct.pack(">B", 1+len(req.tld)) + bytes(req.tld, "utf-8") + random.getrandbits(8).to_bytes(1, 'big')
         dom += b'\x00'
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 32:
         # always123456.yourdomain.com<byte(s) starting from 0 to 255> (incremental)
         dom = b'\x0c' + bytes("always" + rand_suffix, "utf-8")
         dom += struct.pack(">B", len(req.sld)) + bytes(req.sld, "utf-8")
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            tmp = b''
            for _ in range(resp.nfz_sv):
               tmp += resp.nfz_byte_iterator.to_bytes(1, 'big')
               resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
            dom += struct.pack(">B", resp.nfz_sv+len(req.tld)) + bytes(req.tld, "utf-8") + tmp
         else:
            dom += struct.pack(">B", 1+len(req.tld)) + bytes(req.tld, "utf-8") + resp.nfz_byte_iterator.to_bytes(1, 'big')
            resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
         dom += b'\x00'
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 33:
         # always123456.yourdomain.com<byte(s) starting from 0 to 255> (repeated)
         dom = b'\x0c' + bytes("always" + rand_suffix, "utf-8")
         dom += struct.pack(">B", len(req.sld)) + bytes(req.sld, "utf-8")
         if hasattr(resp, "nfz_sv"):
            # if there is a sub-variant, it means we want to repeat the byte more times
            tmp = resp.nfz_byte_iterator.to_bytes(1, 'big') * resp.nfz_sv
            dom += struct.pack(">B", resp.nfz_sv+len(req.tld)) + bytes(req.tld, "utf-8") + tmp
         else:
            dom += struct.pack(">B", 1+len(req.tld)) + bytes(req.tld, "utf-8") + resp.nfz_byte_iterator.to_bytes(1, 'big')
         dom += b'\x00'
         resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
         resp.DOM_ALREADY_CONVERTED = 1
      ######################
      case 34:
         # http://always123456.yourdomain.com/
         dom = "http://always" + rand_suffix + "." + req.sld_tld_domain + "/"
      ######################
      case 35:
         # http://always123456.yourdomain.com:80/
         dom = "http://always" + rand_suffix + "." + req.sld_tld_domain + ":80/"
      ######################
      case 36:
         # https://always123456.yourdomain.com/
         dom = "https://always" + rand_suffix + "." + req.sld_tld_domain + "/"
      ######################
      case 37:
         # https://always123456.yourdomain.com:443/
         dom = "https://always" + rand_suffix + "." + req.sld_tld_domain + ":443/"
      ######################
      case 38:
         # always123456.yourdomain.com:80
         dom = "always" + rand_suffix + "." + req.sld_tld_domain + ":80"
      ######################
      case 39:
         # always123456.yourdomain.com:443
         dom = "always" + rand_suffix + "." + req.sld_tld_domain + ":443"
      ######################
      case 40:
         # 1.2.3.4 (in DNS name notation as 4 labels)
         dom = "1.2.3.4"
      ######################
      case 41:
         # 1.2.3.4:80 (in DNS name notation as 4 labels)
         dom = "1.2.3.4:80"
      ######################
      case 42:
         # 1.2.3.4 (in DNS name notation as 1 label)
         dom = "1<DOT>2<DOT>3<DOT>4"
      ######################
      case 43:
         # 1.2.3.4:80 (in DNS name notation as 1 label)
         dom = "1<DOT>2<DOT>3<DOT>4:80"
      ######################
      case 44:
         # <OUR-IP-ADDRESS> (in DNS name notation as 4 labels)
         dom = ZONEFILE["ns1." + req.sld_tld_domain]["A"]
      ######################
      case 45:
         # <OUR-IP-ADDRESS>:80 (in DNS name notation as 4 labels)
         ourip = ZONEFILE["ns1." + req.sld_tld_domain]["A"]
         dom = ourip + ":80"
      ######################
      case _:
         # hello (default case)
         dom = "hello"
      ######################
    return dom

################################
# Function to increment chainXXX if there is one

def increment_chain(req_domain):
   req_subdomains = req_domain.split(".")
   new_subdomains = req_subdomains

   first_subdomain = req_subdomains[0]
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

   print("new domain name:", new_domain_name) if debug else True
   return new_domain_name

################################
# Function to generate random chainXXX

def random_chain(req_domain):
   req_subdomains = req_domain.split(".")
   new_subdomains = req_subdomains

   first_subdomain = req_subdomains[0]
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

   # replace the subdomain with new incremented index (if there was no index, it will be "chain1")
   new_subdomains[0] = new_subdomain

   # now construct a nice full domain name and return it
   new_domain_name = new_subdomain
   for l in range(1, len(new_subdomains)):
      new_domain_name += "." + new_subdomains[l]

   print("new domain name:", new_domain_name) if debug else True
   return new_domain_name

################################
# Function for printing messages on the console

def log(m):
    stamp = str(time.time()).ljust(18, "0")
    end = ""
    if resp.len != 0:
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
   if resp.len != 0:
      tocalc = resp.len # override length by added '.lenXXX.' in the domain name
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
        if debug:
           req.HEX = binascii.b2a_hex(req.RAW)
           print("Request (RAW):", proto, req.RAW)
           print("Request (HEX):", proto, req.HEX)

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
        req.QURR  = int.from_bytes(req.RAW[4:6], "big")
        req.ANRR  = int.from_bytes(req.RAW[6:8], "big")
        req.AURR  = int.from_bytes(req.RAW[8:10], "big")
        req.ADRR  = int.from_bytes(req.RAW[10:12], "big")

        # decode the domain name in the question
        req.subdomains = []    # sOMeThINg whaTEVeR ANytHinG cOM
        req.subdomains_lc = [] # something whatever anything com
        req.full_domain = ""      # sOMeThINg.whaTEVeR.ANytHinG.cOM
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
            req.type_bin = req.RAW[int(offset):int(offset)+2]
            req.type_int = struct.unpack(">H", req.type_bin)[0]
            req.type_str = getTypeName(req.type_int)

            req.class_bin = req.RAW[int(offset)+2:int(offset)+4]
            req.class_int = struct.unpack(">H", req.class_bin)[0]
            req.class_str = getClassName(req.class_int)
        except:
           stamp = str(time.time()).ljust(18, "0")
           print("%s | %s ? %s | ERROR: Cannot parse query | (len: %d) %s" % (stamp, req.info, req.full_domain.strip(), len(req.RAW)+2, binascii.b2a_hex(req.RAW)))
           return

        print("Request from %s %s %s" % (req.info, req.type_str, req.full_domain)) if debug else True

        ###############################################
        # 2. Extract SLD+TLD to see later if we are authoritative or not

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
        #  flgs  - set custom flags, either in hex (0x????) or in decimal
        #          (0-65535) or rand to generate random, e.g.: .flgsrand.
        #  nfz   - enable name fuzzer which can generate various illegal
        #          and malformed domain names
        #  qurr  - set custom number of Questions in the DNS header
        #  anrr  - set custom number of Answer RRs in the DNS header
        #  aurr  - set custom number of Authority RRs in the DNS header
        #  adrr  - set custom number of Additional RRs in the DNS header

        resp.sleep = globalsleep
        resp.TTL = globalttl
        resp.len = 0
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
            #######################
            elif label.startswith("ttl"):      # custom TTL requested
               if label[3:].isnumeric():
                  resp.TTL = int(label[3:])
            #######################
            elif label.startswith("len"):      # TCP length override
               if label[3:].isnumeric():
                  n = int(label[3:])
                  if n > 65535: n = 65535
                  resp.len = n
            #######################
            elif label == "newid":             # new random transaction ID
               resp.ID = struct.pack(">H", random.getrandbits(16))
               addcustomlog("NEWID")
            #######################
            elif label.startswith("flgs"):     # set custom flags in the DNS header
               if label[4:].isnumeric():
                  n = int(label[4:])
                  if n > 65535: n = 65535
                  resp.FLGS = struct.pack(">H", n)
                  addcustomlog("FLGS:" + hex(n))
               elif label[4:6] == "0x":
                  n = int(label[6:], base=16)
                  if n > 65535: n = 65535
                  resp.FLGS = struct.pack(">H", n)
                  addcustomlog("FLGS:" + hex(n))
               elif label[4:8] == "rand":
                  n = random.getrandbits(16)
                  resp.FLGS = struct.pack(">H", n)
                  addcustomlog("FLGS:" + hex(n))
            #######################
            elif label.startswith("qurr"):     # set custom number of questions in the DNS header
               if label[4:].isnumeric():
                  n = int(label[4:])
                  if n > 65535: n = 65535
                  resp.QURR = n
                  addcustomlog("QURR:" + str(resp.QURR))
            #######################
            elif label.startswith("anrr"):     # set custom number of answer RR in the DNS header
               if label[4:].isnumeric():
                  n = int(label[4:])
                  if n > 65535: n = 65535
                  resp.ANRR = n
                  addcustomlog("ANRR:" + str(resp.ANRR))
            #######################
            elif label.startswith("aurr"):     # set custom number of authority RR in the DNS header
               if label[4:].isnumeric():
                  n = int(label[4:])
                  if n > 65535: n = 65535
                  resp.AURR = n
                  addcustomlog("AURR:" + str(resp.AURR))
            #######################
            elif label.startswith("adrr"):     # set custom number of additional RR in the DNS header
               if label[4:].isnumeric():
                  n = int(label[4:])
                  if n > 65535: n = 65535
                  resp.ADRR = n
                  addcustomlog("ADRR:" + str(resp.ADRR))
            #######################
            elif label == "noq":               # remove the question from the response query section
               resp.noq = 0
               addcustomlog("NOQ")
            #######################
            elif label.startswith("nfz"):      # enable name fuzzer
               if label[3:].isnumeric():
                  resp.nfz = int(label[3:])    # the variant
                  if req.subdomains_lc[index+1].isnumeric():       # does the next subdomain contain only a number?
                     resp.nfz_sv = int(req.subdomains_lc[index+1]) # if yes, then it is a sub-variant
                     addcustomlog("NFZ:" + str(resp.nfz) + "." + str(resp.nfz_sv))
                  else:
                     addcustomlog("NFZ:" + str(resp.nfz))
                  resp.nfz_byte_iterator = 0   # to make sure we keep track of values from \x00 to \xff
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
           log("just closing connection")
           time.sleep(resp.sleep)
           close_conn(self)
        #####################################################################
        elif req.sld_tld_domain not in OURDOMAINS:
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
              buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
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
              ip = "2.3.4.5"
              ### DNS header ########
              buffer = prep_dns_header(b'\x84\x00', resp.QURR, 1, 0, 0)
              ### QUESTION SECTION ########
              if resp.noq: buffer += convDom2Bin(req.full_domain) + req.type_bin + req.class_bin
              ### ANSWER SECTION ########
              # A
              buffer += convDom2Bin(req.full_domain) + getTypeBin("A") + getClassBin("IN")
              buffer += struct.pack(">L", resp.TTL)    ## TTL
              buffer += struct.pack(">H", 4)           ## Data length
              buffer += socket.inet_aton(ip)           ## IP
              # log and send
              log("A %s" % (ip))
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
              buffer += convDom2Bin(req.full_domain) + getTypeBin("TXT") + getClassBin("CH")
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
                        mod_lines = mod['module']['code'].splitlines()
                        mod_indent = len(mod_lines[0]) - len(mod_lines[0].lstrip())
                        if mod_lines[0].strip().startswith("if"):
                            # if the first line starts with "if", change it to "elif"
                            mod_lines[0] = ' ' * mod_indent + 'elif' + mod_lines[0].lstrip()[2:]
                        # now, write each line of the module code with the correct indentation
                        if mod_indent > desired_indent:
                           torm = mod_indent-desired_indent
                           indented_fixed_code = '\n'.join([line[torm:] for line in mod_lines])
                        else:
                           indent = desired_indent - mod_indent
                           indented_fixed_code = '\n'.join([' ' * indent + line for line in mod_lines])
                        new_file.write(indented_fixed_code + '\n')
            new_file.write(line)

    # Replace the current process with the new script, passing all arguments
    os.execvp(sys.executable, ['python', new_script_name] + sys.argv[1:])

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

