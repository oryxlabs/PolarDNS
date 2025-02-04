import random
import struct
import string

################################
# Name fuzzer function (nfz)

def name_fuzz_malf_p0(resp):
    malf = b''
    match resp.nfz_malf:
       case 0:
          # NULL byte(s)
          for i in range(resp.nfz_subs):
             tmp = b'\x00' * resp.nfz_malf_size
             malf += struct.pack(">B", resp.nfz_malf_size) + tmp
       # # # # # # # # # # #
       case 1:
          # string made of random letter(s) or number(s) - repeated
          for i in range(resp.nfz_subs):
             tmp = random.choice(string.ascii_lowercase + string.digits) * resp.nfz_malf_size
             malf += struct.pack(">B", resp.nfz_malf_size) + bytes(tmp, "utf-8")
       # # # # # # # # # # #
       case 2:
          # string made of random letter(s) or number(s)
          for i in range(resp.nfz_subs):
             tmp = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(resp.nfz_malf_size))
             malf += struct.pack(">B", resp.nfz_malf_size) + bytes(tmp, "utf-8")
       # # # # # # # # # # #
       case 3:
          # string made of printable character(s) - repeated
          for i in range(resp.nfz_subs):
             tmp = random.choice(string.printable) * resp.nfz_malf_size
             malf += struct.pack(">B", resp.nfz_malf_size) + bytes(tmp, "utf-8")
       # # # # # # # # # # #
       case 4:
          # string made of printable character(s)
          for i in range(resp.nfz_subs):
             tmp = ''.join(random.choice(string.printable) for _ in range(resp.nfz_malf_size))
             malf += struct.pack(">B", resp.nfz_malf_size) + bytes(tmp, "utf-8")
       # # # # # # # # # # #
       case 5:
          # random byte(s) - repeated
          for i in range(resp.nfz_subs):
             tmp = random.getrandbits(8).to_bytes(1, 'big') * resp.nfz_malf_size
             malf += struct.pack(">B", resp.nfz_malf_size) + tmp
       # # # # # # # # # # #
       case 6:
          # random byte(s)
          for i in range(resp.nfz_subs):
             tmp = b''.join(random.getrandbits(8).to_bytes(1, 'big') for _ in range(resp.nfz_malf_size))
             malf += struct.pack(">B", resp.nfz_malf_size) + tmp
       # # # # # # # # # # #
       case 7:
          # byte(s) starting from 0 to 255 (repeated)
          for i in range(resp.nfz_subs):
             tmp = resp.nfz_byte_iterator.to_bytes(1, 'big') * resp.nfz_malf_size
             malf += struct.pack(">B", resp.nfz_malf_size) + tmp
             resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
       # # # # # # # # # # #
       case 8:
          # byte(s) starting from 0 to 255 (incremental)
          for i in range(resp.nfz_subs):
             tmp = b''
             for _ in range(resp.nfz_malf_size):
                tmp += resp.nfz_byte_iterator.to_bytes(1, 'big')
                resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
             malf += struct.pack(">B", resp.nfz_malf_size) + tmp
       # # # # # # # # # # #
       case 9:
          # specific byte(s)
          for i in range(resp.nfz_subs):
             tmp = resp.nfz_malf_byte * resp.nfz_malf_size
             malf += struct.pack(">B", resp.nfz_malf_size) + tmp
       # # # # # # # # # # #
    return malf

################################
# Name fuzzer function (nfz) for variants nfz1, nfz2 and nfz3 in position 1

def name_fuzz_malf_p1(resp, firstdom):
    firstdom = bytes(firstdom, "utf-8")
    malf = b''
    match resp.nfz_malf:
       case 0:
          # NULL byte(s)
          for i in range(resp.nfz_subs-1):
             tmp = b'\x00' * resp.nfz_malf_size
             malf += struct.pack(">B", resp.nfz_malf_size) + tmp
          # for the last generated subdomain, concatenate with the actual subdomain
          tmp = b'\x00' * resp.nfz_malf_size
          tmp += firstdom
          malf += struct.pack(">B", len(tmp)) + tmp
       # # # # # # # # # # #
       case 1:
          # string made of random letter(s) or number(s) - repeated
          for i in range(resp.nfz_subs-1):
             tmp = random.choice(string.ascii_lowercase + string.digits) * resp.nfz_malf_size
             malf += struct.pack(">B", resp.nfz_malf_size) + bytes(tmp, "utf-8")
          # for the last generated subdomain, concatenate with the actual subdomain
          tmp = random.choice(string.ascii_lowercase + string.digits) * resp.nfz_malf_size
          malf += struct.pack(">B", len(tmp) + len(firstdom)) + bytes(tmp, "utf-8") + firstdom
       # # # # # # # # # # #
       case 2:
          # string made of random letter(s) or number(s)
          for i in range(resp.nfz_subs-1):
             tmp = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(resp.nfz_malf_size))
             malf += struct.pack(">B", resp.nfz_malf_size) + bytes(tmp, "utf-8")
          # for the last generated subdomain, concatenate with the actual subdomain
          tmp = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(resp.nfz_malf_size))
          malf += struct.pack(">B", len(tmp) + len(firstdom)) + bytes(tmp, "utf-8") + firstdom
       # # # # # # # # # # #
       case 3:
          # string made of printable character(s) - repeated
          for i in range(resp.nfz_subs-1):
             tmp = random.choice(string.printable) * resp.nfz_malf_size
             malf += struct.pack(">B", resp.nfz_malf_size) + bytes(tmp, "utf-8")
          # for the last generated subdomain, concatenate with the actual subdomain
          tmp = random.choice(string.printable) * resp.nfz_malf_size
          malf += struct.pack(">B", len(tmp) + len(firstdom)) + bytes(tmp, "utf-8") + firstdom
       # # # # # # # # # # #
       case 4:
          # string made of printable character(s)
          for i in range(resp.nfz_subs-1):
             tmp = ''.join(random.choice(string.printable) for _ in range(resp.nfz_malf_size))
             malf += struct.pack(">B", resp.nfz_malf_size) + bytes(tmp, "utf-8")
          # for the last generated subdomain, concatenate with the actual subdomain
          tmp = ''.join(random.choice(string.printable) for _ in range(resp.nfz_malf_size))
          malf += struct.pack(">B", len(tmp) + len(firstdom)) + bytes(tmp, "utf-8") + firstdom
       # # # # # # # # # # #
       case 5:
          # random byte(s) - repeated
          for i in range(resp.nfz_subs-1):
             tmp = random.getrandbits(8).to_bytes(1, 'big') * resp.nfz_malf_size
             malf += struct.pack(">B", resp.nfz_malf_size) + tmp
          # for the last generated subdomain, concatenate with the actual subdomain
          tmp = random.getrandbits(8).to_bytes(1, 'big') * resp.nfz_malf_size
          tmp += firstdom
          malf += struct.pack(">B", len(tmp)) + tmp
       # # # # # # # # # # #
       case 6:
          # random byte(s)
          for i in range(resp.nfz_subs-1):
             tmp = b''.join(random.getrandbits(8).to_bytes(1, 'big') for _ in range(resp.nfz_malf_size))
             malf += struct.pack(">B", resp.nfz_malf_size) + tmp
          # for the last generated subdomain, concatenate with the actual subdomain
          tmp = b''.join(random.getrandbits(8).to_bytes(1, 'big') for _ in range(resp.nfz_malf_size))
          tmp += firstdom
          malf += struct.pack(">B", len(tmp)) + tmp
       # # # # # # # # # # #
       case 7:
          # byte(s) starting from 0 to 255 (repeated)
          for i in range(resp.nfz_subs-1):
             tmp = resp.nfz_byte_iterator.to_bytes(1, 'big') * resp.nfz_malf_size
             malf += struct.pack(">B", resp.nfz_malf_size) + tmp
             resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
          # for the last generated subdomain, concatenate with the actual subdomain
          tmp = resp.nfz_byte_iterator.to_bytes(1, 'big') * resp.nfz_malf_size
          tmp += firstdom
          malf += struct.pack(">B", len(tmp)) + tmp
          resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
       # # # # # # # # # # #
       case 8:
          # byte(s) starting from 0 to 255 (incremental)
          for i in range(resp.nfz_subs-1):
             tmp = b''
             for _ in range(resp.nfz_malf_size):
                tmp += resp.nfz_byte_iterator.to_bytes(1, 'big')
                resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
             malf += struct.pack(">B", resp.nfz_malf_size) + tmp
          # for the last generated subdomain, concatenate with the actual subdomain
          tmp = b''
          for _ in range(resp.nfz_malf_size):
             tmp += resp.nfz_byte_iterator.to_bytes(1, 'big')
             resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
          tmp += firstdom
          malf += struct.pack(">B", len(tmp)) + tmp
       # # # # # # # # # # #

       case 9:
          # specific byte(s)
          for i in range(resp.nfz_subs-1):
             tmp = resp.nfz_malf_byte * resp.nfz_malf_size
             malf += struct.pack(">B", resp.nfz_malf_size) + tmp
          # for the last generated subdomain, concatenate with the actual subdomain
          tmp = resp.nfz_malf_byte * resp.nfz_malf_size
          tmp += firstdom
          malf += struct.pack(">B", len(tmp)) + tmp
       # # # # # # # # # # #
    return malf

################################
# Name fuzzer function (nfz) for variants nfz1, nfz2 and nfz3 in position 2

def name_fuzz_malf_p2(resp, firstdom, suffix):
    if suffix != "":
       firstdom = bytes(firstdom, "utf-8")
       suffix = bytes(suffix, "utf-8")
    else:
       midpoint = len(firstdom) // 2
       suffix = bytes(firstdom[midpoint:], "utf-8")
       firstdom = bytes(firstdom[:midpoint], "utf-8")

    malf = b''
    if resp.nfz_subs < 2:
       # if the malformation has 1 subdomain only
       addlen = len(firstdom) + len(suffix)
       match resp.nfz_malf:
          case 0:
             # NULL byte(s)
             tmp = b'\x00' * resp.nfz_malf_size
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + tmp
          # # # # # # # # # # #
          case 1:
             # string made of random letter(s) or number(s) - repeated
             tmp = random.choice(string.ascii_lowercase + string.digits) * resp.nfz_malf_size
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + bytes(tmp, "utf-8")
          # # # # # # # # # # #
          case 2:
             # string made of random letter(s) or number(s)
             tmp = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(resp.nfz_malf_size))
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + bytes(tmp, "utf-8")
          # # # # # # # # # # #
          case 3:
             # string made of printable character(s) - repeated
             tmp = random.choice(string.printable) * resp.nfz_malf_size
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + bytes(tmp, "utf-8")
          # # # # # # # # # # #
          case 4:
             # string made of printable character(s)
             tmp = ''.join(random.choice(string.printable) for _ in range(resp.nfz_malf_size))
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + bytes(tmp, "utf-8")
          # # # # # # # # # # #
          case 5:
             # random byte(s) - repeated
             tmp = random.getrandbits(8).to_bytes(1, 'big') * resp.nfz_malf_size
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + tmp
          # # # # # # # # # # #
          case 6:
             # random byte(s)
             tmp = b''.join(random.getrandbits(8).to_bytes(1, 'big') for _ in range(resp.nfz_malf_size))
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + tmp
          # # # # # # # # # # #
          case 7:
             # byte(s) starting from 0 to 255 (repeated)
             tmp = resp.nfz_byte_iterator.to_bytes(1, 'big') * resp.nfz_malf_size
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + tmp
             resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
          # # # # # # # # # # #
          case 8:
             # byte(s) starting from 0 to 255 (incremental)
             tmp = b''
             for _ in range(resp.nfz_malf_size):
                tmp += resp.nfz_byte_iterator.to_bytes(1, 'big')
                resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + tmp
          # # # # # # # # # # #
          case 9:
             # specific byte(s)
             tmp = resp.nfz_malf_byte * resp.nfz_malf_size
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + tmp
          # # # # # # # # # # #
       malf += suffix
    else:
       # if the malformation has 2 or more subdomains
       match resp.nfz_malf:
          case 0:
             # NULL byte(s)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = firstdom
             tmp += b'\x00' * resp.nfz_malf_size
             malf += struct.pack(">B", len(tmp)) + tmp
             # now do the middle subdomains
             for i in range(resp.nfz_subs-2):
                tmp = b'\x00' * resp.nfz_malf_size
                malf += struct.pack(">B", resp.nfz_malf_size) + tmp
             # for the last generated subdomain, concatenate with the random suffix
             tmp = b'\x00' * resp.nfz_malf_size
             tmp += suffix
             malf += struct.pack(">B", len(tmp)) + tmp
          # # # # # # # # # # #
          case 1:
             # string made of random letter(s) or number(s) - repeated
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = random.choice(string.ascii_lowercase + string.digits) * resp.nfz_malf_size
             malf = struct.pack(">B", len(tmp) + len(firstdom)) + firstdom + bytes(tmp, "utf-8")
             # now do the middle subdomains
             for i in range(resp.nfz_subs-2):
                tmp = random.choice(string.ascii_lowercase + string.digits) * resp.nfz_malf_size
                malf += struct.pack(">B", resp.nfz_malf_size) + bytes(tmp, "utf-8")
             # for the last generated subdomain, concatenate with the random suffix
             tmp = random.choice(string.ascii_lowercase + string.digits) * resp.nfz_malf_size
             malf += struct.pack(">B", len(tmp) + len(suffix)) + bytes(tmp, "utf-8") + suffix
          # # # # # # # # # # #
          case 2:
             # string made of random letter(s) or number(s)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(resp.nfz_malf_size))
             malf += struct.pack(">B", len(tmp) + len(firstdom)) + firstdom + bytes(tmp, "utf-8")
             # now do the middle subdomains
             for i in range(resp.nfz_subs-2):
                tmp = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(resp.nfz_malf_size))
                malf += struct.pack(">B", resp.nfz_malf_size) + bytes(tmp, "utf-8")
             # for the last generated subdomain, concatenate with the random suffix
             tmp = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(resp.nfz_malf_size))
             malf += struct.pack(">B", len(tmp) + len(suffix)) + bytes(tmp, "utf-8") + suffix
          # # # # # # # # # # #
          case 3:
             # string made of printable character(s) - repeated
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = random.choice(string.printable) * resp.nfz_malf_size
             malf += struct.pack(">B", len(tmp) + len(firstdom)) + firstdom + bytes(tmp, "utf-8")
             # now do the middle subdomains
             for i in range(resp.nfz_subs-2):
                tmp = random.choice(string.printable) * resp.nfz_malf_size
                malf += struct.pack(">B", resp.nfz_malf_size) + bytes(tmp, "utf-8")
             # for the last generated subdomain, concatenate with the random suffix
             tmp = random.choice(string.printable) * resp.nfz_malf_size
             malf += struct.pack(">B", len(tmp) + len(suffix)) + bytes(tmp, "utf-8") + suffix
          # # # # # # # # # # #
          case 4:
             # string made of printable character(s)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = ''.join(random.choice(string.printable) for _ in range(resp.nfz_malf_size))
             malf += struct.pack(">B", len(tmp) + len(firstdom)) + firstdom + bytes(tmp, "utf-8")
             # now do the middle subdomains
             for i in range(resp.nfz_subs-2):
                tmp = ''.join(random.choice(string.printable) for _ in range(resp.nfz_malf_size))
                malf += struct.pack(">B", resp.nfz_malf_size) + bytes(tmp, "utf-8")
             # for the last generated subdomain, concatenate with the actual subdomain
             tmp = ''.join(random.choice(string.printable) for _ in range(resp.nfz_malf_size))
             malf += struct.pack(">B", len(tmp) + len(suffix)) + bytes(tmp, "utf-8") + suffix
          # # # # # # # # # # #
          case 5:
             # random byte(s) - repeated
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = firstdom
             tmp += random.getrandbits(8).to_bytes(1, 'big') * resp.nfz_malf_size
             malf += struct.pack(">B", len(tmp)) + tmp
             # now do the middle subdomains
             for i in range(resp.nfz_subs-2):
                tmp = random.getrandbits(8).to_bytes(1, 'big') * resp.nfz_malf_size
                malf += struct.pack(">B", resp.nfz_malf_size) + tmp
             # for the last generated subdomain, concatenate with the random suffix
             tmp = random.getrandbits(8).to_bytes(1, 'big') * resp.nfz_malf_size
             tmp += suffix
             malf += struct.pack(">B", len(tmp)) + tmp
          # # # # # # # # # # #
          case 6:
             # random byte(s)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = firstdom
             tmp += b''.join(random.getrandbits(8).to_bytes(1, 'big') for _ in range(resp.nfz_malf_size))
             malf += struct.pack(">B", len(tmp)) + tmp
             # now do the middle subdomains
             for i in range(resp.nfz_subs-2):
                tmp = b''.join(random.getrandbits(8).to_bytes(1, 'big') for _ in range(resp.nfz_malf_size))
                malf += struct.pack(">B", resp.nfz_malf_size) + tmp
             # for the last generated subdomain, concatenate with the random suffix
             tmp = b''.join(random.getrandbits(8).to_bytes(1, 'big') for _ in range(resp.nfz_malf_size))
             tmp += suffix
             malf += struct.pack(">B", len(tmp)) + tmp
          # # # # # # # # # # #
          case 7:
             # byte(s) starting from 0 to 255 (repeated)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = firstdom
             tmp += resp.nfz_byte_iterator.to_bytes(1, 'big') * resp.nfz_malf_size
             malf += struct.pack(">B", len(tmp)) + tmp
             resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
             # now do the middle subdomains
             for i in range(resp.nfz_subs-2):
                tmp = resp.nfz_byte_iterator.to_bytes(1, 'big') * resp.nfz_malf_size
                malf += struct.pack(">B", resp.nfz_malf_size) + tmp
                resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
             # for the last generated subdomain, concatenate with the random suffix
             tmp = resp.nfz_byte_iterator.to_bytes(1, 'big') * resp.nfz_malf_size
             tmp += suffix
             malf += struct.pack(">B", len(tmp)) + tmp
             resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
          # # # # # # # # # # #
          case 8:
             # byte(s) starting from 0 to 255 (incremental)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = firstdom
             for _ in range(resp.nfz_malf_size):
                tmp += resp.nfz_byte_iterator.to_bytes(1, 'big')
                resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
             malf += struct.pack(">B", len(tmp)) + tmp
             # now do the middle subdomains
             for i in range(resp.nfz_subs-2):
                tmp = b''
                for _ in range(resp.nfz_malf_size):
                   tmp += resp.nfz_byte_iterator.to_bytes(1, 'big')
                   resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
                malf += struct.pack(">B", resp.nfz_malf_size) + tmp
             # for the last generated subdomain, concatenate with the random suffix
             tmp = b''
             for _ in range(resp.nfz_malf_size):
                tmp += resp.nfz_byte_iterator.to_bytes(1, 'big')
                resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
             tmp += suffix
             malf += struct.pack(">B", len(tmp)) + tmp
          # # # # # # # # # # #
          case 9:
             # specific byte(s)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = firstdom
             tmp += resp.nfz_malf_byte * resp.nfz_malf_size
             malf += struct.pack(">B", len(tmp)) + tmp
             # now do the middle subdomains
             for i in range(resp.nfz_subs-2):
                tmp = resp.nfz_malf_byte * resp.nfz_malf_size
                malf += struct.pack(">B", resp.nfz_malf_size) + tmp
             # for the last generated subdomain, concatenate with the random suffix
             tmp = resp.nfz_malf_byte * resp.nfz_malf_size
             tmp += suffix
             malf += struct.pack(">B", len(tmp)) + tmp
          # # # # # # # # # # #
    return malf

################################
# Name fuzzer function (nfz) for variants nfz1, nfz2 and nfz3 in position 3

def name_fuzz_malf_p3(resp, firstdom):
    firstdom = bytes(firstdom, "utf-8")
    malf = b''
    if resp.nfz_subs < 2:
       # if the malformation has 1 subdomain only
       addlen = len(firstdom)
       match resp.nfz_malf:
          case 0:
             # NULL byte(s)
             tmp = b'\x00' * resp.nfz_malf_size
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + tmp
          # # # # # # # # # # #
          case 1:
             # string made of random letter(s) or number(s) - repeated
             tmp = random.choice(string.ascii_lowercase + string.digits) * resp.nfz_malf_size
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + bytes(tmp, "utf-8")
          # # # # # # # # # # #
          case 2:
             # string made of random letter(s) or number(s)
             tmp = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(resp.nfz_malf_size))
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + bytes(tmp, "utf-8")
          # # # # # # # # # # #
          case 3:
             # string made of printable character(s) - repeated
             tmp = random.choice(string.printable) * resp.nfz_malf_size
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + bytes(tmp, "utf-8")
          # # # # # # # # # # #
          case 4:
             # string made of printable character(s)
             tmp = ''.join(random.choice(string.printable) for _ in range(resp.nfz_malf_size))
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + bytes(tmp, "utf-8")
          # # # # # # # # # # #
          case 5:
             # random byte(s) - repeated
             tmp = random.getrandbits(8).to_bytes(1, 'big') * resp.nfz_malf_size
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + tmp
          # # # # # # # # # # #
          case 6:
             # random byte(s)
             tmp = b''.join(random.getrandbits(8).to_bytes(1, 'big') for _ in range(resp.nfz_malf_size))
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + tmp
          # # # # # # # # # # #
          case 7:
             # byte(s) starting from 0 to 255 (repeated)
             tmp = resp.nfz_byte_iterator.to_bytes(1, 'big') * resp.nfz_malf_size
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + tmp
             resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
          # # # # # # # # # # #
          case 8:
             # byte(s) starting from 0 to 255 (incremental)
             tmp = b''
             for _ in range(resp.nfz_malf_size):
                tmp += resp.nfz_byte_iterator.to_bytes(1, 'big')
                resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + tmp
          # # # # # # # # # # #
          case 9:
             # specific byte(s)
             tmp = resp.nfz_malf_byte * resp.nfz_malf_size
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + tmp
          # # # # # # # # # # #
    else:
       # if the malformation has 2 or more subdomains
       match resp.nfz_malf:
          case 0:
             # NULL byte(s)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = firstdom
             tmp += b'\x00' * resp.nfz_malf_size
             malf += struct.pack(">B", len(tmp)) + tmp
             # now do the rest of the subdomains
             for i in range(resp.nfz_subs-1):
                tmp = b'\x00' * resp.nfz_malf_size
                malf += struct.pack(">B", resp.nfz_malf_size) + tmp
          # # # # # # # # # # #
          case 1:
             # string made of random letter(s) or number(s) - repeated
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = random.choice(string.ascii_lowercase + string.digits) * resp.nfz_malf_size
             malf = struct.pack(">B", len(tmp) + len(firstdom)) + firstdom + bytes(tmp, "utf-8")
             # now do the rest of the subdomains
             for i in range(resp.nfz_subs-1):
                tmp = random.choice(string.ascii_lowercase + string.digits) * resp.nfz_malf_size
                malf += struct.pack(">B", resp.nfz_malf_size) + bytes(tmp, "utf-8")
          # # # # # # # # # # #
          case 2:
             # string made of random letter(s) or number(s)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(resp.nfz_malf_size))
             malf += struct.pack(">B", len(tmp) + len(firstdom)) + firstdom + bytes(tmp, "utf-8")
             # now do the rest of the subdomains
             for i in range(resp.nfz_subs-1):
                tmp = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(resp.nfz_malf_size))
                malf += struct.pack(">B", resp.nfz_malf_size) + bytes(tmp, "utf-8")
          # # # # # # # # # # #
          case 3:
             # string made of printable character(s) - repeated
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = random.choice(string.printable) * resp.nfz_malf_size
             malf += struct.pack(">B", len(tmp) + len(firstdom)) + firstdom + bytes(tmp, "utf-8")
             # now do the rest of the subdomains
             for i in range(resp.nfz_subs-1):
                tmp = random.choice(string.printable) * resp.nfz_malf_size
                malf += struct.pack(">B", resp.nfz_malf_size) + bytes(tmp, "utf-8")
          # # # # # # # # # # #
          case 4:
             # string made of printable character(s)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = ''.join(random.choice(string.printable) for _ in range(resp.nfz_malf_size))
             malf += struct.pack(">B", len(tmp) + len(firstdom)) + firstdom + bytes(tmp, "utf-8")
             # now do the rest of the subdomains
             for i in range(resp.nfz_subs-1):
                tmp = ''.join(random.choice(string.printable) for _ in range(resp.nfz_malf_size))
                malf += struct.pack(">B", resp.nfz_malf_size) + bytes(tmp, "utf-8")
          # # # # # # # # # # #
          case 5:
             # random byte(s) - repeated
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = firstdom
             tmp += random.getrandbits(8).to_bytes(1, 'big') * resp.nfz_malf_size
             malf += struct.pack(">B", len(tmp)) + tmp
             # now do the rest of the subdomains
             for i in range(resp.nfz_subs-1):
                tmp = random.getrandbits(8).to_bytes(1, 'big') * resp.nfz_malf_size
                malf += struct.pack(">B", resp.nfz_malf_size) + tmp
          # # # # # # # # # # #
          case 6:
             # random byte(s)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = firstdom
             tmp += b''.join(random.getrandbits(8).to_bytes(1, 'big') for _ in range(resp.nfz_malf_size))
             malf += struct.pack(">B", len(tmp)) + tmp
             # now do the rest of the subdomains
             for i in range(resp.nfz_subs-1):
                tmp = b''.join(random.getrandbits(8).to_bytes(1, 'big') for _ in range(resp.nfz_malf_size))
                malf += struct.pack(">B", resp.nfz_malf_size) + tmp
          # # # # # # # # # # #
          case 7:
             # byte(s) starting from 0 to 255 (repeated)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = firstdom
             tmp += resp.nfz_byte_iterator.to_bytes(1, 'big') * resp.nfz_malf_size
             malf += struct.pack(">B", len(tmp)) + tmp
             resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
             # now do the rest of the subdomains
             for i in range(resp.nfz_subs-1):
                tmp = resp.nfz_byte_iterator.to_bytes(1, 'big') * resp.nfz_malf_size
                malf += struct.pack(">B", resp.nfz_malf_size) + tmp
                resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
          # # # # # # # # # # #
          case 8:
             # byte(s) starting from 0 to 255 (incremental)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = firstdom
             for _ in range(resp.nfz_malf_size):
                tmp += resp.nfz_byte_iterator.to_bytes(1, 'big')
                resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
             malf += struct.pack(">B", len(tmp)) + tmp
             # now do the rest of the subdomains
             for i in range(resp.nfz_subs-1):
                tmp = b''
                for _ in range(resp.nfz_malf_size):
                   tmp += resp.nfz_byte_iterator.to_bytes(1, 'big')
                   resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
                malf += struct.pack(">B", resp.nfz_malf_size) + tmp
          # # # # # # # # # # #
          case 9:
             # specific byte(s)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = firstdom
             tmp += resp.nfz_malf_byte * resp.nfz_malf_size
             malf += struct.pack(">B", len(tmp)) + tmp
             # now do the rest of the subdomains
             for i in range(resp.nfz_subs-1):
                tmp = resp.nfz_malf_byte * resp.nfz_malf_size
                malf += struct.pack(">B", resp.nfz_malf_size) + tmp
          # # # # # # # # # # #
    return malf

################################
# Name fuzzer function (nfz) for variants nfz1, nfz2 and nfz3 in position 4

def name_fuzz_malf_p4(resp, firstdom, slddom):
    firstdom = bytes(firstdom, "utf-8")
    slddom = bytes(slddom, "utf-8")
    malf = b''
    if resp.nfz_subs < 2:
       # if the malformation has 1 subdomain only
       addlen = len(firstdom) + len(slddom)
       match resp.nfz_malf:
          case 0:
             # NULL byte(s)
             tmp = b'\x00' * resp.nfz_malf_size
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + tmp
          # # # # # # # # # # #
          case 1:
             # string made of random letter(s) or number(s) - repeated
             tmp = random.choice(string.ascii_lowercase + string.digits) * resp.nfz_malf_size
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + bytes(tmp, "utf-8")
          # # # # # # # # # # #
          case 2:
             # string made of random letter(s) or number(s)
             tmp = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(resp.nfz_malf_size))
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + bytes(tmp, "utf-8")
          # # # # # # # # # # #
          case 3:
             # string made of printable character(s) - repeated
             tmp = random.choice(string.printable) * resp.nfz_malf_size
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + bytes(tmp, "utf-8")
          # # # # # # # # # # #
          case 4:
             # string made of printable character(s)
             tmp = ''.join(random.choice(string.printable) for _ in range(resp.nfz_malf_size))
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + bytes(tmp, "utf-8")
          # # # # # # # # # # #
          case 5:
             # random byte(s) - repeated
             tmp = random.getrandbits(8).to_bytes(1, 'big') * resp.nfz_malf_size
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + tmp
          # # # # # # # # # # #
          case 6:
             # random byte(s)
             tmp = b''.join(random.getrandbits(8).to_bytes(1, 'big') for _ in range(resp.nfz_malf_size))
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + tmp
          # # # # # # # # # # #
          case 7:
             # byte(s) starting from 0 to 255 (repeated)
             tmp = resp.nfz_byte_iterator.to_bytes(1, 'big') * resp.nfz_malf_size
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + tmp
             resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
          # # # # # # # # # # #
          case 8:
             # byte(s) starting from 0 to 255 (incremental)
             tmp = b''
             for _ in range(resp.nfz_malf_size):
                tmp += resp.nfz_byte_iterator.to_bytes(1, 'big')
                resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + tmp
          # # # # # # # # # # #
          case 9:
             # specific byte(s)
             tmp = resp.nfz_malf_byte * resp.nfz_malf_size
             malf = struct.pack(">B", resp.nfz_malf_size + addlen) + firstdom + tmp
          # # # # # # # # # # #
       malf += slddom
    else:
       # if the malformation has 2 or more subdomains
       match resp.nfz_malf:
          case 0:
             # NULL byte(s)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = firstdom
             tmp += b'\x00' * resp.nfz_malf_size
             malf += struct.pack(">B", len(tmp)) + tmp
             # now do the middle subdomains
             for i in range(resp.nfz_subs-2):
                tmp = b'\x00' * resp.nfz_malf_size
                malf += struct.pack(">B", resp.nfz_malf_size) + tmp
             # for the last generated subdomain, concatenate with the sld
             tmp = b'\x00' * resp.nfz_malf_size
             tmp += slddom
             malf += struct.pack(">B", len(tmp)) + tmp
          # # # # # # # # # # #
          case 1:
             # string made of random letter(s) or number(s) - repeated
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = random.choice(string.ascii_lowercase + string.digits) * resp.nfz_malf_size
             malf = struct.pack(">B", len(tmp) + len(firstdom)) + firstdom + bytes(tmp, "utf-8")
             # now do the middle subdomains
             for i in range(resp.nfz_subs-2):
                tmp = random.choice(string.ascii_lowercase + string.digits) * resp.nfz_malf_size
                malf += struct.pack(">B", resp.nfz_malf_size) + bytes(tmp, "utf-8")
             # for the last generated subdomain, concatenate with the sld
             tmp = random.choice(string.ascii_lowercase + string.digits) * resp.nfz_malf_size
             malf += struct.pack(">B", len(tmp) + len(slddom)) + bytes(tmp, "utf-8") + slddom
          # # # # # # # # # # #
          case 2:
             # string made of random letter(s) or number(s)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(resp.nfz_malf_size))
             malf += struct.pack(">B", len(tmp) + len(firstdom)) + firstdom + bytes(tmp, "utf-8")
             # now do the middle subdomains
             for i in range(resp.nfz_subs-2):
                tmp = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(resp.nfz_malf_size))
                malf += struct.pack(">B", resp.nfz_malf_size) + bytes(tmp, "utf-8")
             # for the last generated subdomain, concatenate with the sld
             tmp = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(resp.nfz_malf_size))
             malf += struct.pack(">B", len(tmp) + len(slddom)) + bytes(tmp, "utf-8") + slddom
          # # # # # # # # # # #
          case 3:
             # string made of printable character(s) - repeated
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = random.choice(string.printable) * resp.nfz_malf_size
             malf += struct.pack(">B", len(tmp) + len(firstdom)) + firstdom + bytes(tmp, "utf-8")
             # now do the middle subdomains
             for i in range(resp.nfz_subs-2):
                tmp = random.choice(string.printable) * resp.nfz_malf_size
                malf += struct.pack(">B", resp.nfz_malf_size) + bytes(tmp, "utf-8")
             # for the last generated subdomain, concatenate with the sld
             tmp = random.choice(string.printable) * resp.nfz_malf_size
             malf += struct.pack(">B", len(tmp) + len(slddom)) + bytes(tmp, "utf-8") + slddom
          # # # # # # # # # # #
          case 4:
             # string made of printable character(s)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = ''.join(random.choice(string.printable) for _ in range(resp.nfz_malf_size))
             malf += struct.pack(">B", len(tmp) + len(firstdom)) + firstdom + bytes(tmp, "utf-8")
             # now do the middle subdomains
             for i in range(resp.nfz_subs-2):
                tmp = ''.join(random.choice(string.printable) for _ in range(resp.nfz_malf_size))
                malf += struct.pack(">B", resp.nfz_malf_size) + bytes(tmp, "utf-8")
             # for the last generated subdomain, concatenate with the actual subdomain
             tmp = ''.join(random.choice(string.printable) for _ in range(resp.nfz_malf_size))
             malf += struct.pack(">B", len(tmp) + len(slddom)) + bytes(tmp, "utf-8") + slddom
          # # # # # # # # # # #
          case 5:
             # random byte(s) - repeated
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = firstdom
             tmp += random.getrandbits(8).to_bytes(1, 'big') * resp.nfz_malf_size
             malf += struct.pack(">B", len(tmp)) + tmp
             # now do the middle subdomains
             for i in range(resp.nfz_subs-2):
                tmp = random.getrandbits(8).to_bytes(1, 'big') * resp.nfz_malf_size
                malf += struct.pack(">B", resp.nfz_malf_size) + tmp
             # for the last generated subdomain, concatenate with the sld
             tmp = random.getrandbits(8).to_bytes(1, 'big') * resp.nfz_malf_size
             tmp += slddom
             malf += struct.pack(">B", len(tmp)) + tmp
          # # # # # # # # # # #
          case 6:
             # random byte(s)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = firstdom
             tmp += b''.join(random.getrandbits(8).to_bytes(1, 'big') for _ in range(resp.nfz_malf_size))
             malf += struct.pack(">B", len(tmp)) + tmp
             # now do the middle subdomains
             for i in range(resp.nfz_subs-2):
                tmp = b''.join(random.getrandbits(8).to_bytes(1, 'big') for _ in range(resp.nfz_malf_size))
                malf += struct.pack(">B", resp.nfz_malf_size) + tmp
             # for the last generated subdomain, concatenate with the sld
             tmp = b''.join(random.getrandbits(8).to_bytes(1, 'big') for _ in range(resp.nfz_malf_size))
             tmp += slddom
             malf += struct.pack(">B", len(tmp)) + tmp
          # # # # # # # # # # #
          case 7:
             # byte(s) starting from 0 to 255 (repeated)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = firstdom
             tmp += resp.nfz_byte_iterator.to_bytes(1, 'big') * resp.nfz_malf_size
             malf += struct.pack(">B", len(tmp)) + tmp
             resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
             # now do the middle subdomains
             for i in range(resp.nfz_subs-2):
                tmp = resp.nfz_byte_iterator.to_bytes(1, 'big') * resp.nfz_malf_size
                malf += struct.pack(">B", resp.nfz_malf_size) + tmp
                resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
             # for the last generated subdomain, concatenate with the sld
             tmp = resp.nfz_byte_iterator.to_bytes(1, 'big') * resp.nfz_malf_size
             tmp += slddom
             malf += struct.pack(">B", len(tmp)) + tmp
             resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
          # # # # # # # # # # #
          case 8:
             # byte(s) starting from 0 to 255 (incremental)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = firstdom
             for _ in range(resp.nfz_malf_size):
                tmp += resp.nfz_byte_iterator.to_bytes(1, 'big')
                resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
             malf += struct.pack(">B", len(tmp)) + tmp
             # now do the middle subdomains
             for i in range(resp.nfz_subs-2):
                tmp = b''
                for _ in range(resp.nfz_malf_size):
                   tmp += resp.nfz_byte_iterator.to_bytes(1, 'big')
                   resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
                malf += struct.pack(">B", resp.nfz_malf_size) + tmp
             # for the last generated subdomain, concatenate with the sld
             tmp = b''
             for _ in range(resp.nfz_malf_size):
                tmp += resp.nfz_byte_iterator.to_bytes(1, 'big')
                resp.nfz_byte_iterator = (resp.nfz_byte_iterator + 1) % 256
             tmp += slddom
             malf += struct.pack(">B", len(tmp)) + tmp
          # # # # # # # # # # #
          case 9:
             # specific byte(s)
             # for the first generated subdomain, concatenate with the actual subdomain
             tmp = firstdom
             tmp += resp.nfz_malf_byte * resp.nfz_malf_size
             malf += struct.pack(">B", len(tmp)) + tmp
             # now do the middle subdomains
             for i in range(resp.nfz_subs-2):
                tmp = resp.nfz_malf_byte * resp.nfz_malf_size
                malf += struct.pack(">B", resp.nfz_malf_size) + tmp
             # for the last generated subdomain, concatenate with the sld
             tmp = resp.nfz_malf_byte * resp.nfz_malf_size
             tmp += slddom
             malf += struct.pack(">B", len(tmp)) + tmp
          # # # # # # # # # # #
    return malf

################################

