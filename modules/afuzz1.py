def main(labels, *args, **kwargs):
    """
        name = "afuzz1"
        info = "Single A record with arbitrary byte"
        desc = "Respond with A record containing arbitrary byte in the middle of the name in the ANSWER section, essentially giving an incorrect answer."
        type = "feature"
        author = "ivan.jedek@oryxlabs.com"
    """
    if labels[0].startswith("afuzz1"):
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
