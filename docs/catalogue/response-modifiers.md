# PolarDNS catalogue - Response modifiers
1. [General features](general-features.md)
1. [Response modifiers](response-modifiers.md)
	- [Set random transaction ID (newid)](#set-random-transaction-id-newid)
	- [Set truncated flag - force TCP mode (tc)](#set-truncated-flag---force-tcp-mode-tc)
	- [Remove the query section (noq)](#remove-the-query-section-noq)
	- [Add a delay / latency (slp)](#add-a-delay--latency-slp)
	- [Set custom TTL value (ttl)](#set-custom-ttl-value-ttl)
	- [Set custom length in TCP (len)](#set-custom-length-in-tcp-len)
	- [Set custom flags in the header (flgs)](#set-custom-flags-in-the-header-flgs)
	- [Set question RRs in the header (qurr)](#set-question-rrs-in-the-header-qurr)
	- [Set answer RRs in the header (anrr)](#set-answer-rrs-in-the-header-anrr)
	- [Set authority RRs in the header (aurr)](#set-authority-rrs-in-the-header-aurr)
	- [Set additional RRs in the header (adrr)](#set-additional-rrs-in-the-header-adrr)
1. [CNAME fuzzing](cname-fuzzing.md)
1. [Bad compression](bad-compression.md)
1. [Empty responses](empty-responses.md)
1. [Record injections](record-injections.md)

Response modifiers can modify the response e.g. alter the DNS header, introduce arbitrary delays (latencies) and other things.
These modifiers work with any request, can be specified anywhere in the domain name as a standalone label, and also can be combined with each other.

##
### Set random transaction ID (newid)
Generate a new random transaction ID in the response.

<table>
<tr><td>format:</td><td>anything.newid.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig hello.newid.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig hello.newid.yourdomain.com @127.0.0.1
;; Warning: ID mismatch: expected ID 34139, got 57646
;; communications error to 127.0.0.1#53: timed out
;; Warning: ID mismatch: expected ID 34139, got 38156
;; communications error to 127.0.0.1#53: timed out
;; Warning: ID mismatch: expected ID 34139, got 31508
;; communications error to 127.0.0.1#53: timed out

; <<>> DiG 9.18.10-2-Debian <<>> hello.newid.yourdomain.com @127.0.0.1
;; global options: +cmd
;; no servers could be reached

```
### Set truncated flag - force TCP mode (tc)
In UDP mode respond only with a DNS header with TC (Truncated) flag set, so that the remote resolver or client will retry using TCP. This is to force the resolver (client) to use TCP mode for communicating with us.

<table>
<tr><td>format:</td><td>anything.tc.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig always.tc.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig always.tc.yourdomain.com @127.0.0.1
;; Truncated, retrying in TCP mode.

; <<>> DiG 9.18.10-2-Debian <<>> always.tc.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 14795
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;always.tc.yourdomain.com.	IN	A

;; ANSWER SECTION:
always.tc.yourdomain.com. 60	IN	A	2.3.4.5

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (TCP)
;; WHEN: Thu Nov 02 16:37:35 +04 2023
;; MSG SIZE  rcvd: 82
```
### Remove the query section (noq)
Remove the query section (question) from the response, but without altering the question RRs in the DNS header. For altering the number of question RRs, use the [qurr](#set-question-rrs-in-the-header-qurr) modifier.

<table>
<tr><td>format:</td><td>anything.noq.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig always.noq.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig always.noq.qurr0.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig always.noq.qurr0.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> always.noq.qurr0.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 19616
;; flags: qr aa; QUERY: 0, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; ANSWER SECTION:
always.noq.qurr0.yourdomain.com. 60 IN	A	2.3.4.5

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:35 +04 2023
;; MSG SIZE  rcvd: 59
```
### Add a delay / latency (slp)
Introduce an arbitrary latency (delay). Sleep for specified number of miliseconds before sending out the response.

<table>
<tr><td>format:</td><td>anything.slp&lt;MILISECONDS>.yourdomain.com</td></tr>
<tr><td>remark:</td><td>1000 is 1 second</td></tr>
<tr><td>example:</td><td><code>dig always.slp1000.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig always.slp1000.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> always.slp1000.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 21289
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;always.slp1000.yourdomain.com.	IN	A

;; ANSWER SECTION:
always.slp1000.yourdomain.com. 60 IN	A	2.3.4.5

;; Query time: 1008 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:36 +04 2023
;; MSG SIZE  rcvd: 92
```
### Set custom TTL value (ttl)
Set arbitrary time-to-live (TTL) value in the response.

<table>
<tr><td>format:</td><td>anything.ttl&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>remark:</td><td>Max TTL is 31 bytes long (2147483648) - 68.09 years</td></tr>
<tr><td>example:</td><td><code>dig always.ttl12345678.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig always.ttl12345678.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> always.ttl12345678.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4868
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;always.ttl12345678.yourdomain.com. IN	A

;; ANSWER SECTION:
always.ttl12345678.yourdomain.com. 12345678 IN A 2.3.4.5

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Fri Nov 03 14:31:08 +04 2023
;; MSG SIZE  rcvd: 100

```
### Set custom length in TCP (len)
Set custom DNS packet length in the DNS header. This only works in TCP mode since only TCP mode has length specified (the first 2 bytes of the DNS packet).

<table>
<tr><td>format:</td><td>anything.len&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>remark:</td><td>Max len is 65535 (2 bytes)</td></tr>
<tr><td>example:</td><td><code>dig always.len80.yourdomain.com @127.0.0.1 +tcp</code></td></tr>
</table>

Sample:
```
# dig always.len80.yourdomain.com @127.0.0.1 +tcp
;; Warning: Message parser reports malformed message packet.

; <<>> DiG 9.18.10-2-Debian <<>> always.len80.yourdomain.com @127.0.0.1 +tcp
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 50588
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: Message has 6 extra bytes at end

;; QUESTION SECTION:
;always.len80.yourdomain.com.	IN	A

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (TCP)
;; WHEN: Wed Nov 08 14:42:46 +04 2023
;; MSG SIZE  rcvd: 80

```
### Set custom flags in the header (flgs)
Set custom flags in the DNS header, allowing to specify it as a decimal number, hexadecimal number or to indicate to generate completely random flags.

<table>
<tr><td>format:</td><td>anything.flgs&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>format:</td><td>anything.flgs&lt;0xHEX>.yourdomain.com</td></tr>
<tr><td>format:</td><td>anything.flgsrand.yourdomain.com</td></tr>
<tr><td>remark:</td><td>Flags is 2 bytes long field, so max decimal number is 65535 or 0xffff in hexadecimal format</td></tr>
<tr><td>example:</td><td><code>dig always.flgs0x8400.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig always.flgs33792.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig always.flgsrand.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig always.flgs0x8400.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> always.flgs0x8400.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4241
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;always.flgs0x8400.yourdomain.com. IN	A

;; ANSWER SECTION:
always.flgs0x8400.yourdomain.com. 60 IN	A	2.3.4.5

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:51 +04 2023
;; MSG SIZE  rcvd: 98
```
### Set question RRs in the header (qurr)
Set arbitrary number of questions in the DNS header.

<table>
<tr><td>format:</td><td>anything.qurr&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>remark:</td><td>Max number of questions is 65535 (2 bytes)</td></tr>
<tr><td>example:</td><td><code>dig always.qurr50.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig always.qurr50.yourdomain.com @127.0.0.1
;; Warning: Message parser reports malformed message packet.
;; ;; Question section mismatch: got ./TYPE0/CLASS15360
;; communications error to 127.0.0.1#53: timed out
;; Warning: Message parser reports malformed message packet.
;; ;; Question section mismatch: got ./TYPE0/CLASS15360
;; communications error to 127.0.0.1#53: timed out
;; Warning: Message parser reports malformed message packet.
;; ;; Question section mismatch: got ./TYPE0/CLASS15360
;; communications error to 127.0.0.1#53: timed out

; <<>> DiG 9.18.10-2-Debian <<>> always.qurr50.yourdomain.com @127.0.0.1
;; global options: +cmd
;; no servers could be reached

```
### Set answer RRs in the header (anrr)
Set arbitrary number of answer records in the DNS header.

<table>
<tr><td>format:</td><td>anything.anrr&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>remark:</td><td>Max number of answer records is 65535 (2 bytes)</td></tr>
<tr><td>example:</td><td><code>dig always.anrr50.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig always.anrr50.yourdomain.com @127.0.0.1
;; Warning: Message parser reports malformed message packet.

; <<>> DiG 9.18.10-2-Debian <<>> always.anrr50.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45335
;; flags: qr aa; QUERY: 1, ANSWER: 50, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;always.anrr50.yourdomain.com.	IN	A

;; ANSWER SECTION:
always.anrr50.yourdomain.com. 60 IN	A	2.3.4.5

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:51 +04 2023
;; MSG SIZE  rcvd: 90
```
### Set authority RRs in the header (aurr)
Set arbitrary number of authority records in the DNS header.

<table>
<tr><td>format:</td><td>anything.aurr&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>remark:</td><td>Max number of authority records is 65535 (2 bytes)</td></tr>
<tr><td>example:</td><td><code>dig always.aurr50.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig always.aurr50.yourdomain.com @127.0.0.1
;; Warning: Message parser reports malformed message packet.

; <<>> DiG 9.18.10-2-Debian <<>> always.aurr50.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45789
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 50, ADDITIONAL: 0

;; QUESTION SECTION:
;always.aurr50.yourdomain.com.	IN	A

;; ANSWER SECTION:
always.aurr50.yourdomain.com. 60 IN	A	2.3.4.5

;; Query time: 4 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:51 +04 2023
;; MSG SIZE  rcvd: 90
```
### Set additional RRs in the header (adrr)
Set arbitrary number of additional records in the DNS header.

<table>
<tr><td>format:</td><td>anything.adrr&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>remark:</td><td>Max number of additional records is 65535 (2 bytes)</td></tr>
<tr><td>example:</td><td><code>dig always.adrr50.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig always.adrr50.yourdomain.com @127.0.0.1
;; Warning: Message parser reports malformed message packet.

; <<>> DiG 9.18.10-2-Debian <<>> always.adrr50.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 44535
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 50

;; QUESTION SECTION:
;always.adrr50.yourdomain.com.	IN	A

;; ANSWER SECTION:
always.adrr50.yourdomain.com. 60 IN	A	2.3.4.5

;; Query time: 4 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:51 +04 2023
;; MSG SIZE  rcvd: 90
```

##
Go back to [menu](#polardns-catalogue---response-modifiers).

