# PolarDNS catalogue - Response modifiers
1. [General features](general-features.md)
1. [Aliases, loops and chains](aliases-loops-and-chains.md)
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
	- [Cut N bytes from the end of the packet (cut)](#cut-n-bytes-from-the-end-of-the-packet-cut)
	- [Force compression (fc)](#force-compression-fc)
	- [No compression (nc)](#no-compression-nc)
	- [Name fuzzing generator (nfz)](#name-fuzzing-generator-nfz)
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
### Cut N bytes from the end of the packet (cut)
Cut arbitrary number of bytes from the end of the packet.

<table>
<tr><td>format:</td><td>anything.cut&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig always.cut00.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig always.cut10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig size.128.cut00.fc.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig size.128.cut16.fc.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig size.128.cut16.fc.yourdomain.com @127.0.0.1
;; Warning: Message parser reports malformed message packet.

; <<>> DiG 9.18.10-2-Debian <<>> size.128.cut16.fc.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 19940
;; flags: qr aa; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;size.128.cut16.fc.yourdomain.com. IN	A

;; ANSWER SECTION:
size.128.cut16.fc.yourdomain.com. 60 IN	A	127.0.0.236
size.128.cut16.fc.yourdomain.com. 60 IN	A	127.0.0.233
size.128.cut16.fc.yourdomain.com. 60 IN	A	127.0.0.123

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Mon Jul 08 15:41:00 +04 2024
;; MSG SIZE  rcvd: 98

```
### Force compression (fc)
Use DNS compression in the response, overriding any DNS compression settings specified in the configuration file.

<table>
<tr><td>format:</td><td>anything.fc.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig always.fc.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig size.300.fc.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig size.300.fc.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> size.300.fc.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 17029
;; flags: qr aa; QUERY: 1, ANSWER: 16, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;size.300.fc.yourdomain.com.	IN	A

;; ANSWER SECTION:
size.300.fc.yourdomain.com. 60	IN	A	127.0.0.112
size.300.fc.yourdomain.com. 60	IN	A	127.0.0.206
size.300.fc.yourdomain.com. 60	IN	A	127.0.0.64
size.300.fc.yourdomain.com. 60	IN	A	127.0.0.238
size.300.fc.yourdomain.com. 60	IN	A	127.0.0.100
size.300.fc.yourdomain.com. 60	IN	A	127.0.0.121
size.300.fc.yourdomain.com. 60	IN	A	127.0.0.72
size.300.fc.yourdomain.com. 60	IN	A	127.0.0.164
size.300.fc.yourdomain.com. 60	IN	A	127.0.0.79
size.300.fc.yourdomain.com. 60	IN	A	127.0.0.85
size.300.fc.yourdomain.com. 60	IN	A	127.0.0.243
size.300.fc.yourdomain.com. 60	IN	A	127.0.0.97
size.300.fc.yourdomain.com. 60	IN	A	127.0.0.16
size.300.fc.yourdomain.com. 60	IN	A	127.0.0.119
size.300.fc.yourdomain.com. 60	IN	A	127.0.0.215
size.300.fc.yourdomain.com. 60	IN	A	127.0.0.178

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sun Jul 07 22:59:53 +04 2024
;; MSG SIZE  rcvd: 300

```
### No compression (nc)
Do not use DNS compression in the response, overriding any DNS compression settings specified in the configuration file.

<table>
<tr><td>format:</td><td>anything.nc.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig always.nc.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig size.300.nc.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig size.300.nc.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> size.300.nc.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 20422
;; flags: qr aa; QUERY: 1, ANSWER: 6, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;size.300.nc.yourdomain.com.	IN	A

;; ANSWER SECTION:
size.300.nc.yourdomain.com. 60	IN	A	127.0.0.1
size.300.nc.yourdomain.com. 60	IN	A	127.0.0.130
size.300.nc.yourdomain.com. 60	IN	A	127.0.0.148
size.300.nc.yourdomain.com. 60	IN	A	127.0.0.83
size.300.nc.yourdomain.com. 60	IN	A	127.0.0.75
size.300.nc.yourdomain.com. 60	IN	A	127.0.0.224

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sun Jul 07 23:05:03 +04 2024
;; MSG SIZE  rcvd: 296

```
### Name fuzzing generator (nfz)
Generate various illegal and malformed domain names based on the selected variant and size. This generator was primarily created for alias features (such as alias, cnalias, dnalias, etc.) to provide a unified mechanism for generating malformed domain names.

<table>
<tr><td>format:</td><td>something.nfz&lt;VARIANT-0-49>.&lt;SIZE>.yourdomain.com<br>alias.&lt;HOWMANY>.nfz&lt;VARIANT-0-49>.&lt;SIZE>.yourdomain.com</td></tr>
<tr><td>remark:</td><td>VARIANT produces the following responses:<br><table> <tr><td>0</td><td colspan="2">NULL byte(s)</td></tr> <tr><td>1</td><td colspan="2">the &lt;ROOT> domain</td></tr> <tr><td>2</td><td colspan="2">random printable character(s)</td></tr> <tr><td>3</td><td colspan="2">random printable character(s) (repeated)</td></tr> <tr><td>4</td><td colspan="2">random byte(s)</td></tr> <tr><td>5</td><td colspan="2">random byte(s) (repeated)</td></tr> <tr><td>6</td><td colspan="2">incremental byte(s), from 0 to 255</td></tr> <tr><td>7</td><td colspan="2">incremental byte(s), from 0 to 255 (repeated)</td></tr> <tr><td>8</td><td colspan="2">subdomain(s), made of 63 random bytes</td></tr> <tr><td>9</td><td colspan="2">subdomain(s), made of 63 random printable characters</td></tr> <tr><td>10</td><td colspan="2">subdomain(s), made of 63 random letters and numbers</td></tr> <tr><td>11</td><td colspan="2">subdomain(s), made of 1 random byte</td></tr> <tr><td>12</td><td colspan="2">subdomain(s), made of 1 random printable character</td></tr> <tr><td>13</td><td colspan="2">subdomain(s), made of 1 random letter or a number</td></tr> <tr><td>14</td><td colspan="2">subdomain(s), made of 1 incremental byte from 0 to 255</td></tr> <tr><td>15</td><td colspan="2">subdomain(s), made of 1 incremental byte from 0 to 255 (repeated)</td></tr> <tr><td>16</td><td colspan="2">nonres######.yourdomain.com</td></tr> <tr><td>17</td><td colspan="2">always######.yourdomain.com</td></tr> <tr><td>18</td><td colspan="2">always######.&lt;NULL byte(s)>.yourdomain.com</td></tr> <tr><td>19</td><td colspan="2">always######.&lt;random byte(s)>.yourdomain.com</td></tr> <tr><td>20</td><td colspan="2">always######.&lt;random byte(s)>.yourdomain.com (repeated)</td></tr> <tr><td>21</td><td colspan="2">always######.&lt;incremental byte(s) from 0 to 255>.yourdomain.com</td></tr> <tr><td>22</td><td colspan="2">always######.&lt;incremental byte(s) from 0 to 255>.yourdomain.com (repeated)</td></tr> <tr><td>23</td><td colspan="2">always######.&lt;random 1 byte long subdomain(s)>.yourdomain.com</td></tr> <tr><td>24</td><td colspan="2">always######.&lt;random 1 byte long subdomain(s) made of a printable character>.yourdomain.com</td></tr> <tr><td>25</td><td colspan="2">always######.&lt;random 1 byte long subdomain(s) made of a letter or a number>.yourdomain.com</td></tr> <tr><td>26</td><td colspan="2">always######.&lt;incremental 1 byte long subdomain(s), from 0 to 255>.yourdomain.com</td></tr> <tr><td>27</td><td colspan="2">always######.&lt;incremental 1 byte long subdomain(s), from 0 to 255>.yourdomain.com (repeated)</td></tr> <tr><td>28</td><td colspan="2">&lt;NULL byte(s)>always######.yourdomain.com</td></tr> <tr><td>29</td><td colspan="2">&lt;random byte(s)>always######.yourdomain.com</td></tr> <tr><td>30</td><td colspan="2">&lt;random byte(s)>always######.yourdomain.com (repeated)</td></tr> <tr><td>31</td><td colspan="2">&lt;incremental byte(s), from 0 to 255>always######.yourdomain.com</td></tr> <tr><td>32</td><td colspan="2">&lt;incremental byte(s), from 0 to 255>always######.yourdomain.com (repeated)</td></tr> <tr><td>33</td><td colspan="2">always######.yourdomain.com&lt;NULL byte(s)></td></tr> <tr><td>34</td><td colspan="2">always######.yourdomain.com&lt;random byte(s)></td></tr> <tr><td>35</td><td colspan="2">always######.yourdomain.com&lt;random byte(s)> (repeated)</td></tr> <tr><td>36</td><td colspan="2">always######.yourdomain.com&lt;incremental byte(s) from 0 to 255></td></tr> <tr><td>37</td><td colspan="2">always######.yourdomain.com&lt;incremental byte(s) from 0 to 255> (repeated)</td></tr> <tr><td>38</td><td colspan="2">always######.yourdomain.com:80</td></tr> <tr><td>39</td><td colspan="2">always######.yourdomain.com:443</td></tr> <tr><td>40</td><td colspan="2">http://always######.yourdomain.com/</td></tr> <tr><td>41</td><td colspan="2">http://always######.yourdomain.com:80/</td></tr> <tr><td>42</td><td colspan="2">https://always######.yourdomain.com/</td></tr> <tr><td>43</td><td colspan="2">https://always######.yourdomain.com:443/</td></tr> <tr><td>44</td><td>1.2.3.4</td><td>DNS name notation</td></tr> <tr><td>45</td><td>1.2.3.4:80</td><td>DNS name notation</td></tr> <tr><td>46</td><td>1\.2\.3\.4</td><td>DNS name notation (using a single label with actual dot symbols)</td></tr> <tr><td>47</td><td>1\.2\.3\.4:80</td><td>DNS name notation (using a single label with actual dot symbols)</td></tr> <tr><td>48</td><td>192.0.2.1</td><td>DNS name notation (our own IP address)</td></tr> <tr><td>49</td><td>192.0.2.1:80</td><td>DNS name notation (our own IP address)</td></tr> </table></td></tr>
<tr><td>remark:</td><td>The <a href="http://www.tcpipguide.com/free/t_DNSNameNotationandMessageCompressionTechnique.htm"><strong>DNS name notation</strong></a> is a format used for hostnames and domain names, not IP addresses.</td></tr>
<tr><td>example:</td><td><code>dig alias.nfz0.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig DNAME alias.10.nfz0.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig DNAME alias.10.nfz1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig DNAME alias.10.nfz2.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig MX alias.20.nfz3.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig MX alias.5.nfz4.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig MX alias.5.nfz5.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Samples:
```
-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz0.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz0.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 31364
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz0.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz0.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000.
alias.10.nfz0.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000.
alias.10.nfz0.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000.
alias.10.nfz0.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000.
alias.10.nfz0.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000.
alias.10.nfz0.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000.
alias.10.nfz0.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000.
alias.10.nfz0.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000.
alias.10.nfz0.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000.
alias.10.nfz0.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 619

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz1.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz1.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 37625
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz1.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz1.10.yourdomain.com. 60 IN	MX	0 .
alias.10.nfz1.10.yourdomain.com. 60 IN	MX	0 .
alias.10.nfz1.10.yourdomain.com. 60 IN	MX	0 .
alias.10.nfz1.10.yourdomain.com. 60 IN	MX	0 .
alias.10.nfz1.10.yourdomain.com. 60 IN	MX	0 .
alias.10.nfz1.10.yourdomain.com. 60 IN	MX	0 .
alias.10.nfz1.10.yourdomain.com. 60 IN	MX	0 .
alias.10.nfz1.10.yourdomain.com. 60 IN	MX	0 .
alias.10.nfz1.10.yourdomain.com. 60 IN	MX	0 .
alias.10.nfz1.10.yourdomain.com. 60 IN	MX	0 .

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 509

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz2.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz2.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 64787
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz2.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz2.10.yourdomain.com. 60 IN	MX	0 f9&Q+M\010-\;O.
alias.10.nfz2.10.yourdomain.com. 60 IN	MX	0 VZsCWh?FA0.
alias.10.nfz2.10.yourdomain.com. 60 IN	MX	0 \"1&\)<SZ\;B|.
alias.10.nfz2.10.yourdomain.com. 60 IN	MX	0 8g!NJKR{Qf.
alias.10.nfz2.10.yourdomain.com. 60 IN	MX	0 ti50%\013wdN8.
alias.10.nfz2.10.yourdomain.com. 60 IN	MX	0 jOx~\$yQB:A.
alias.10.nfz2.10.yourdomain.com. 60 IN	MX	0 yjV\012EHloRy.
alias.10.nfz2.10.yourdomain.com. 60 IN	MX	0 ?w:~\011?&Zg\009.
alias.10.nfz2.10.yourdomain.com. 60 IN	MX	0 dhh7d\$uypE.
alias.10.nfz2.10.yourdomain.com. 60 IN	MX	0 #^Gby\012i\@p\032.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 619

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz3.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz3.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 22147
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz3.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz3.10.yourdomain.com. 60 IN	MX	0 ----------.
alias.10.nfz3.10.yourdomain.com. 60 IN	MX	0 %%%%%%%%%%.
alias.10.nfz3.10.yourdomain.com. 60 IN	MX	0 OOOOOOOOOO.
alias.10.nfz3.10.yourdomain.com. 60 IN	MX	0 hhhhhhhhhh.
alias.10.nfz3.10.yourdomain.com. 60 IN	MX	0 UUUUUUUUUU.
alias.10.nfz3.10.yourdomain.com. 60 IN	MX	0 ||||||||||.
alias.10.nfz3.10.yourdomain.com. 60 IN	MX	0 MMMMMMMMMM.
alias.10.nfz3.10.yourdomain.com. 60 IN	MX	0 CCCCCCCCCC.
alias.10.nfz3.10.yourdomain.com. 60 IN	MX	0 }}}}}}}}}}.
alias.10.nfz3.10.yourdomain.com. 60 IN	MX	0 \009\009\009\009\009\009\009\009\009\009.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 619

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz4.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz4.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 58525
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz4.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz4.10.yourdomain.com. 60 IN	MX	0 \245\021\001I\200\186\127\229\137k.
alias.10.nfz4.10.yourdomain.com. 60 IN	MX	0 \238\220\172\001\(\233\212\224\001\022.
alias.10.nfz4.10.yourdomain.com. 60 IN	MX	0 {n\129ji\161\018&\"\157.
alias.10.nfz4.10.yourdomain.com. 60 IN	MX	0 \140,?\235\228u#\016[\206.
alias.10.nfz4.10.yourdomain.com. 60 IN	MX	0 \026\199\000\168\244*\134\216\188\250.
alias.10.nfz4.10.yourdomain.com. 60 IN	MX	0 \186MT\205\191GI3nZ.
alias.10.nfz4.10.yourdomain.com. 60 IN	MX	0 B\188\129\"w\145Zn\014\009.
alias.10.nfz4.10.yourdomain.com. 60 IN	MX	0 \199c{\012k\159\205Z=9.
alias.10.nfz4.10.yourdomain.com. 60 IN	MX	0 \136D\\\214w\230\208\162\208\181.
alias.10.nfz4.10.yourdomain.com. 60 IN	MX	0 \169\156\219\203^\223!R\225\227.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 619

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz5.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz5.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 37964
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz5.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz5.10.yourdomain.com. 60 IN	MX	0 \\\\\\\\\\\\\\\\\\\\.
alias.10.nfz5.10.yourdomain.com. 60 IN	MX	0 dddddddddd.
alias.10.nfz5.10.yourdomain.com. 60 IN	MX	0 \022\022\022\022\022\022\022\022\022\022.
alias.10.nfz5.10.yourdomain.com. 60 IN	MX	0 \248\248\248\248\248\248\248\248\248\248.
alias.10.nfz5.10.yourdomain.com. 60 IN	MX	0 \169\169\169\169\169\169\169\169\169\169.
alias.10.nfz5.10.yourdomain.com. 60 IN	MX	0 \160\160\160\160\160\160\160\160\160\160.
alias.10.nfz5.10.yourdomain.com. 60 IN	MX	0 HHHHHHHHHH.
alias.10.nfz5.10.yourdomain.com. 60 IN	MX	0 hhhhhhhhhh.
alias.10.nfz5.10.yourdomain.com. 60 IN	MX	0 \032\032\032\032\032\032\032\032\032\032.
alias.10.nfz5.10.yourdomain.com. 60 IN	MX	0 \130\130\130\130\130\130\130\130\130\130.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 619

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz6.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz6.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7548
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz6.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz6.10.yourdomain.com. 60 IN	MX	0 \000\001\002\003\004\005\006\007\008\009.
alias.10.nfz6.10.yourdomain.com. 60 IN	MX	0 \010\011\012\013\014\015\016\017\018\019.
alias.10.nfz6.10.yourdomain.com. 60 IN	MX	0 \020\021\022\023\024\025\026\027\028\029.
alias.10.nfz6.10.yourdomain.com. 60 IN	MX	0 \030\031\032!\"#\$%&'.
alias.10.nfz6.10.yourdomain.com. 60 IN	MX	0 \(\)*+,-\./01.
alias.10.nfz6.10.yourdomain.com. 60 IN	MX	0 23456789:\;.
alias.10.nfz6.10.yourdomain.com. 60 IN	MX	0 <=>?\@ABCDE.
alias.10.nfz6.10.yourdomain.com. 60 IN	MX	0 FGHIJKLMNO.
alias.10.nfz6.10.yourdomain.com. 60 IN	MX	0 PQRSTUVWXY.
alias.10.nfz6.10.yourdomain.com. 60 IN	MX	0 Z[\\]^_`abc.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 619

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz7.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz7.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 35050
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz7.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz7.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000.
alias.10.nfz7.10.yourdomain.com. 60 IN	MX	0 \001\001\001\001\001\001\001\001\001\001.
alias.10.nfz7.10.yourdomain.com. 60 IN	MX	0 \002\002\002\002\002\002\002\002\002\002.
alias.10.nfz7.10.yourdomain.com. 60 IN	MX	0 \003\003\003\003\003\003\003\003\003\003.
alias.10.nfz7.10.yourdomain.com. 60 IN	MX	0 \004\004\004\004\004\004\004\004\004\004.
alias.10.nfz7.10.yourdomain.com. 60 IN	MX	0 \005\005\005\005\005\005\005\005\005\005.
alias.10.nfz7.10.yourdomain.com. 60 IN	MX	0 \006\006\006\006\006\006\006\006\006\006.
alias.10.nfz7.10.yourdomain.com. 60 IN	MX	0 \007\007\007\007\007\007\007\007\007\007.
alias.10.nfz7.10.yourdomain.com. 60 IN	MX	0 \008\008\008\008\008\008\008\008\008\008.
alias.10.nfz7.10.yourdomain.com. 60 IN	MX	0 \009\009\009\009\009\009\009\009\009\009.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 619

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz8.3.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz8.3.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 42966
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz8.3.yourdomain.com.	IN	MX

;; ANSWER SECTION:
alias.10.nfz8.3.yourdomain.com.	60 IN	MX	0 \181Y^\031\162~\220\005\207_\239\177\241d\140f\242\150\248\231\137\159\023\@\137\161\016\215\129!\252\031\210\162hb\029\230\170\023\013\018\190\148\011\217\184\013-\003W|\"^x}I\191^\001\218\201\127.\200\223\191\240F\157\169\243\011W\021\017\204Da:4F\007\028\209\213\135\242}e\229D\200U2\2238\175v\172\024\219\246\166\235\2453B\.\148L\170Nx\130X\190XD\164\195\179\139\158?\245\164.\149\247\003k\024A\176c\135c\212<s\177m\246\230f\217tr\029\196\130L\241\161\239\022\251\227\007\188\156\)\030\237\243\229\152A\223\211\136\2131m\149J\232\165u\196\015\175\140\191\177\181\.\163\2296.
alias.10.nfz8.3.yourdomain.com.	60 IN	MX	0 5\130\(6\182]\227\159\234\161\008\219\214\031\170?\144\189\009\160\194\195\231\127A\015\172\220\215\168\005\192\139\254\004\158W\010\025\227\205\255F\161\150\245\147\200\222\184TC?s\211>\139\202\009\236b\239\003.D\\=\196\004\216\150\170f\184\)\\\136]\159r3\205\172o\185P\192\0034\031\222*\$\244`\0312\007\237\$2\212S\201\130\214e\1615\023\241\188S\2469w\210Q\143\183\244{ec\187e\232.\164zV\026\(s\168Y\128\185\205\003/\152E}\208,\222%\225KD\225\138\133\127t_sk\143c\019\182x\132\181\026\184\254\249\206\228C\153*\015Im\025\221\161\144D\187<\205\004\154{\188`.
alias.10.nfz8.3.yourdomain.com.	60 IN	MX	0 #\252\233\155Z\1468\017\149\.\172\245\148[\001\255\242n\000\206bB\143b\136\213\153\153\175\017\002\011\233^\1756\169\209q*\147\151X\003d\134j<\013\207\002\195A\014\168\176\251^\149\255\240\216>.p>a}\162\185\215\.\226\248\213[\197\161W\017\218\014L\194\221\237\021_\131%\185\157:\237\233\020\241\252\252/u\205:B\016\015\031\017\)\2426\161>\@Rp\194w!\187\135t4\149L\133\168.\162\181N\237\133b&\225\025\202\187<\156l\170\020\141\166\002\246Q0\127\019\246\1748\$\176R\011\127_\231\1644\182m\129\014\012ZQ=\019nI\221\173\174M\141\162P\234\253l\245\233\171\167\175\183.
alias.10.nfz8.3.yourdomain.com.	60 IN	MX	0 \232\251\"\177\026\211\208\190\030+\244\135\143\196\151H\1598~K,\182\229\200``\029\027\179\179p\195\217\009\137#\017\218I\030a\155\158,\145CMg\174\\\133b\233\209\135T\000\030\205\148\014\198\224.O\231-]CG-\206\138\180\185\016\012\012\175\175\141\202\191\(\133-,\229\212\178^2\220\019\248%\010\130u\188\223%\225I\148\165\\\207\131\140\191M\161X\252f\236\238\.\172y\187\219\201\221\024\205.\196o6\008\134\226\@\1658\008T\225>\171\236^\210bg\156\223\2328\202M\017\"\197\192P{|\004\242\017\154\189\213\166\233\180/Nm\008\150\162\203\240\127\130\212\238\224\009|\203\2342\151F\012\".
alias.10.nfz8.3.yourdomain.com.	60 IN	MX	0 \216\011\242\201\003\234\243\131\155\131!\165\145\229\137\159\140Y\134\207Ba\232\222A\175\180\$1\012\183\192\199\169\132\203\224\196\182\012\001\199\139#\181\208\136m\165\224\008\238j9\174M\222\140B\183\013\246\173.h4oLa\219\245\249*J\002\237[EJ\154#\232<\209\004\174^\188\247\138\)\218\"\229J\130I\228\208\148\235\174h\(\139\147\206\167\148H\018\185\216B:\028\0151+p\028\128\220\208\026\195\012.\011\017\194`\153\2534V\010\008\001\253>\199\198\207\183\007\214\168\162\162\188z\157x\166\173\127\008\031\000\209\206\175\235\160\001\217\177\243\137\129\141\2153\192\243\219g+VA`\142X\246\214pi\018R\137.
alias.10.nfz8.3.yourdomain.com.	60 IN	MX	0 \031\198\174\137z\208W\;\129\148\025\028\241\024B\239\178\180\227\199\242\209!\001\164\202\203\1752\170\127=\170\224|e\"Y\005\208\229\174\232\015\157\004S\008Z'\249\171\214\179\127\)\163\006\145S\229\(\032.\204\@\180&R\215y\230-<[r\156\002\187\248b1\232w\138\128\212\139\185\191e\184\019\129vcDV\165He5ZOJd\247\170\145B\175,\219U\229h\142\202*\147i\246\.\179\235\155\207.\164\229a\209\205\006\010Y\204\135,K\174h3\(\166\032\1514\007\220m\130\030\$\243r\183\228\163\196J\200\177\222,\137\021\242\014\@p}g\007n\197g\228=\242\198J\191\178\128I\214\235\216\186\024.
alias.10.nfz8.3.yourdomain.com.	60 IN	MX	0 R}\028\155se\228\130\211'\018s\142\003\249\021\222\"\245\254G/S\174\163&\195\190\022\018O\002\188\186\027\157\142\134\133\226\173\252\182{P\165\)\157\168Gaqf\189\233\205\199\190\237\168C\144\238.\159\247\178:\215\134?L\245\2102\1444\024KA\009?\205W\\],\023kc\143z\245e\176X\019Q\192'S\190\134\252b\189\243\157\$\209\251[\174\158\187HU\000\\\255\218\215\1553\246\221P.\235\000\022\250\221I\136\255I\188\129\158\128m\154\139\032\029\144%Cx\128\243\016o?\2424\222C`_\243_\173i\018\236\014\213\)\248\223\249\233\168\174#\180\237\@\253\151N\229\172\148\22199\156Q.
alias.10.nfz8.3.yourdomain.com.	60 IN	MX	0 \224/[\$\143U\129r\197\137\012\132\154\023\008U\027\"\\\220\239w\028NWF\235\239\004'J\224\009W\229\142\130\185\144\022G\207\245\153\2046\205\218\242U2\139\222\223\014\025\182V\010#\202{\157.j\132\207\238dH\144iS\201>\198k\209\.WR\026\140\147\134i\(\221\164\131\232g\241\0272U\0034\243rh\032\022\030&\159\189W=\0137\193\1277\246\243wB\171\1609\178\186\002f\248\200.\222X\219y\255k\232\$P\026\199R\180\130G&\003\253\142\215\198\210\219C|Y\160\016\164\2338\193_Zy\$\232\214\\\187\175o\197\211\230\254\172o}\235\132\138n~\154E\019\236\145\230#\198s.
alias.10.nfz8.3.yourdomain.com.	60 IN	MX	0 H\173\$\021\216\0198\255\229r\129BE\137J\144J\185`\201\165\240O\238\240\204\;\130\027D0Z\229X\133\144<3\165\003\144\"C\028\032\230\162A\205\247\208]|cS\142\151\012C\173^\176T.\175\249,_\175\018pk\150\;\030*\018\134\240&/\215\216\026\137c\1335\202\163\016y\2180\201\242\189`\238\220:\131\138j\127~\032\252\014\240\238\008\175\131k\029\233\222\246\019e\217\196|\021\244\147.\151\161\246GP\$}\016\211\228\249i\255\028+y\169KG\202\231Y=\194\203\170y\254\004\194\241\201\147\242-\026\179x\190\004/\1869\030\228\208\2310jj\163\242\150g\175\217\158\154\149\012}\127\254.
alias.10.nfz8.3.yourdomain.com.	60 IN	MX	0 \)N\223\199\217Po\1323o\029\031:\1334i\009\191NzW~\180Tk\153\191\211\160\145\022\"\1646\134\187\152s\2312Z\016\005\163\183\137\248\006\236\030wW\189\179\165*\211J\212\139\023V\193.\013\1468\1600\206\030a\010<P\009\009|\235k\213\168\024pC\136\158\220>#\172\024_3>\211\178\134\190x\179j\216\@S+EeF\193t\154\127P\192\029\170Hd|=/\207Q\243\239\130.\001*b\193\167~\131Q\211\136\249\019\026?\1541c\136\166LH\242,\023\004\156\192\191\001B\137\189\025\212\197\"\194v\024%\247\197\189\227\164\160\026\196\023\021\191}\235\236g\161\181\218\018\253\191\196\214.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 2418

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz9.3.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz9.3.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 59160
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz9.3.yourdomain.com.	IN	MX

;; ANSWER SECTION:
alias.10.nfz9.3.yourdomain.com.	60 IN	MX	0 EhLi{_{Pk\\BD8OtB\;k,\032T5jwiDA\012.?nHzm1o\;6n\009rIz3j\0099m2\032TRk!\\TvRz?rj>.ip[OJG\"b\009d/L1~mQB\;!zc5B\012u#YWOtA+H\032v<-Re\$lrNXjr\"M\$+8L\009\)m/W\011#\0129\010*.KQWr~6q2:\032z4\011:?op[`N7blYGARx\(v_R[9}GNs{_.~#[E\)\013nSVO4k~%.02N6\009.l.
alias.10.nfz9.3.yourdomain.com.	60 IN	MX	0 BSahBme\$J]O{M=b&\012h5HNb\013x-s^&b\013g`cp4Jlu\)S\\=B+fgW[hEr?VmN\"-^gW&=O.y3u?W5r.\009q8xae\032zAMw1oOu{L!hd'd1\(\032>U~b}N~7r!Sgy_9xm}_M3%K_A.fclg.-WleLZn?|UW\)CXCOmRzNcQBMc}pq^+3~zJI\)\@[r>lU9wvr1MA'#\(dAzFhu.\010S0D.
alias.10.nfz9.3.yourdomain.com.	60 IN	MX	0 KeN7J]nP_<]ghI6|Hz\013q#M\012Saeie{4f^'Cp\(nh_fA>4\"{%o8W-QhseaUj\"tzaZ=.-s0lc\$GR`&uz<\@JP{\013*hTyq|K0bEE>NUqH4Do6P01L'/\013m\(NYk#tVf#Lv:\011?j\010\013.y\013LVF\;~vj-m.4yaz%7Mq|dh,jO.=D\032>]&W8~7gWTAp5]gH^#]bgQ-/qjpxy'`\@v.
alias.10.nfz9.3.yourdomain.com.	60 IN	MX	0 T`\\hK>y?]A?T-\@re=\0111~P^G1/\"\009\(WM\".}O9:fGm\009I{g7eL\@\"sUCP6PzA6.fw7\011i.[sGyaPZB}6x\011f5[j8|r\009\":+HK6r75`/3Za^!\013\@y{5n\$r~|{Mw*>SxjN!cOmQW_x.8X1nL[Y!JPJoX\)85\@\;\@2b6feoZNw:B\011\013WCLXg|X9u<u\$u4mV\009hpf7][\010b:hfkz-.
alias.10.nfz9.3.yourdomain.com.	60 IN	MX	0 2Ah>\(:h\009`}5x'p!{GV/q\"b~=_qF{\\yeYs\0114\)Pdh\"]0\009nV\$OpOu\;'\;T\@3\\\012rJ\010M].jz7E\013R]bR+o\)=eH\(IG+MqlyC\\\011O&5c:Y\009zW7.!^UBCyzZd`\032D!-rELQl&v<bn[~.\@%e=\011\009>nw\"u2\013>O'H8c/y{i`}16\009\010ny&C\"?#A\$+W\@\032t\"t\"J\032\011\013.t,\"1\\|x/2XC#.
alias.10.nfz9.3.yourdomain.com.	60 IN	MX	0 \009qs!4>0<FRn|PXbI,*<9,8,\\J3\009\011DYO26+J%1j\032ISJ\(}\$[\(O^{[\009uza|-\)\;<:?M.YSV\;2N0\(L\011\$\(B2L\013I\0102L{AG!\010K[CTmK'3|\"jzY4yy3*\0107\032_5jC\009Vr1Dx\011\(RIr=2.&\)\;CtsVqJo+h\032+\013?=uyy<4=TDBjpudoKmt+:+ysP\012\(Xm{#Rfalm7n*\010Bokx\0100m\(.
alias.10.nfz9.3.yourdomain.com.	60 IN	MX	0 QJerrG4\(ZBk\(GACma%U~FA\;Jmu-UAuA5Yv6EU\(3l|G|beUHVCUwY\;\)l{w\"#\"'5b.hy2\(v3c\;\0090sMB\009\\!NSJd\"m<HAXch\;\\/Xz6[W\013k6`UDbAa7g7w5~}\013K|=Ax\(Yagx.8\@RosQ!\@7S\012iI\;E\$k\$+=~H\032\;\009CSvt3\013}MCw\013qFnp/\)aKUoJD\;#o65G\@|\$I<mX1X.
alias.10.nfz9.3.yourdomain.com.	60 IN	MX	0 %.C`[IST^\012YIUNWZ=4ND6K\\m#KIS7X92\009QlV.iF04\\[\;`2*?!m8.|U&!lGe}EMc.EM\009Co'\$6tVNsV9F#'n\@.^<ug`TzP\$\(9\;A'~y\012\"\0100-cZPAs+q\"1^\;%\011zw1QuNEa!.yOmz8\",Vw6uQ'E#Wf&#,,mn6CD\0323*`k`'+8fu>QB,'\)9\)ieXgi\\U]-4DMbik\$-p.
alias.10.nfz9.3.yourdomain.com.	60 IN	MX	0 Ve%MO>\$R\(\\kab}-9hSSl1\0138Ff6^5\$AA1:9%.k|P~=-z\010MOb/D\0116\032\032|+kBtzX\@S3.KP\010<v\010,o?Fl9H7=!\011\"\).G0mijFB\009y\$b1\$x.W\011rQ,q80?Q!lYo-k~^J,\032RtS]O-X.p5-f+MI\\zpk0\)x_*\@72?ce'\(]<|v'Mj'|E?<{y\013-\)V&VP:JZPYM'sPa\012:\;~`9\010d.
alias.10.nfz9.3.yourdomain.com.	60 IN	MX	0 y%7e\\\(&~cV_4Faa`\@>&\\y\;|<DC[/LG`Rp*XW2teV\)\012\012PV9?B],:b\012!JCoc\\Qt\(:.5b6z\032}\;f3xwcF58n,\@[2+w\$<?|\010bwr'yS6Cd\;\012#K/IFba/V]#O+~hG\@dXr~j\)JJ.\\\032fo9OL&}vv\@sHFo&g}RV<\"7qeX{f=Ltz2|c%w+r\@h_<{IVA'\012]3Z?H5\010TECr{%.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 2418

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz10.3.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz10.3.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 56747
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz10.3.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz10.3.yourdomain.com. 60 IN	MX	0 zlo13jni53o02gqu6ee94l4yt4b5g3aznms5zuf17y7am91seeqmz6gq5v1txu0.w4wnh72shj2gbaq5re3o3j9nf8njenmbmrqmx1pt6d0546f63u18yt2rqg16j5h.g7jxb58z4p469v0fgsq7ly8g8wt7xyp9b2neifw4cs0cog2oecxzdzrisjzp5bq.
alias.10.nfz10.3.yourdomain.com. 60 IN	MX	0 ghcle0myu5abcjt6k6172xy1ceoihmv0rli7lp9bhxnwvy4quou4zjsdhsospjt.fkaw3se9n2onu92x4fy0gqs4rkpptbmngf4ultgykhl8rmb1wp5mx26zmorwqrm.s3hchp7zq54urpohml676yj4zudvzpteiflwpqei5s691s67b1zlvkd8fak00zb.
alias.10.nfz10.3.yourdomain.com. 60 IN	MX	0 8banihdu33e60ip9022ncg6ssa2lbiyywc4bphzwsom7u6bhugjpqcs3c5rgre5.dr7734s78bbokzgcpcn3w9yn2fx6kfe75d8p4681jy8huzq1j6pkdlsg6zgnynq.3yekwuut25yv3e63lxyi3it4f520lkx7fa0ek025l8yei0v24qocizyco3rtg7m.
alias.10.nfz10.3.yourdomain.com. 60 IN	MX	0 a46yiuvnnvawvviwhg3rbou7z9a02cdjg953w2cihydu5l4dcmjgb7h3jlo0txd.40yzdc8l8cbx53f4fjydq7multnx3u7lo2mtem42mv0uqij4y2hc1m8lid8yrc9.y3euxga3ycx4wo8thkhhse5dnf7g8uink9gqzkgqgr927naoci496kkxzh9d72i.
alias.10.nfz10.3.yourdomain.com. 60 IN	MX	0 gn5yombbpj8e4hrpr31alp8rox5elfkwoh8z64fenyhho6u199hq2dnt0pvlbcc.85g1gpbrbpjh47b3nu36mqhlyiq47kcxr40ulkdylgcbswzfusm9n7lyomg44es.5e3f2ko15i5ywbqzm3s8smc0q7ummi3nenami4oee14x0iebzjee3y9eabpt4sz.
alias.10.nfz10.3.yourdomain.com. 60 IN	MX	0 zumx32d2e30s1k6nszxtt1v7au4mifugj6xq0jldr0hdt5hk7xl39ixzz46menm.tagonntuw6evk9swurqxxf4dnnj54o03obzsdx135yyktym13pdoty8u7nblnpf.al2q32dqhugorpnxjoljs76cvx5zos2w5qc3tgtt0xzqw5ax1nly8u186hu8e55.
alias.10.nfz10.3.yourdomain.com. 60 IN	MX	0 loh96vjhaw9foo8yftui6wetvfztia9tf9s7n4h6pp55rqhxaqn9mbet567oja3.qvn2qmg3qs8lzcnam7kafwgwqjiy7v74v7pl1ydrwvmg0h8i7dtig0wr6qy5kzr.k24yvmctgf0z4cfz15csi5668glf30f5wfmkhdsk310yy5ebuuototrvgam4icl.
alias.10.nfz10.3.yourdomain.com. 60 IN	MX	0 792380s7nce3utbd7rt9z4hxirpv435wdo6ucl9h6fxekc0wg6293gmtxievjlr.2bddop0jh94ypeuhncwdgggkga8yndewsnfbjmjv2rtf2ufxfwesfh6zokwonbp.espi74dn3i60g91s3d2lbdp647x348np8yo80sya8uvplrkubgaik83jqr7nuu1.
alias.10.nfz10.3.yourdomain.com. 60 IN	MX	0 y69qn1uok4jklnjpxp9qqd0nasricqenomk3qr79r25mwf1yn1ffaqkoewigikc.x7ji765p9myru68y4p36a4uf148b4yodyga2d6ynxt1flsmev32063h4kk973xe.ddxj1cvztnutn4bfvsq0ocrtpw0gcpdheo3h9bx1sqwebkg8piv8wudh7h9l9ed.
alias.10.nfz10.3.yourdomain.com. 60 IN	MX	0 c1hqt6x5y93339rewi5zgg3f7zfh5tuo6hbipfyrqmn4z5qy6a5jgpk834usx78.02lcbd7qw8t0dffiny49q5nt0xsvzcdjqsdwdnw3vlonm9xlffypk5tu2dr15bj.y4wrhzn3vw1q2ucgoc8s3weomn835su888mellou4n71pxlaj64rdfpm5jlei20.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 2429

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz11.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz11.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 39701
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz11.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz11.10.yourdomain.com. 60 IN	MX	0 F.~.\165.\148.\228.6.\218.\170.\178.\007.
alias.10.nfz11.10.yourdomain.com. 60 IN	MX	0 \224.j.\023.\029.\157.\242.\164.\169.u.I.
alias.10.nfz11.10.yourdomain.com. 60 IN	MX	0 \254.^.\137.w.Z.\233.h.\021.\200.u.
alias.10.nfz11.10.yourdomain.com. 60 IN	MX	0 \198.D.\160.\157.\028.\233.U.\255.\181.\222.
alias.10.nfz11.10.yourdomain.com. 60 IN	MX	0 \$.\203.\147.\\.\165.\025.A.j.\145.\021.
alias.10.nfz11.10.yourdomain.com. 60 IN	MX	0 \153.\199.h.\\.\017.\147.q.].\129.K.
alias.10.nfz11.10.yourdomain.com. 60 IN	MX	0 \197.r.%.\198.g.u.:.i.,.\009.
alias.10.nfz11.10.yourdomain.com. 60 IN	MX	0 \165.\018.\016.#.\202.g.\127.C.N.\230.
alias.10.nfz11.10.yourdomain.com. 60 IN	MX	0 \203.\130.\175.}.\018.8.o.\237.\231.\196.
alias.10.nfz11.10.yourdomain.com. 60 IN	MX	0 \216.d.\207.\197.\203.\239.\232.>.+.\".

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 720

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz12.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz12.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 40277
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz12.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz12.10.yourdomain.com. 60 IN	MX	0 1.=.Y.Z.h.\@.\;.\$.2.v.
alias.10.nfz12.10.yourdomain.com. 60 IN	MX	0 9.`.y.5.\010.\012.6.I.3.w.
alias.10.nfz12.10.yourdomain.com. 60 IN	MX	0 f.<.0.:.a.A.S.\\.7.+.
alias.10.nfz12.10.yourdomain.com. 60 IN	MX	0 8.4.1.f./.%.~.M.N.*.
alias.10.nfz12.10.yourdomain.com. 60 IN	MX	0 8.u.N.y.W.q.k.V.N.R.
alias.10.nfz12.10.yourdomain.com. 60 IN	MX	0 \011.1.\;.E.3.Z.k.K.D.}.
alias.10.nfz12.10.yourdomain.com. 60 IN	MX	0 G.u._.a.~.3.\@.t.-.d.
alias.10.nfz12.10.yourdomain.com. 60 IN	MX	0 g.H.+.x.F.4.L.[.d.\$.
alias.10.nfz12.10.yourdomain.com. 60 IN	MX	0 =.2.3.a.:.z.o.M.\010.W.
alias.10.nfz12.10.yourdomain.com. 60 IN	MX	0 f.'.\\.?.i.Q.S.Y.M.C.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 720

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz13.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz13.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 57026
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz13.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz13.10.yourdomain.com. 60 IN	MX	0 9.x.q.g.d.d.j.p.p.9.
alias.10.nfz13.10.yourdomain.com. 60 IN	MX	0 3.m.r.5.a.u.o.o.8.f.
alias.10.nfz13.10.yourdomain.com. 60 IN	MX	0 q.7.j.a.v.c.w.m.1.i.
alias.10.nfz13.10.yourdomain.com. 60 IN	MX	0 c.5.2.e.r.0.p.i.z.5.
alias.10.nfz13.10.yourdomain.com. 60 IN	MX	0 t.a.6.6.1.1.v.k.r.y.
alias.10.nfz13.10.yourdomain.com. 60 IN	MX	0 y.m.w.m.s.q.d.g.p.s.
alias.10.nfz13.10.yourdomain.com. 60 IN	MX	0 o.o.r.q.8.o.x.c.y.t.
alias.10.nfz13.10.yourdomain.com. 60 IN	MX	0 j.q.l.v.x.m.w.f.t.c.
alias.10.nfz13.10.yourdomain.com. 60 IN	MX	0 m.f.6.i.i.c.8.q.e.9.
alias.10.nfz13.10.yourdomain.com. 60 IN	MX	0 d.n.f.m.g.4.f.g.r.a.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 720

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz14.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz14.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 40059
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz14.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz14.10.yourdomain.com. 60 IN	MX	0 \000.\001.\002.\003.\004.\005.\006.\007.\008.\009.
alias.10.nfz14.10.yourdomain.com. 60 IN	MX	0 \010.\011.\012.\013.\014.\015.\016.\017.\018.\019.
alias.10.nfz14.10.yourdomain.com. 60 IN	MX	0 \020.\021.\022.\023.\024.\025.\026.\027.\028.\029.
alias.10.nfz14.10.yourdomain.com. 60 IN	MX	0 \030.\031.\032.!.\".#.\$.%.&.'.
alias.10.nfz14.10.yourdomain.com. 60 IN	MX	0 \(.\).*.+.,.-.\../.0.1.
alias.10.nfz14.10.yourdomain.com. 60 IN	MX	0 2.3.4.5.6.7.8.9.:.\;.
alias.10.nfz14.10.yourdomain.com. 60 IN	MX	0 <.=.>.?.\@.A.B.C.D.E.
alias.10.nfz14.10.yourdomain.com. 60 IN	MX	0 F.G.H.I.J.K.L.M.N.O.
alias.10.nfz14.10.yourdomain.com. 60 IN	MX	0 P.Q.R.S.T.U.V.W.X.Y.
alias.10.nfz14.10.yourdomain.com. 60 IN	MX	0 Z.[.\\.].^._.`.a.b.c.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 720

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz15.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz15.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4160
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz15.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz15.10.yourdomain.com. 60 IN	MX	0 \000.\000.\000.\000.\000.\000.\000.\000.\000.\000.
alias.10.nfz15.10.yourdomain.com. 60 IN	MX	0 \001.\001.\001.\001.\001.\001.\001.\001.\001.\001.
alias.10.nfz15.10.yourdomain.com. 60 IN	MX	0 \002.\002.\002.\002.\002.\002.\002.\002.\002.\002.
alias.10.nfz15.10.yourdomain.com. 60 IN	MX	0 \003.\003.\003.\003.\003.\003.\003.\003.\003.\003.
alias.10.nfz15.10.yourdomain.com. 60 IN	MX	0 \004.\004.\004.\004.\004.\004.\004.\004.\004.\004.
alias.10.nfz15.10.yourdomain.com. 60 IN	MX	0 \005.\005.\005.\005.\005.\005.\005.\005.\005.\005.
alias.10.nfz15.10.yourdomain.com. 60 IN	MX	0 \006.\006.\006.\006.\006.\006.\006.\006.\006.\006.
alias.10.nfz15.10.yourdomain.com. 60 IN	MX	0 \007.\007.\007.\007.\007.\007.\007.\007.\007.\007.
alias.10.nfz15.10.yourdomain.com. 60 IN	MX	0 \008.\008.\008.\008.\008.\008.\008.\008.\008.\008.
alias.10.nfz15.10.yourdomain.com. 60 IN	MX	0 \009.\009.\009.\009.\009.\009.\009.\009.\009.\009.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 720

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz16.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz16.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 35881
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz16.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz16.10.yourdomain.com. 60 IN	MX	0 nonres662899.yourdomain.com.
alias.10.nfz16.10.yourdomain.com. 60 IN	MX	0 nonres603842.yourdomain.com.
alias.10.nfz16.10.yourdomain.com. 60 IN	MX	0 nonres052019.yourdomain.com.
alias.10.nfz16.10.yourdomain.com. 60 IN	MX	0 nonres292263.yourdomain.com.
alias.10.nfz16.10.yourdomain.com. 60 IN	MX	0 nonres155186.yourdomain.com.
alias.10.nfz16.10.yourdomain.com. 60 IN	MX	0 nonres349984.yourdomain.com.
alias.10.nfz16.10.yourdomain.com. 60 IN	MX	0 nonres784178.yourdomain.com.
alias.10.nfz16.10.yourdomain.com. 60 IN	MX	0 nonres616570.yourdomain.com.
alias.10.nfz16.10.yourdomain.com. 60 IN	MX	0 nonres354861.yourdomain.com.
alias.10.nfz16.10.yourdomain.com. 60 IN	MX	0 nonres779591.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 800

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz17.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz17.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 48579
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz17.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz17.10.yourdomain.com. 60 IN	MX	0 always774569.yourdomain.com.
alias.10.nfz17.10.yourdomain.com. 60 IN	MX	0 always598753.yourdomain.com.
alias.10.nfz17.10.yourdomain.com. 60 IN	MX	0 always316242.yourdomain.com.
alias.10.nfz17.10.yourdomain.com. 60 IN	MX	0 always550288.yourdomain.com.
alias.10.nfz17.10.yourdomain.com. 60 IN	MX	0 always710251.yourdomain.com.
alias.10.nfz17.10.yourdomain.com. 60 IN	MX	0 always001530.yourdomain.com.
alias.10.nfz17.10.yourdomain.com. 60 IN	MX	0 always305648.yourdomain.com.
alias.10.nfz17.10.yourdomain.com. 60 IN	MX	0 always113913.yourdomain.com.
alias.10.nfz17.10.yourdomain.com. 60 IN	MX	0 always462548.yourdomain.com.
alias.10.nfz17.10.yourdomain.com. 60 IN	MX	0 always368328.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 800

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz18.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz18.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 20378
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz18.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz18.10.yourdomain.com. 60 IN	MX	0 always885203.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.
alias.10.nfz18.10.yourdomain.com. 60 IN	MX	0 always156519.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.
alias.10.nfz18.10.yourdomain.com. 60 IN	MX	0 always345494.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.
alias.10.nfz18.10.yourdomain.com. 60 IN	MX	0 always895924.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.
alias.10.nfz18.10.yourdomain.com. 60 IN	MX	0 always228702.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.
alias.10.nfz18.10.yourdomain.com. 60 IN	MX	0 always570499.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.
alias.10.nfz18.10.yourdomain.com. 60 IN	MX	0 always669701.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.
alias.10.nfz18.10.yourdomain.com. 60 IN	MX	0 always505226.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.
alias.10.nfz18.10.yourdomain.com. 60 IN	MX	0 always503057.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.
alias.10.nfz18.10.yourdomain.com. 60 IN	MX	0 always523533.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 910

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz19.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz19.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 64961
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz19.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz19.10.yourdomain.com. 60 IN	MX	0 always181133.\195\229?]\172Or\129D\254.yourdomain.com.
alias.10.nfz19.10.yourdomain.com. 60 IN	MX	0 always002812.\138n2\243\134y\175S\238\217.yourdomain.com.
alias.10.nfz19.10.yourdomain.com. 60 IN	MX	0 always612569.\023[\160\130\227\178]\021\001Q.yourdomain.com.
alias.10.nfz19.10.yourdomain.com. 60 IN	MX	0 always081715.\230\184\131\137\001\144:\252\223*.yourdomain.com.
alias.10.nfz19.10.yourdomain.com. 60 IN	MX	0 always896363.m\229\194\247\009\252\133\229\2181.yourdomain.com.
alias.10.nfz19.10.yourdomain.com. 60 IN	MX	0 always853795.`\247\189rx\190\226\144\157\184.yourdomain.com.
alias.10.nfz19.10.yourdomain.com. 60 IN	MX	0 always642400.\176\154\238\217\218\227F\212\1430.yourdomain.com.
alias.10.nfz19.10.yourdomain.com. 60 IN	MX	0 always441430.\233a\142[R\137\129\191\025\184.yourdomain.com.
alias.10.nfz19.10.yourdomain.com. 60 IN	MX	0 always356089.\025\015\020\151_\252^\157x\203.yourdomain.com.
alias.10.nfz19.10.yourdomain.com. 60 IN	MX	0 always866078.\172/\222\031\136\251\202\158\207\146.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 910

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz20.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz20.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 25180
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz20.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz20.10.yourdomain.com. 60 IN	MX	0 always436010.\197\197\197\197\197\197\197\197\197\197.yourdomain.com.
alias.10.nfz20.10.yourdomain.com. 60 IN	MX	0 always449634.\144\144\144\144\144\144\144\144\144\144.yourdomain.com.
alias.10.nfz20.10.yourdomain.com. 60 IN	MX	0 always759549.5555555555.yourdomain.com.
alias.10.nfz20.10.yourdomain.com. 60 IN	MX	0 always051795.\206\206\206\206\206\206\206\206\206\206.yourdomain.com.
alias.10.nfz20.10.yourdomain.com. 60 IN	MX	0 always218844.\140\140\140\140\140\140\140\140\140\140.yourdomain.com.
alias.10.nfz20.10.yourdomain.com. 60 IN	MX	0 always356570.~~~~~~~~~~.yourdomain.com.
alias.10.nfz20.10.yourdomain.com. 60 IN	MX	0 always881510.\017\017\017\017\017\017\017\017\017\017.yourdomain.com.
alias.10.nfz20.10.yourdomain.com. 60 IN	MX	0 always664761.\140\140\140\140\140\140\140\140\140\140.yourdomain.com.
alias.10.nfz20.10.yourdomain.com. 60 IN	MX	0 always089092.aaaaaaaaaa.yourdomain.com.
alias.10.nfz20.10.yourdomain.com. 60 IN	MX	0 always196257.==========.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 910

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz21.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz21.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1383
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz21.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz21.10.yourdomain.com. 60 IN	MX	0 always020825.\000\001\002\003\004\005\006\007\008\009.yourdomain.com.
alias.10.nfz21.10.yourdomain.com. 60 IN	MX	0 always832117.\010\011\012\013\014\015\016\017\018\019.yourdomain.com.
alias.10.nfz21.10.yourdomain.com. 60 IN	MX	0 always850504.\020\021\022\023\024\025\026\027\028\029.yourdomain.com.
alias.10.nfz21.10.yourdomain.com. 60 IN	MX	0 always353381.\030\031\032!\"#\$%&'.yourdomain.com.
alias.10.nfz21.10.yourdomain.com. 60 IN	MX	0 always041382.\(\)*+,-\./01.yourdomain.com.
alias.10.nfz21.10.yourdomain.com. 60 IN	MX	0 always409462.23456789:\;.yourdomain.com.
alias.10.nfz21.10.yourdomain.com. 60 IN	MX	0 always230386.<=>?\@ABCDE.yourdomain.com.
alias.10.nfz21.10.yourdomain.com. 60 IN	MX	0 always805332.FGHIJKLMNO.yourdomain.com.
alias.10.nfz21.10.yourdomain.com. 60 IN	MX	0 always450865.PQRSTUVWXY.yourdomain.com.
alias.10.nfz21.10.yourdomain.com. 60 IN	MX	0 always873205.Z[\\]^_`abc.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 910

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz22.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz22.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 40155
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz22.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz22.10.yourdomain.com. 60 IN	MX	0 always480590.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.
alias.10.nfz22.10.yourdomain.com. 60 IN	MX	0 always063696.\001\001\001\001\001\001\001\001\001\001.yourdomain.com.
alias.10.nfz22.10.yourdomain.com. 60 IN	MX	0 always506694.\002\002\002\002\002\002\002\002\002\002.yourdomain.com.
alias.10.nfz22.10.yourdomain.com. 60 IN	MX	0 always529035.\003\003\003\003\003\003\003\003\003\003.yourdomain.com.
alias.10.nfz22.10.yourdomain.com. 60 IN	MX	0 always406740.\004\004\004\004\004\004\004\004\004\004.yourdomain.com.
alias.10.nfz22.10.yourdomain.com. 60 IN	MX	0 always704966.\005\005\005\005\005\005\005\005\005\005.yourdomain.com.
alias.10.nfz22.10.yourdomain.com. 60 IN	MX	0 always316254.\006\006\006\006\006\006\006\006\006\006.yourdomain.com.
alias.10.nfz22.10.yourdomain.com. 60 IN	MX	0 always822482.\007\007\007\007\007\007\007\007\007\007.yourdomain.com.
alias.10.nfz22.10.yourdomain.com. 60 IN	MX	0 always027040.\008\008\008\008\008\008\008\008\008\008.yourdomain.com.
alias.10.nfz22.10.yourdomain.com. 60 IN	MX	0 always414886.\009\009\009\009\009\009\009\009\009\009.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 910

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz23.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz23.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 63435
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz23.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz23.10.yourdomain.com. 60 IN	MX	0 always726970.\129.\209.i.S.}.3.\141.\202.\156.\179.yourdomain.com.
alias.10.nfz23.10.yourdomain.com. 60 IN	MX	0 always149899.K.N.\152.\170.\189.[.3.\178.8.e.yourdomain.com.
alias.10.nfz23.10.yourdomain.com. 60 IN	MX	0 always355378.3.7.X.\233.A.\131.b.\158.\220.\202.yourdomain.com.
alias.10.nfz23.10.yourdomain.com. 60 IN	MX	0 always721831.\205.\163.\137.\023.\021.\236.\240.\238.\146.w.yourdomain.com.
alias.10.nfz23.10.yourdomain.com. 60 IN	MX	0 always474210.\248.\032.\227.\167.6.\247.\183.\230.\203.\215.yourdomain.com.
alias.10.nfz23.10.yourdomain.com. 60 IN	MX	0 always308018.\238.i.\002.\150.5.\225.m.\165.\207.\238.yourdomain.com.
alias.10.nfz23.10.yourdomain.com. 60 IN	MX	0 always371175.\199.\133.B.V.\183.\214.\195.f.\171.\133.yourdomain.com.
alias.10.nfz23.10.yourdomain.com. 60 IN	MX	0 always331871.=.\254.s.\223.i.\254.:.\224.\151.\235.yourdomain.com.
alias.10.nfz23.10.yourdomain.com. 60 IN	MX	0 always495541.u.\190.U.\011.V.\167.R.\010.\192.\243.yourdomain.com.
alias.10.nfz23.10.yourdomain.com. 60 IN	MX	0 always986347.a.u.\144.p.W.l.\220.\220.\$.\030.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 1000

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz24.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz24.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41601
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz24.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz24.10.yourdomain.com. 60 IN	MX	0 always559595.w.J.>.1.=.s.|.\(.M.1.yourdomain.com.
alias.10.nfz24.10.yourdomain.com. 60 IN	MX	0 always800241.h.\011.\".K.9.\\.G.x.m.a.yourdomain.com.
alias.10.nfz24.10.yourdomain.com. 60 IN	MX	0 always292171.e.P.x.o.m.\".N.u.{.R.yourdomain.com.
alias.10.nfz24.10.yourdomain.com. 60 IN	MX	0 always677158./.Z.o.6.\@.\012.\@.&.c.7.yourdomain.com.
alias.10.nfz24.10.yourdomain.com. 60 IN	MX	0 always036101.1.P.M.g.`.+.z.\).n.p.yourdomain.com.
alias.10.nfz24.10.yourdomain.com. 60 IN	MX	0 always581546.m.#.4.3.F.5.C.k.'.\\.yourdomain.com.
alias.10.nfz24.10.yourdomain.com. 60 IN	MX	0 always615455.K.D.W.U.=.9.,.X.r.7.yourdomain.com.
alias.10.nfz24.10.yourdomain.com. 60 IN	MX	0 always892590.L.o.Q.#.Z.0.}.x.l.m.yourdomain.com.
alias.10.nfz24.10.yourdomain.com. 60 IN	MX	0 always553381.'.-.7.=.-.r.\013.n.\010.8.yourdomain.com.
alias.10.nfz24.10.yourdomain.com. 60 IN	MX	0 always667724.d.\".z.C.b.H.\012.E.\".C.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 1000

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz25.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz25.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 48927
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz25.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz25.10.yourdomain.com. 60 IN	MX	0 always311270.r.6.h.y.h.j.s.i.3.b.yourdomain.com.
alias.10.nfz25.10.yourdomain.com. 60 IN	MX	0 always033861.x.s.g.m.g.i.q.r.m.c.yourdomain.com.
alias.10.nfz25.10.yourdomain.com. 60 IN	MX	0 always824650.u.w.h.g.8.2.7.m.r.3.yourdomain.com.
alias.10.nfz25.10.yourdomain.com. 60 IN	MX	0 always102853.z.k.2.z.b.x.e.6.9.3.yourdomain.com.
alias.10.nfz25.10.yourdomain.com. 60 IN	MX	0 always295527.h.w.x.t.g.r.l.d.2.t.yourdomain.com.
alias.10.nfz25.10.yourdomain.com. 60 IN	MX	0 always673014.n.l.6.9.6.a.x.8.l.2.yourdomain.com.
alias.10.nfz25.10.yourdomain.com. 60 IN	MX	0 always300694.f.5.l.t.g.z.n.y.5.y.yourdomain.com.
alias.10.nfz25.10.yourdomain.com. 60 IN	MX	0 always314998.v.s.e.e.z.i.9.a.r.6.yourdomain.com.
alias.10.nfz25.10.yourdomain.com. 60 IN	MX	0 always941885.p.n.d.c.2.2.3.h.d.d.yourdomain.com.
alias.10.nfz25.10.yourdomain.com. 60 IN	MX	0 always797933.j.4.i.j.h.l.x.0.1.d.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 1000

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz26.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz26.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 50760
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz26.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz26.10.yourdomain.com. 60 IN	MX	0 always521749.\000.\001.\002.\003.\004.\005.\006.\007.\008.\009.yourdomain.com.
alias.10.nfz26.10.yourdomain.com. 60 IN	MX	0 always998072.\010.\011.\012.\013.\014.\015.\016.\017.\018.\019.yourdomain.com.
alias.10.nfz26.10.yourdomain.com. 60 IN	MX	0 always408721.\020.\021.\022.\023.\024.\025.\026.\027.\028.\029.yourdomain.com.
alias.10.nfz26.10.yourdomain.com. 60 IN	MX	0 always286235.\030.\031.\032.!.\".#.\$.%.&.'.yourdomain.com.
alias.10.nfz26.10.yourdomain.com. 60 IN	MX	0 always174519.\(.\).*.+.,.-.\../.0.1.yourdomain.com.
alias.10.nfz26.10.yourdomain.com. 60 IN	MX	0 always963495.2.3.4.5.6.7.8.9.:.\;.yourdomain.com.
alias.10.nfz26.10.yourdomain.com. 60 IN	MX	0 always458390.<.=.>.?.\@.A.B.C.D.E.yourdomain.com.
alias.10.nfz26.10.yourdomain.com. 60 IN	MX	0 always047740.F.G.H.I.J.K.L.M.N.O.yourdomain.com.
alias.10.nfz26.10.yourdomain.com. 60 IN	MX	0 always300303.P.Q.R.S.T.U.V.W.X.Y.yourdomain.com.
alias.10.nfz26.10.yourdomain.com. 60 IN	MX	0 always954772.Z.[.\\.].^._.`.a.b.c.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 1000

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz27.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz27.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 252
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz27.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz27.10.yourdomain.com. 60 IN	MX	0 always269358.\000.\000.\000.\000.\000.\000.\000.\000.\000.\000.yourdomain.com.
alias.10.nfz27.10.yourdomain.com. 60 IN	MX	0 always066417.\001.\001.\001.\001.\001.\001.\001.\001.\001.\001.yourdomain.com.
alias.10.nfz27.10.yourdomain.com. 60 IN	MX	0 always139309.\002.\002.\002.\002.\002.\002.\002.\002.\002.\002.yourdomain.com.
alias.10.nfz27.10.yourdomain.com. 60 IN	MX	0 always769193.\003.\003.\003.\003.\003.\003.\003.\003.\003.\003.yourdomain.com.
alias.10.nfz27.10.yourdomain.com. 60 IN	MX	0 always511345.\004.\004.\004.\004.\004.\004.\004.\004.\004.\004.yourdomain.com.
alias.10.nfz27.10.yourdomain.com. 60 IN	MX	0 always469763.\005.\005.\005.\005.\005.\005.\005.\005.\005.\005.yourdomain.com.
alias.10.nfz27.10.yourdomain.com. 60 IN	MX	0 always792088.\006.\006.\006.\006.\006.\006.\006.\006.\006.\006.yourdomain.com.
alias.10.nfz27.10.yourdomain.com. 60 IN	MX	0 always280850.\007.\007.\007.\007.\007.\007.\007.\007.\007.\007.yourdomain.com.
alias.10.nfz27.10.yourdomain.com. 60 IN	MX	0 always020532.\008.\008.\008.\008.\008.\008.\008.\008.\008.\008.yourdomain.com.
alias.10.nfz27.10.yourdomain.com. 60 IN	MX	0 always483824.\009.\009.\009.\009.\009.\009.\009.\009.\009.\009.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 1000

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz28.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz28.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 21393
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz28.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz28.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always265307.yourdomain.com.
alias.10.nfz28.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always461261.yourdomain.com.
alias.10.nfz28.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always435895.yourdomain.com.
alias.10.nfz28.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always334807.yourdomain.com.
alias.10.nfz28.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always545495.yourdomain.com.
alias.10.nfz28.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always456664.yourdomain.com.
alias.10.nfz28.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always836291.yourdomain.com.
alias.10.nfz28.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always016440.yourdomain.com.
alias.10.nfz28.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always392590.yourdomain.com.
alias.10.nfz28.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always869845.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 900

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz29.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz29.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51581
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz29.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz29.10.yourdomain.com. 60 IN	MX	0 S\229\202-\180e\026Ok\025always893549.yourdomain.com.
alias.10.nfz29.10.yourdomain.com. 60 IN	MX	0 \245Y\252\203\242\139\012c\193\249always644450.yourdomain.com.
alias.10.nfz29.10.yourdomain.com. 60 IN	MX	0 K\023v\135\217,J\007\158\213always741330.yourdomain.com.
alias.10.nfz29.10.yourdomain.com. 60 IN	MX	0 \1541\185r\201An\178\000<always784993.yourdomain.com.
alias.10.nfz29.10.yourdomain.com. 60 IN	MX	0 \214\203\223\143\223\179\013\225\161\198always831309.yourdomain.com.
alias.10.nfz29.10.yourdomain.com. 60 IN	MX	0 \167\009:\190\011\133\246Yw\222always844916.yourdomain.com.
alias.10.nfz29.10.yourdomain.com. 60 IN	MX	0 \131#y\015\136\248\188\240*]always172605.yourdomain.com.
alias.10.nfz29.10.yourdomain.com. 60 IN	MX	0 \011\141\020\248\232\1840\022\159\;always662135.yourdomain.com.
alias.10.nfz29.10.yourdomain.com. 60 IN	MX	0 \150b\148\184\129\133\.\203\247\147always661876.yourdomain.com.
alias.10.nfz29.10.yourdomain.com. 60 IN	MX	0 \2377\021\027O\155CXl\032always434240.yourdomain.com.

;; Query time: 3 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 900

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz30.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz30.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 53363
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz30.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz30.10.yourdomain.com. 60 IN	MX	0 IIIIIIIIIIalways521982.yourdomain.com.
alias.10.nfz30.10.yourdomain.com. 60 IN	MX	0 \185\185\185\185\185\185\185\185\185\185always158118.yourdomain.com.
alias.10.nfz30.10.yourdomain.com. 60 IN	MX	0 \177\177\177\177\177\177\177\177\177\177always239896.yourdomain.com.
alias.10.nfz30.10.yourdomain.com. 60 IN	MX	0 \127\127\127\127\127\127\127\127\127\127always226299.yourdomain.com.
alias.10.nfz30.10.yourdomain.com. 60 IN	MX	0 \160\160\160\160\160\160\160\160\160\160always474536.yourdomain.com.
alias.10.nfz30.10.yourdomain.com. 60 IN	MX	0 \183\183\183\183\183\183\183\183\183\183always092473.yourdomain.com.
alias.10.nfz30.10.yourdomain.com. 60 IN	MX	0 \018\018\018\018\018\018\018\018\018\018always853991.yourdomain.com.
alias.10.nfz30.10.yourdomain.com. 60 IN	MX	0 <<<<<<<<<<always253980.yourdomain.com.
alias.10.nfz30.10.yourdomain.com. 60 IN	MX	0 \252\252\252\252\252\252\252\252\252\252always985766.yourdomain.com.
alias.10.nfz30.10.yourdomain.com. 60 IN	MX	0 \201\201\201\201\201\201\201\201\201\201always202080.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 900

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz31.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz31.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1223
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz31.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz31.10.yourdomain.com. 60 IN	MX	0 \000\001\002\003\004\005\006\007\008\009always030923.yourdomain.com.
alias.10.nfz31.10.yourdomain.com. 60 IN	MX	0 \010\011\012\013\014\015\016\017\018\019always562672.yourdomain.com.
alias.10.nfz31.10.yourdomain.com. 60 IN	MX	0 \020\021\022\023\024\025\026\027\028\029always844306.yourdomain.com.
alias.10.nfz31.10.yourdomain.com. 60 IN	MX	0 \030\031\032!\"#\$%&'always217020.yourdomain.com.
alias.10.nfz31.10.yourdomain.com. 60 IN	MX	0 \(\)*+,-\./01always400197.yourdomain.com.
alias.10.nfz31.10.yourdomain.com. 60 IN	MX	0 23456789:\;always397970.yourdomain.com.
alias.10.nfz31.10.yourdomain.com. 60 IN	MX	0 <=>?\@ABCDEalways803553.yourdomain.com.
alias.10.nfz31.10.yourdomain.com. 60 IN	MX	0 FGHIJKLMNOalways743179.yourdomain.com.
alias.10.nfz31.10.yourdomain.com. 60 IN	MX	0 PQRSTUVWXYalways618461.yourdomain.com.
alias.10.nfz31.10.yourdomain.com. 60 IN	MX	0 Z[\\]^_`abcalways212032.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 900

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz32.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz32.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 13180
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz32.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz32.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always138153.yourdomain.com.
alias.10.nfz32.10.yourdomain.com. 60 IN	MX	0 \001\001\001\001\001\001\001\001\001\001always682804.yourdomain.com.
alias.10.nfz32.10.yourdomain.com. 60 IN	MX	0 \002\002\002\002\002\002\002\002\002\002always488471.yourdomain.com.
alias.10.nfz32.10.yourdomain.com. 60 IN	MX	0 \003\003\003\003\003\003\003\003\003\003always682527.yourdomain.com.
alias.10.nfz32.10.yourdomain.com. 60 IN	MX	0 \004\004\004\004\004\004\004\004\004\004always910323.yourdomain.com.
alias.10.nfz32.10.yourdomain.com. 60 IN	MX	0 \005\005\005\005\005\005\005\005\005\005always360362.yourdomain.com.
alias.10.nfz32.10.yourdomain.com. 60 IN	MX	0 \006\006\006\006\006\006\006\006\006\006always761113.yourdomain.com.
alias.10.nfz32.10.yourdomain.com. 60 IN	MX	0 \007\007\007\007\007\007\007\007\007\007always677566.yourdomain.com.
alias.10.nfz32.10.yourdomain.com. 60 IN	MX	0 \008\008\008\008\008\008\008\008\008\008always362847.yourdomain.com.
alias.10.nfz32.10.yourdomain.com. 60 IN	MX	0 \009\009\009\009\009\009\009\009\009\009always425390.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 900

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz33.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz33.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7567
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz33.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz33.10.yourdomain.com. 60 IN	MX	0 always856381.yourdomain.com\000\000\000\000\000\000\000\000\000\000.
alias.10.nfz33.10.yourdomain.com. 60 IN	MX	0 always317587.yourdomain.com\000\000\000\000\000\000\000\000\000\000.
alias.10.nfz33.10.yourdomain.com. 60 IN	MX	0 always482616.yourdomain.com\000\000\000\000\000\000\000\000\000\000.
alias.10.nfz33.10.yourdomain.com. 60 IN	MX	0 always248066.yourdomain.com\000\000\000\000\000\000\000\000\000\000.
alias.10.nfz33.10.yourdomain.com. 60 IN	MX	0 always838925.yourdomain.com\000\000\000\000\000\000\000\000\000\000.
alias.10.nfz33.10.yourdomain.com. 60 IN	MX	0 always629152.yourdomain.com\000\000\000\000\000\000\000\000\000\000.
alias.10.nfz33.10.yourdomain.com. 60 IN	MX	0 always028376.yourdomain.com\000\000\000\000\000\000\000\000\000\000.
alias.10.nfz33.10.yourdomain.com. 60 IN	MX	0 always262932.yourdomain.com\000\000\000\000\000\000\000\000\000\000.
alias.10.nfz33.10.yourdomain.com. 60 IN	MX	0 always282218.yourdomain.com\000\000\000\000\000\000\000\000\000\000.
alias.10.nfz33.10.yourdomain.com. 60 IN	MX	0 always567997.yourdomain.com\000\000\000\000\000\000\000\000\000\000.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 900

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz34.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz34.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 11102
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz34.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz34.10.yourdomain.com. 60 IN	MX	0 always555923.yourdomain.comWr\1955\002\195\138T_B.
alias.10.nfz34.10.yourdomain.com. 60 IN	MX	0 always022237.yourdomain.com\022y\186\006\224[\029\224\231\236.
alias.10.nfz34.10.yourdomain.com. 60 IN	MX	0 always075078.yourdomain.com4\164\182\219\;6\216\222\223\248.
alias.10.nfz34.10.yourdomain.com. 60 IN	MX	0 always224366.yourdomain.com\171\(\185\210<GqW`k.
alias.10.nfz34.10.yourdomain.com. 60 IN	MX	0 always017478.yourdomain.com\144\241\202\238x\183W&\165\252.
alias.10.nfz34.10.yourdomain.com. 60 IN	MX	0 always282503.yourdomain.comRs[\001\202\151\221L\163~.
alias.10.nfz34.10.yourdomain.com. 60 IN	MX	0 always900429.yourdomain.comZI\184\149\155\180\\ML`.
alias.10.nfz34.10.yourdomain.com. 60 IN	MX	0 always031494.yourdomain.com\140\196F\223u\160\003\174\213\224.
alias.10.nfz34.10.yourdomain.com. 60 IN	MX	0 always713129.yourdomain.com\219\009_2\028\010x}<\021.
alias.10.nfz34.10.yourdomain.com. 60 IN	MX	0 always129110.yourdomain.com\153\005\023J8J\198\155\217*.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 900

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz35.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz35.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32696
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz35.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz35.10.yourdomain.com. 60 IN	MX	0 always281025.yourdomain.com\250\250\250\250\250\250\250\250\250\250.
alias.10.nfz35.10.yourdomain.com. 60 IN	MX	0 always479284.yourdomain.com]]]]]]]]]].
alias.10.nfz35.10.yourdomain.com. 60 IN	MX	0 always270733.yourdomain.com\017\017\017\017\017\017\017\017\017\017.
alias.10.nfz35.10.yourdomain.com. 60 IN	MX	0 always310376.yourdomain.com\248\248\248\248\248\248\248\248\248\248.
alias.10.nfz35.10.yourdomain.com. 60 IN	MX	0 always725707.yourdomain.com\147\147\147\147\147\147\147\147\147\147.
alias.10.nfz35.10.yourdomain.com. 60 IN	MX	0 always082209.yourdomain.com\137\137\137\137\137\137\137\137\137\137.
alias.10.nfz35.10.yourdomain.com. 60 IN	MX	0 always894278.yourdomain.com\237\237\237\237\237\237\237\237\237\237.
alias.10.nfz35.10.yourdomain.com. 60 IN	MX	0 always077687.yourdomain.com\187\187\187\187\187\187\187\187\187\187.
alias.10.nfz35.10.yourdomain.com. 60 IN	MX	0 always352592.yourdomain.com\030\030\030\030\030\030\030\030\030\030.
alias.10.nfz35.10.yourdomain.com. 60 IN	MX	0 always800417.yourdomain.com\233\233\233\233\233\233\233\233\233\233.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 900

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz36.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz36.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 21720
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz36.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz36.10.yourdomain.com. 60 IN	MX	0 always607461.yourdomain.com\000\001\002\003\004\005\006\007\008\009.
alias.10.nfz36.10.yourdomain.com. 60 IN	MX	0 always410144.yourdomain.com\010\011\012\013\014\015\016\017\018\019.
alias.10.nfz36.10.yourdomain.com. 60 IN	MX	0 always977644.yourdomain.com\020\021\022\023\024\025\026\027\028\029.
alias.10.nfz36.10.yourdomain.com. 60 IN	MX	0 always329522.yourdomain.com\030\031\032!\"#\$%&'.
alias.10.nfz36.10.yourdomain.com. 60 IN	MX	0 always966580.yourdomain.com\(\)*+,-\./01.
alias.10.nfz36.10.yourdomain.com. 60 IN	MX	0 always189804.yourdomain.com23456789:\;.
alias.10.nfz36.10.yourdomain.com. 60 IN	MX	0 always291752.yourdomain.com<=>?\@ABCDE.
alias.10.nfz36.10.yourdomain.com. 60 IN	MX	0 always509312.yourdomain.comFGHIJKLMNO.
alias.10.nfz36.10.yourdomain.com. 60 IN	MX	0 always608320.yourdomain.comPQRSTUVWXY.
alias.10.nfz36.10.yourdomain.com. 60 IN	MX	0 always340892.yourdomain.comZ[\\]^_`abc.

;; Query time: 3 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 900

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz37.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz37.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 34725
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz37.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz37.10.yourdomain.com. 60 IN	MX	0 always477824.yourdomain.com\000\000\000\000\000\000\000\000\000\000.
alias.10.nfz37.10.yourdomain.com. 60 IN	MX	0 always901234.yourdomain.com\001\001\001\001\001\001\001\001\001\001.
alias.10.nfz37.10.yourdomain.com. 60 IN	MX	0 always782923.yourdomain.com\002\002\002\002\002\002\002\002\002\002.
alias.10.nfz37.10.yourdomain.com. 60 IN	MX	0 always661052.yourdomain.com\003\003\003\003\003\003\003\003\003\003.
alias.10.nfz37.10.yourdomain.com. 60 IN	MX	0 always146207.yourdomain.com\004\004\004\004\004\004\004\004\004\004.
alias.10.nfz37.10.yourdomain.com. 60 IN	MX	0 always002125.yourdomain.com\005\005\005\005\005\005\005\005\005\005.
alias.10.nfz37.10.yourdomain.com. 60 IN	MX	0 always259466.yourdomain.com\006\006\006\006\006\006\006\006\006\006.
alias.10.nfz37.10.yourdomain.com. 60 IN	MX	0 always871271.yourdomain.com\007\007\007\007\007\007\007\007\007\007.
alias.10.nfz37.10.yourdomain.com. 60 IN	MX	0 always743811.yourdomain.com\008\008\008\008\008\008\008\008\008\008.
alias.10.nfz37.10.yourdomain.com. 60 IN	MX	0 always243218.yourdomain.com\009\009\009\009\009\009\009\009\009\009.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 900

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz38.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz38.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 6632
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz38.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz38.10.yourdomain.com. 60 IN	MX	0 always004581.yourdomain.com:80.
alias.10.nfz38.10.yourdomain.com. 60 IN	MX	0 always620332.yourdomain.com:80.
alias.10.nfz38.10.yourdomain.com. 60 IN	MX	0 always833191.yourdomain.com:80.
alias.10.nfz38.10.yourdomain.com. 60 IN	MX	0 always334943.yourdomain.com:80.
alias.10.nfz38.10.yourdomain.com. 60 IN	MX	0 always852243.yourdomain.com:80.
alias.10.nfz38.10.yourdomain.com. 60 IN	MX	0 always890649.yourdomain.com:80.
alias.10.nfz38.10.yourdomain.com. 60 IN	MX	0 always863608.yourdomain.com:80.
alias.10.nfz38.10.yourdomain.com. 60 IN	MX	0 always489773.yourdomain.com:80.
alias.10.nfz38.10.yourdomain.com. 60 IN	MX	0 always024725.yourdomain.com:80.
alias.10.nfz38.10.yourdomain.com. 60 IN	MX	0 always128819.yourdomain.com:80.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 830

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz39.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz39.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 18241
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz39.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz39.10.yourdomain.com. 60 IN	MX	0 always607900.yourdomain.com:443.
alias.10.nfz39.10.yourdomain.com. 60 IN	MX	0 always738698.yourdomain.com:443.
alias.10.nfz39.10.yourdomain.com. 60 IN	MX	0 always311886.yourdomain.com:443.
alias.10.nfz39.10.yourdomain.com. 60 IN	MX	0 always523012.yourdomain.com:443.
alias.10.nfz39.10.yourdomain.com. 60 IN	MX	0 always874044.yourdomain.com:443.
alias.10.nfz39.10.yourdomain.com. 60 IN	MX	0 always689217.yourdomain.com:443.
alias.10.nfz39.10.yourdomain.com. 60 IN	MX	0 always087820.yourdomain.com:443.
alias.10.nfz39.10.yourdomain.com. 60 IN	MX	0 always715061.yourdomain.com:443.
alias.10.nfz39.10.yourdomain.com. 60 IN	MX	0 always665196.yourdomain.com:443.
alias.10.nfz39.10.yourdomain.com. 60 IN	MX	0 always934879.yourdomain.com:443.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 840

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz40.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz40.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 60723
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz40.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz40.10.yourdomain.com. 60 IN	MX	0 http://always399833.yourdomain.com/.
alias.10.nfz40.10.yourdomain.com. 60 IN	MX	0 http://always453649.yourdomain.com/.
alias.10.nfz40.10.yourdomain.com. 60 IN	MX	0 http://always102888.yourdomain.com/.
alias.10.nfz40.10.yourdomain.com. 60 IN	MX	0 http://always228703.yourdomain.com/.
alias.10.nfz40.10.yourdomain.com. 60 IN	MX	0 http://always215762.yourdomain.com/.
alias.10.nfz40.10.yourdomain.com. 60 IN	MX	0 http://always200251.yourdomain.com/.
alias.10.nfz40.10.yourdomain.com. 60 IN	MX	0 http://always067908.yourdomain.com/.
alias.10.nfz40.10.yourdomain.com. 60 IN	MX	0 http://always627667.yourdomain.com/.
alias.10.nfz40.10.yourdomain.com. 60 IN	MX	0 http://always392659.yourdomain.com/.
alias.10.nfz40.10.yourdomain.com. 60 IN	MX	0 http://always081657.yourdomain.com/.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 880

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz41.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz41.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 6640
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz41.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz41.10.yourdomain.com. 60 IN	MX	0 http://always396822.yourdomain.com:80/.
alias.10.nfz41.10.yourdomain.com. 60 IN	MX	0 http://always142593.yourdomain.com:80/.
alias.10.nfz41.10.yourdomain.com. 60 IN	MX	0 http://always721367.yourdomain.com:80/.
alias.10.nfz41.10.yourdomain.com. 60 IN	MX	0 http://always767400.yourdomain.com:80/.
alias.10.nfz41.10.yourdomain.com. 60 IN	MX	0 http://always149434.yourdomain.com:80/.
alias.10.nfz41.10.yourdomain.com. 60 IN	MX	0 http://always587145.yourdomain.com:80/.
alias.10.nfz41.10.yourdomain.com. 60 IN	MX	0 http://always005461.yourdomain.com:80/.
alias.10.nfz41.10.yourdomain.com. 60 IN	MX	0 http://always177389.yourdomain.com:80/.
alias.10.nfz41.10.yourdomain.com. 60 IN	MX	0 http://always643335.yourdomain.com:80/.
alias.10.nfz41.10.yourdomain.com. 60 IN	MX	0 http://always270310.yourdomain.com:80/.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 910

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz42.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz42.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 57231
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz42.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz42.10.yourdomain.com. 60 IN	MX	0 https://always565117.yourdomain.com/.
alias.10.nfz42.10.yourdomain.com. 60 IN	MX	0 https://always391293.yourdomain.com/.
alias.10.nfz42.10.yourdomain.com. 60 IN	MX	0 https://always752066.yourdomain.com/.
alias.10.nfz42.10.yourdomain.com. 60 IN	MX	0 https://always639729.yourdomain.com/.
alias.10.nfz42.10.yourdomain.com. 60 IN	MX	0 https://always329244.yourdomain.com/.
alias.10.nfz42.10.yourdomain.com. 60 IN	MX	0 https://always049400.yourdomain.com/.
alias.10.nfz42.10.yourdomain.com. 60 IN	MX	0 https://always025722.yourdomain.com/.
alias.10.nfz42.10.yourdomain.com. 60 IN	MX	0 https://always582802.yourdomain.com/.
alias.10.nfz42.10.yourdomain.com. 60 IN	MX	0 https://always036505.yourdomain.com/.
alias.10.nfz42.10.yourdomain.com. 60 IN	MX	0 https://always292396.yourdomain.com/.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 890

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz43.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz43.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 64695
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz43.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz43.10.yourdomain.com. 60 IN	MX	0 https://always109772.yourdomain.com:443/.
alias.10.nfz43.10.yourdomain.com. 60 IN	MX	0 https://always851821.yourdomain.com:443/.
alias.10.nfz43.10.yourdomain.com. 60 IN	MX	0 https://always831221.yourdomain.com:443/.
alias.10.nfz43.10.yourdomain.com. 60 IN	MX	0 https://always089441.yourdomain.com:443/.
alias.10.nfz43.10.yourdomain.com. 60 IN	MX	0 https://always022735.yourdomain.com:443/.
alias.10.nfz43.10.yourdomain.com. 60 IN	MX	0 https://always232039.yourdomain.com:443/.
alias.10.nfz43.10.yourdomain.com. 60 IN	MX	0 https://always190227.yourdomain.com:443/.
alias.10.nfz43.10.yourdomain.com. 60 IN	MX	0 https://always472110.yourdomain.com:443/.
alias.10.nfz43.10.yourdomain.com. 60 IN	MX	0 https://always097308.yourdomain.com:443/.
alias.10.nfz43.10.yourdomain.com. 60 IN	MX	0 https://always056394.yourdomain.com:443/.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 930

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz44.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz44.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 59428
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz44.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz44.10.yourdomain.com. 60 IN	MX	0 1.2.3.4.
alias.10.nfz44.10.yourdomain.com. 60 IN	MX	0 1.2.3.4.
alias.10.nfz44.10.yourdomain.com. 60 IN	MX	0 1.2.3.4.
alias.10.nfz44.10.yourdomain.com. 60 IN	MX	0 1.2.3.4.
alias.10.nfz44.10.yourdomain.com. 60 IN	MX	0 1.2.3.4.
alias.10.nfz44.10.yourdomain.com. 60 IN	MX	0 1.2.3.4.
alias.10.nfz44.10.yourdomain.com. 60 IN	MX	0 1.2.3.4.
alias.10.nfz44.10.yourdomain.com. 60 IN	MX	0 1.2.3.4.
alias.10.nfz44.10.yourdomain.com. 60 IN	MX	0 1.2.3.4.
alias.10.nfz44.10.yourdomain.com. 60 IN	MX	0 1.2.3.4.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 600

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz45.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz45.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 35571
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz45.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz45.10.yourdomain.com. 60 IN	MX	0 1.2.3.4:80.
alias.10.nfz45.10.yourdomain.com. 60 IN	MX	0 1.2.3.4:80.
alias.10.nfz45.10.yourdomain.com. 60 IN	MX	0 1.2.3.4:80.
alias.10.nfz45.10.yourdomain.com. 60 IN	MX	0 1.2.3.4:80.
alias.10.nfz45.10.yourdomain.com. 60 IN	MX	0 1.2.3.4:80.
alias.10.nfz45.10.yourdomain.com. 60 IN	MX	0 1.2.3.4:80.
alias.10.nfz45.10.yourdomain.com. 60 IN	MX	0 1.2.3.4:80.
alias.10.nfz45.10.yourdomain.com. 60 IN	MX	0 1.2.3.4:80.
alias.10.nfz45.10.yourdomain.com. 60 IN	MX	0 1.2.3.4:80.
alias.10.nfz45.10.yourdomain.com. 60 IN	MX	0 1.2.3.4:80.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 630

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz46.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz46.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 27832
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz46.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz46.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4.
alias.10.nfz46.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4.
alias.10.nfz46.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4.
alias.10.nfz46.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4.
alias.10.nfz46.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4.
alias.10.nfz46.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4.
alias.10.nfz46.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4.
alias.10.nfz46.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4.
alias.10.nfz46.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4.
alias.10.nfz46.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 600

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz47.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz47.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 39251
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz47.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz47.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4:80.
alias.10.nfz47.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4:80.
alias.10.nfz47.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4:80.
alias.10.nfz47.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4:80.
alias.10.nfz47.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4:80.
alias.10.nfz47.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4:80.
alias.10.nfz47.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4:80.
alias.10.nfz47.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4:80.
alias.10.nfz47.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4:80.
alias.10.nfz47.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4:80.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 630

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz48.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz48.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 63513
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz48.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz48.10.yourdomain.com. 60 IN	MX	0 127.0.0.1.
alias.10.nfz48.10.yourdomain.com. 60 IN	MX	0 127.0.0.1.
alias.10.nfz48.10.yourdomain.com. 60 IN	MX	0 127.0.0.1.
alias.10.nfz48.10.yourdomain.com. 60 IN	MX	0 127.0.0.1.
alias.10.nfz48.10.yourdomain.com. 60 IN	MX	0 127.0.0.1.
alias.10.nfz48.10.yourdomain.com. 60 IN	MX	0 127.0.0.1.
alias.10.nfz48.10.yourdomain.com. 60 IN	MX	0 127.0.0.1.
alias.10.nfz48.10.yourdomain.com. 60 IN	MX	0 127.0.0.1.
alias.10.nfz48.10.yourdomain.com. 60 IN	MX	0 127.0.0.1.
alias.10.nfz48.10.yourdomain.com. 60 IN	MX	0 127.0.0.1.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:41 +04 2024
;; MSG SIZE  rcvd: 620

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz49.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz49.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41635
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz49.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz49.10.yourdomain.com. 60 IN	MX	0 127.0.0.1:80.
alias.10.nfz49.10.yourdomain.com. 60 IN	MX	0 127.0.0.1:80.
alias.10.nfz49.10.yourdomain.com. 60 IN	MX	0 127.0.0.1:80.
alias.10.nfz49.10.yourdomain.com. 60 IN	MX	0 127.0.0.1:80.
alias.10.nfz49.10.yourdomain.com. 60 IN	MX	0 127.0.0.1:80.
alias.10.nfz49.10.yourdomain.com. 60 IN	MX	0 127.0.0.1:80.
alias.10.nfz49.10.yourdomain.com. 60 IN	MX	0 127.0.0.1:80.
alias.10.nfz49.10.yourdomain.com. 60 IN	MX	0 127.0.0.1:80.
alias.10.nfz49.10.yourdomain.com. 60 IN	MX	0 127.0.0.1:80.
alias.10.nfz49.10.yourdomain.com. 60 IN	MX	0 127.0.0.1:80.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 04 00:22:42 +04 2024
;; MSG SIZE  rcvd: 650

```

##
Go back to [menu](#polardns-catalogue---response-modifiers).

