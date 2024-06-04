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
### Name fuzzing generator (nfz)
Generate various illegal and malformed domain names based on the selected variant and size. This generator was primarily created for alias features (such as alias, cnalias, dnalias, etc.) to provide a unified mechanism for generating malformed domain names.

<table>
<tr><td>format:</td><td>anything.nfz&lt;VARIANT-0-40>.&lt;SIZE>.yourdomain.com</td></tr>
<tr><td>remark:</td><td>VARIANT produces the following responses:<br><table> <tr><td>0</td><td colspan="2">NULL byte(s)</td></tr> <tr><td>1</td><td colspan="2">the &lt;ROOT> domain</td></tr> <tr><td>2</td><td colspan="2">random byte(s)</td></tr> <tr><td>3</td><td colspan="2">random byte(s) (repeated)</td></tr> <tr><td>4</td><td colspan="2">incremental byte(s), from 0 to 255</td></tr> <tr><td>5</td><td colspan="2">incremental byte(s), from 0 to 255 (repeated)</td></tr> <tr><td>6</td><td colspan="2">subdomain(s), made of 63 random bytes</td></tr> <tr><td>7</td><td colspan="2">subdomain(s), made of 63 random printable characters</td></tr> <tr><td>8</td><td colspan="2">subdomain(s), made of 63 random letters and numbers</td></tr> <tr><td>9</td><td colspan="2">subdomain(s), made of 1 random byte</td></tr> <tr><td>10</td><td colspan="2">subdomain(s), made of 1 printable character</td></tr> <tr><td>11</td><td colspan="2">subdomain(s), made of 1 letter or a number</td></tr> <tr><td>12</td><td colspan="2">subdomain(s), made of 1 incremental byte from 0 to 255</td></tr> <tr><td>13</td><td colspan="2">subdomain(s), made of 1 incremental byte from 0 to 255 (repeated)</td></tr> <tr><td>14</td><td colspan="2">always123456.&lt;NULL byte(s)>.yourdomain.com</td></tr> <tr><td>15</td><td colspan="2">always123456.&lt;random byte(s)>.yourdomain.com</td></tr> <tr><td>16</td><td colspan="2">always123456.&lt;random byte(s)>.yourdomain.com (repeated)</td></tr> <tr><td>17</td><td colspan="2">always123456.&lt;incremental byte(s) from 0 to 255>.yourdomain.com</td></tr> <tr><td>18</td><td colspan="2">always123456.&lt;incremental byte(s) from 0 to 255>.yourdomain.com (repeated)</td></tr> <tr><td>19</td><td colspan="2">always123456.&lt;random 1 byte long subdomain(s)>.yourdomain.com</td></tr> <tr><td>20</td><td colspan="2">always123456.&lt;random 1 byte long subdomain(s) made of a printable character>.yourdomain.com</td></tr> <tr><td>21</td><td colspan="2">always123456.&lt;random 1 byte long subdomain(s) made of a letter or a number>.yourdomain.com</td></tr> <tr><td>22</td><td colspan="2">always123456.&lt;incremental 1 byte long subdomain(s), from 0 to 255>.yourdomain.com</td></tr> <tr><td>23</td><td colspan="2">always123456.&lt;incremental 1 byte long subdomain(s), from 0 to 255>.yourdomain.com (repeated)</td></tr> <tr><td>24</td><td colspan="2">&lt;NULL byte(s)>always123456.yourdomain.com</td></tr> <tr><td>25</td><td colspan="2">&lt;random byte(s)>always123456.yourdomain.com</td></tr> <tr><td>26</td><td colspan="2">&lt;random byte(s)>always123456.yourdomain.com (repeated)</td></tr> <tr><td>27</td><td colspan="2">&lt;incremental byte(s), from 0 to 255>always123456.yourdomain.com</td></tr> <tr><td>28</td><td colspan="2">&lt;incremental byte(s), from 0 to 255>always123456.yourdomain.com (repeated)</td></tr> <tr><td>29</td><td colspan="2">always123456.yourdomain.com&lt;NULL byte(s)></td></tr> <tr><td>30</td><td colspan="2">always123456.yourdomain.com&lt;random byte(s)></td></tr> <tr><td>31</td><td colspan="2">always123456.yourdomain.com&lt;random byte(s)> (repeated)</td></tr> <tr><td>32</td><td colspan="2">always123456.yourdomain.com&lt;incremental byte(s) from 0 to 255></td></tr> <tr><td>33</td><td colspan="2">always123456.yourdomain.com&lt;incremental byte(s) from 0 to 255> (repeated)</td></tr> <tr><td>34</td><td colspan="2">http://always123456.yourdomain.com/</td></tr> <tr><td>35</td><td colspan="2">http://always123456.yourdomain.com:80/</td></tr> <tr><td>36</td><td colspan="2">https://always123456.yourdomain.com/</td></tr> <tr><td>37</td><td colspan="2">https://always123456.yourdomain.com:443/</td></tr> <tr><td>38</td><td colspan="2">always123456.yourdomain.com:80</td></tr> <tr><td>39</td><td colspan="2">always123456.yourdomain.com:443</td></tr> <tr><td>40</td><td>1.2.3.4</td><td>DNS name notation</td></tr> <tr><td>41</td><td>1.2.3.4:80</td><td>DNS name notation</td></tr> <tr><td>42</td><td>1\.2\.3\.4</td><td>DNS name notation (using a single label with actual dot symbols)</td></tr> <tr><td>43</td><td>1\.2\.3\.4:80</td><td>DNS name notation (using a single label with actual dot symbols)</td></tr> <tr><td>44</td><td>192.0.2.1</td><td>DNS name notation (our own IP address)</td></tr> <tr><td>45</td><td>192.0.2.1:80</td><td>DNS name notation (our own IP address)</td></tr> </table></td></tr>
<tr><td>remark:</td><td>The <a href="http://www.tcpipguide.com/free/t_DNSNameNotationandMessageCompressionTechnique.htm"><strong>DNS name notation</strong></a> is a format used for hostnames and domain names, not IP addresses</td></tr>
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
# dig MX alias.10.nfz0.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz0.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 60309
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
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 619

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz1.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz1.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2564
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
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 509

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz2.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz2.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 52970
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz2.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz2.10.yourdomain.com. 60 IN	MX	0 k\020f\142\173\137\144B\204\$.
alias.10.nfz2.10.yourdomain.com. 60 IN	MX	0 \132\165\165\178\239nr\007\195\237.
alias.10.nfz2.10.yourdomain.com. 60 IN	MX	0 \250\128\141S\026\1627?\198\246.
alias.10.nfz2.10.yourdomain.com. 60 IN	MX	0 \023\148'4_}\1903x\213.
alias.10.nfz2.10.yourdomain.com. 60 IN	MX	0 \217\133\129|\(\030\004\152\130\142.
alias.10.nfz2.10.yourdomain.com. 60 IN	MX	0 \189\018t\139\180\130\170\157\156z.
alias.10.nfz2.10.yourdomain.com. 60 IN	MX	0 \205\142\212\169\153\140e\003\241\;.
alias.10.nfz2.10.yourdomain.com. 60 IN	MX	0 \025\127\175\151\152\148\171r\251\239.
alias.10.nfz2.10.yourdomain.com. 60 IN	MX	0 \203[\171Z|\030O\223\180\(.
alias.10.nfz2.10.yourdomain.com. 60 IN	MX	0 \001\@\203\159\249\;\128\144\190\016.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 619

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz3.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz3.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7111
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz3.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz3.10.yourdomain.com. 60 IN	MX	0 \145\145\145\145\145\145\145\145\145\145.
alias.10.nfz3.10.yourdomain.com. 60 IN	MX	0 qqqqqqqqqq.
alias.10.nfz3.10.yourdomain.com. 60 IN	MX	0 \242\242\242\242\242\242\242\242\242\242.
alias.10.nfz3.10.yourdomain.com. 60 IN	MX	0 \152\152\152\152\152\152\152\152\152\152.
alias.10.nfz3.10.yourdomain.com. 60 IN	MX	0 \186\186\186\186\186\186\186\186\186\186.
alias.10.nfz3.10.yourdomain.com. 60 IN	MX	0 \245\245\245\245\245\245\245\245\245\245.
alias.10.nfz3.10.yourdomain.com. 60 IN	MX	0 \151\151\151\151\151\151\151\151\151\151.
alias.10.nfz3.10.yourdomain.com. 60 IN	MX	0 <<<<<<<<<<.
alias.10.nfz3.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000.
alias.10.nfz3.10.yourdomain.com. 60 IN	MX	0 \230\230\230\230\230\230\230\230\230\230.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 619

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz4.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz4.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 48756
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz4.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz4.10.yourdomain.com. 60 IN	MX	0 \000\001\002\003\004\005\006\007\008\009.
alias.10.nfz4.10.yourdomain.com. 60 IN	MX	0 \010\011\012\013\014\015\016\017\018\019.
alias.10.nfz4.10.yourdomain.com. 60 IN	MX	0 \020\021\022\023\024\025\026\027\028\029.
alias.10.nfz4.10.yourdomain.com. 60 IN	MX	0 \030\031\032!\"#\$%&'.
alias.10.nfz4.10.yourdomain.com. 60 IN	MX	0 \(\)*+,-\./01.
alias.10.nfz4.10.yourdomain.com. 60 IN	MX	0 23456789:\;.
alias.10.nfz4.10.yourdomain.com. 60 IN	MX	0 <=>?\@ABCDE.
alias.10.nfz4.10.yourdomain.com. 60 IN	MX	0 FGHIJKLMNO.
alias.10.nfz4.10.yourdomain.com. 60 IN	MX	0 PQRSTUVWXY.
alias.10.nfz4.10.yourdomain.com. 60 IN	MX	0 Z[\\]^_`abc.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 619

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz5.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz5.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 20528
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz5.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz5.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000.
alias.10.nfz5.10.yourdomain.com. 60 IN	MX	0 \001\001\001\001\001\001\001\001\001\001.
alias.10.nfz5.10.yourdomain.com. 60 IN	MX	0 \002\002\002\002\002\002\002\002\002\002.
alias.10.nfz5.10.yourdomain.com. 60 IN	MX	0 \003\003\003\003\003\003\003\003\003\003.
alias.10.nfz5.10.yourdomain.com. 60 IN	MX	0 \004\004\004\004\004\004\004\004\004\004.
alias.10.nfz5.10.yourdomain.com. 60 IN	MX	0 \005\005\005\005\005\005\005\005\005\005.
alias.10.nfz5.10.yourdomain.com. 60 IN	MX	0 \006\006\006\006\006\006\006\006\006\006.
alias.10.nfz5.10.yourdomain.com. 60 IN	MX	0 \007\007\007\007\007\007\007\007\007\007.
alias.10.nfz5.10.yourdomain.com. 60 IN	MX	0 \008\008\008\008\008\008\008\008\008\008.
alias.10.nfz5.10.yourdomain.com. 60 IN	MX	0 \009\009\009\009\009\009\009\009\009\009.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 619

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz6.3.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz6.3.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 31234
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz6.3.yourdomain.com.	IN	MX

;; ANSWER SECTION:
alias.10.nfz6.3.yourdomain.com.	60 IN	MX	0 \212\024\195\146\153\245\;&6\248\132\160\202\255\159*\225^\221\017cT\143\133\024g\210\229E'\007\157\030L\173sfl\223\164\$M\128\011Y{<\165:\206\020&\135\005\140>}\242\2478M+\160.\159\1638\"\217\215\211L\032\255\2054??\151sD\2214\226\012\167E3\237\022\030W\005\252\224\210]\186\)V\239\013\244\226\032\173j\001\211\1611\011\009\215\152\213\147\032\155A\222\)\217P\245\132\010.\(%\1655\175[N\137\173\027\163\001*h5/|n\004\141\171\005K}H\170-\251\231\239\190\232\228yJ\146\182\133\161\179\144\136\216\157\172\140\169R\133\219\245Z\(\201\136\1723J\157\166\216\220\239.
alias.10.nfz6.3.yourdomain.com.	60 IN	MX	0 \157\008,MC\166\027L\200\203\012u\026\225L\230\148\"\210\010\240\0245\175\157\182%\218\010\215\248,\206p\165\255x\136*\162\011\214\206\248\001\223\180\230\012\;\@\193\213\219\213\017\)NB\161\216s\232.j\129\136\251\130\186\224h\180\221\146EJ\001\235\010\201t\152\228\215\251\183\151\255\146\009\0169x\200\024jrT&\209\181\154\252\027\215\244\217l\217\235\1524\248\215-\252\141\144\234\012\2459|yi{.f\009\132\181i\176\0105\169\235\181\250\168L\130\173\152\157\168d\2248_>\168WV\226\002M\204S\019\017!l\205\236\163\251\145\143\179,\183\177\182+\220\168P0w\209\176=\201\231h\130\199\164z.
alias.10.nfz6.3.yourdomain.com.	60 IN	MX	0 \155\144\187\242\253<\217\214a\173\146\024*\013\184DMe\172\232i\006\@\145\197=D\023A\227C\\y\219\141\(\032o6V\206\250\(\211\198U\009\142\022\166y\001\005\222\195\127\239\184\144\243BMP.\1623&\224\;\192V\163\255\170\237\220\157=\183<\254}\226XN\193\221\189\.\189\255\160u\239z\022+C27r\020\1788\162PQ\184\142\247\230sT\;\213\022\013\239\1819b\021\255\032|5\202.\023~\0196\004\211\173\247\146\165\224\243\155\182NAQ\241\183q\011J\151\214\1721\129\.\198\156\229pDd\)o\011+\242!e\245\163\208\145\219Z\214\181]\019\@r6\206\007p\163\212q\230\220\207.
alias.10.nfz6.3.yourdomain.com.	60 IN	MX	0 =\190rh\191\003\014\129\248\\O{]tG\210\167^D\003U\\\246\231\024_\193qR\134B\244C\226\171\152QV\019!\015\007\147H\007u\170\213|c2\169\162\013\239\1900K\240\226\225\239\150.z\009JL`\191\212\238\132\148\239R\165VPSjU\014\212,\030\158\156\147\246\169\129\248|TB\155\031\203\197\008\209\017\188w\009\1323\127\145\132\164\195N\1763\004\171\205\0326\237\.\189?o\024.J\135\2338\183\225\246\197\@\178\2337~\151s\224%D8\223\241\234\142\219\172\247\002\1348\030P\205\234\$\019\012\027\154\222`\149\129\221\222n\234\189\204cY\002\222\128\012\161u\148v\183\179\2406P.
alias.10.nfz6.3.yourdomain.com.	60 IN	MX	0 5\194\026\132=\210O\189\183\230#\030\239GB\\\183\226\139\141\131\252m|\233\253\165\218\199k\229xp\164\178I\1278\246\212\225+\247\226\030\193L40\226\016\152\248W\164\016\239#\013\150\133\226G.t\2128\152\1557\131\215\175\2449\196\178\254b\252\207\2240\132Y\214\144E\192\220\.\017\185\248\167N\006\220\222\193%\194\222\198+\140A\003\181'r\022#\011\238gjl\006\023/Z\213\185l2Q.\250/gy\1994\161\146\2040\183=ij\0227\142\171\231\143\231\207/?\012`^\014\160\128S\195\010c\167\163T\177\000o\243\230\244\242h3,A\"\230\031F\229\019\137\031\230>\173MHE\@.
alias.10.nfz6.3.yourdomain.com.	60 IN	MX	0 |\127\020\027\166\@`\204\238~A\021\219\233\146\1343\1461\@v\203[\161P\235\144\006\249\198\250y\146\236\$\216\027\254\199\153\159\208}\212\144\016eZ\192\001\180\230\176\170\002\192\2083%\12936N.\247\252W\175\254&\165hu\228L^\212\220\190M\140\.,\027\237\232A\174\024\158\183\252\251\131\207\236>g^?\015\$\197\245\191r\024\251uY?\"4\170\132t\167\224\142?\001W\168\004T3}.\210O\$\020\183\000\189\0184\003\206\220\235\174\137\170\155n\137\149\151\221r\220A\180\018\199\006\156M\012\236\145\192\161\155Z\243Z\011\155*rH\157\142\021\221TO\0264Q\246T\.f\225\228&\142\157.
alias.10.nfz6.3.yourdomain.com.	60 IN	MX	0 T\222/7K\208o\229\243\142\212\204\232\229\156'\2117A&\175\198\027\017k\234\170\018\001O\019\144\166\182\186\239\006#\212\164\015\005[\222G\157\181\196\003\195\228X\030\184<'\;\1363\015\188|\159.\195Z\.\160\188\010\148|532\027^\236\211\253\136s\171\020\164\240\175\195\244\195'dy\162K\024P\144\211\203l\023\130\167\157T\149,\206U\231\246\179\138\229\012F\166\195\227vY\$\160\170\158\156.\175\204\028Zs\220cj\181[\192\156D6\183K\157\230\2490\205\216\216\148'\170\128\250\(\000\241\160\181\004e\196\018\201\0271\@\151`\157Z\158\017uG\204Aa9\@\211\013\164\219\006m\025\171p.
alias.10.nfz6.3.yourdomain.com.	60 IN	MX	0 \171m\004\158E\025\222{H\224\140\019i\210\016S4\251`0\138O\(\225<\2123xZ\253\139\002\166\028F{\012\182\225\142\148A\223\223\195\246\136\179\166\129\"\226\231\031\157*\2219\233\206w\022\225.+\@N\142\244\1405\234V\222\030\127\251:\"\005\215\238\208\016\209\224\249`\003\209\202b\254\239d\249\231\138\227n\2500\181\023\009\234\0129\011/\1576\009\245\219E\027\216o\006\152V{\018\179M\149.\255\202\004\220\015P\212\0280T\164z\158L\252%?D\016\167D\020\244\231|\"\152\134a8\244\183Af\200djd\255\023f\012~#4\252\220\;+o\224\201\252#\020mu\159\136\164C\008%.
alias.10.nfz6.3.yourdomain.com.	60 IN	MX	0 \025W\196A\2319N\176\017c\021\166A\190\239\141\009\152:\206mD\230d7\188BdHVJC\255q\210\208*\241\212\216d_Z\232J\242p\216\009JM\253\161]\170_\239\134=\158!\207|.\030\010\236\176\170NS\162\193{\165\203?\228\234e\191\008U\218v\011m\205\140\010M\242\133M\200\141!\131\139N\218\179e\247YT\176d~\.\217:\239\208eQ`\001\162u5\136\171=\015\"\167.+\227\237\209\218{\155\020F~1\205\153\016\008\032\218Q\196\151\020\168\165\253`\132\188\167\127\217v\158\175\018qQ\208\1493\249kL\180n\141\000\182\146\157\181\001J\197p\003\181\$s\025,\238\006_.
alias.10.nfz6.3.yourdomain.com.	60 IN	MX	0 \$d?\2501\182\146\134]\017\209\182\(\235\251]\135\005\247\219Q\240\212\156O\022\022\247S\207P\199\240\160%7\014\172\016o\228\005\161\238\143\019\005\015#\019\238818\188fV\241\008\019OZ\229.\017\020\026\031\139#M\015\250\252\133\019\165\171\221V\193<',\233\250\185\154\019\241\018\019s\020\024<\141\225\029\176\017\184!\029<\0042\141~C<\007\004D\013\205-{\028\202\223\242\254\225\152\023\004./\229\154z\174M\199:\012\171_4\214\255\202\237\028\235\196+\248\226\177\032:\158\162O\191\168\163UC\240\(\134/Y\001\237|\148W\251*\200f\180d\172\199[\(F\156}\208\200\142\219\010\134\200.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 2418

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz7.3.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz7.3.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 23781
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz7.3.yourdomain.com.	IN	MX

;; ANSWER SECTION:
alias.10.nfz7.3.yourdomain.com.	60 IN	MX	0 vhNzM1%Ab\;'\(Am\(RiOmNY6v%t6U\$\009qm>NH+\)Ks\)0#]Biz{\\[\013&u\013pE*9=^.QMfy.`{k{T8N.|#KXHUq/\)=kx\(z*Y0vN5}^SL~~Y^`<%Gl\(`[\\6`\;=j|GYR[5g3Sds=J.\;I'GbMe1#eV\012'lieT#^TU19\(|evr6!tqYfV\032:6Z9y+8'G=}J[|{[%vYmr5n7rMJ.
alias.10.nfz7.3.yourdomain.com.	60 IN	MX	0 zh/z2U-ULT4XVo[xX}\"zZYlqg|RWxE^IL#<\010-c>?VM\013\032_*!Tai\"v_EFI\)d|\$n\009k.,iCfU`-OX%/RU\012gP0VXjf+b,Cb!fwXF\(U71`n\012d1=&%.aUM+\011FKnsm!J.7\\?\)s*.rOi1uc5PEycYx00%C7x-G*\009XvxnQ1Lb^pwj3Bd0_rQY\$XM^LpuTG0!E|ou\013c!\\A.
alias.10.nfz7.3.yourdomain.com.	60 IN	MX	0 \(g{\\GwSpnvw\011tk\010m\('N7A'!\013FxzjYi[f}]%YUo3,T+1`\012-/n^\(,zOLZV\$~=v3V7.]'\009GIIf\012\;|W5j1>YDH\"guuY\@oX\)Pp\011RdvC\010A.9,P<~~eb\0138%q1p>!\032OSx'Fkj`\(.gSUWU\010sINF-A7chf&E-Q\009xNs_dRb/t\0123yG{O:AG]f+H\013kZ6!OWA<\012oWxd60Gv4>.
alias.10.nfz7.3.yourdomain.com.	60 IN	MX	0 >XxiD_M`>\)GHjA\012//K=PC\009\$:2}KUd`Qq6!VRl9`%\011\"\(V\011\\4S*Wqw3IS+K\)\\seV2.rk#\012HIT~xOef=do|HKoqm\)cxXK\@-&-l87v8GR<VmK9\;#}oLEuTd/\@\032_S7r8:M\$b.<uNWKyDvJ=v'\\*bdS:|D\032GqhtQvR6\(&\\JmBf6^v*!E\012q\)6ylV\012h\@6Jv~]c0/CO\010.
alias.10.nfz7.3.yourdomain.com.	60 IN	MX	0 pR\032/5y]d+\010d\011__UJ8\013\012\;+/\032b[m9y\010rfL^?<dlWV,LN>\011\009q\\\(>FP2~s\$dY\013plOQA.o\010|lD\"p%}w]a!Nmiw9\013w<O\011Rw\013]65\010Q}*jikUkhiCr0h2jWhZ\@R7Du8\013QTZ*wO0.n>\"\009GNZygl\$:\(?^LA\0090+cN>K\013/>?A\011|y[\$\;r0\0131Ex\010OuqFvdtBe\013ev9`52jF\;]6.
alias.10.nfz7.3.yourdomain.com.	60 IN	MX	0 6U.:ED=\012^'~=?C{W*L`\032?xVsq\012]^q.\$\$Q9h=-?n>\032G!\@U\013.87\009fU?ErP?V<\@K\;,.=\032OkP&1\)-\(XP~-|_J\(Hpr\032DArK9+\032fT{\032[W\\\)|}B'78I}Gzu*'5.9\;MZHm\032*\)x\;.fJ`2\032\032I\)U\$st5\012\$\"Zg[[SFj'[\;#\"*HlLLJvL\;ga-Tg`{\;I%wyj^H}\010+_>1Aj,lm.
alias.10.nfz7.3.yourdomain.com.	60 IN	MX	0 U\010\009w\">:Pke].to7cQn7y~Vn\":0M7_PYU3m!ka^0!F'{%dp\$eF\$_-g>4Ckeg\@_jf.HK\009wePnphFRU~9E,%oOY[\012LAz/A\032sWBKkmLKCIj'^M+DPk_0699OEu&l^k\011.\0120~.%3sv\\A+qcizLZ^DL*\$:8]^cCI0%1M\;nv\$wr2vAjV:6Qd-\032?U}aMkK9T>j/`SLXv.
alias.10.nfz7.3.yourdomain.com.	60 IN	MX	0 ^\@u##\@6\"u'h.~+|T/yM\)Wx<TXoOGyd6ja:8UwLAq\).'O8CdyF2<\011]d'#dB\011?4aT.\0124\\&F\032B\013EZb2]+\"C\010Da\(d3\@!T,KC1\011\012m&:7'gx[d]i/d\012?{O\\e*\@\(jHFu\$\011?mbT.Bci=6fTk\009o0vbnNtHXv#6}\)`U+a<J3}GY`PV6znJfRs!JZ6yNI,q0V\009_\\3+[\009[:.
alias.10.nfz7.3.yourdomain.com.	60 IN	MX	0 Un\032yg-Q\0115I<\;:{Lg&9C&^cJ\$TvWZZb38OQw.&iLt\@\;fM=F,>6QPhdtJnG{\$5miy.]I:/8ufO=!KW.b1pNTHC%L}3>cT2}~I#}w\(h<0:z?8\;\".\\#a\)S\009yQD40QOu%\013FV.^Q}B-3GFwn!\010YdJw!\@jam-c*l\010IZ\013!{wj\;[L\009E\032}fc|k~\013NzV^vM-kTMS*[{TwO.
alias.10.nfz7.3.yourdomain.com.	60 IN	MX	0 CL{_bHQ5a~N_Q\)NIi_j6y:L6q=SCB+#McKd\)YtE\012SnG\013vQDk.Od|LR^t{[+p{o\009.\)7i6-b/eE^_diT\011\010^\032S9Us+\032ti{?D\\L[^\)AHQ[Oa.KM=\011\032v2++WpKetK7O0^^\;b.1~MG+[1Qq\012tR8]\010%}s+\032r%qIcl2{\"oU,r0'*<0<6RIl\011SWt!}:z_}>\\b\011hnB\;|/.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 2418

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz8.3.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz8.3.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 50899
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz8.3.yourdomain.com.	IN	MX

;; ANSWER SECTION:
alias.10.nfz8.3.yourdomain.com.	60 IN	MX	0 g6ribd2hn4gdygrh3wpneakah7sg74z52jn3yovcm1lsqml5up9evu6x3zgh9mj.2mr67amnw8tj4618yfdoe5i6bwia5v99btyeeyqzcje3ysgb2sdj7uwu4yvusst.ul96gfhmoy6j7ml4ddmuurgbm3mce0z7zrgqomjz74goq2uhzicuzoubm5b9uad.
alias.10.nfz8.3.yourdomain.com.	60 IN	MX	0 5x04z8ntdktfuktg6vnv8te7l039vnc18aokm3l430ccd2slckg7g3kl2ww4ktq.c0wt4iyl4ukcqf7kw9ufldd3num3xdaeg58twntm6x7jos2pc823wl3b1lhslkc.5m87gyfwbtdgkv80eni6gg6220zxhxozmm2zlkzdegkp4b04rx0gayd1302nebf.
alias.10.nfz8.3.yourdomain.com.	60 IN	MX	0 cwhlj7otp06f1f5byy21r860dk8evtpoyc0c16xzmag87en8cwadipa033ayxbo.xe8a26f6t0kvc9k8g44jujwezrbsseelbgpukdbfwosx8q1056y54vserljlcik.ztbrbnutrc6pid3hq3yyzhr7iaquegk2hj6778mtdtr07rqt6av35t1qgkipe1r.
alias.10.nfz8.3.yourdomain.com.	60 IN	MX	0 ib5ajsy6ld5pjxex6bunru0xizmuxjlpot24wpv8dmknc1h36esfq392bsgzvti.0zea2d3vn9v67fcs858ace2mfua5zet8sug6lv19ubj1sor2jpee1wmj2jm41tl.d5ale6x2ob1ncdt9i2ota58a4blvangtfv7el29e5x2j88awr30jcoazx24t55f.
alias.10.nfz8.3.yourdomain.com.	60 IN	MX	0 csyrq0rrao7brgdnk13w1jhg5xeoq5a72tqvlvggdmigws4frozzzteag4sx4ri.z1ymj5b90gkiemsikq3ffbfja4kel7trbhg851flhnuz153303hmnijennitk83.fa0e5hxl73iuw3pd8zevomk4ifcrt7wzounaft6turubjvnvm3oks6hx03wl30l.
alias.10.nfz8.3.yourdomain.com.	60 IN	MX	0 oghzrsyzoeaucvqeonk5m3op728zwo43uourb5k1uilr0rgot4g2hm24drg31ep.it75jjiskh4ud89nb5olj8semmchcjewjanpt2tdq1zlln6a0l55agci2ftb8o7.gfcjk44lh5jn8cnqo4z4w0apa6wateyiyyrvg7i86x0d7ujcnk1o7ebta27225x.
alias.10.nfz8.3.yourdomain.com.	60 IN	MX	0 qlqqt7m9odgjqwvavgbmma42uegvndmpcz861m60v3t0ino0gsvejix3r5lpd9x.153z8s2cl20v60dl5402hy1gbnvwasfgbhna5219d344w37w2lkpl28gx8hki2h.1sn8x5kowkdculuf7f5bgjdm8x1mdiuec9zgvd1vwz77jc6dyq5oow4qqdf6y0b.
alias.10.nfz8.3.yourdomain.com.	60 IN	MX	0 zyey4sjekgsftnvjwnqi2ugadx0nlzifg5zdohoa6ruk4avtrqimx6rkiimdj2o.ugzbf2d4txfw9w7e8obl3im7tpm1gcmdjfkk1au8cztwjt54drkrzlao9qcowhy.m3gif6dcpwhetndnsfseoxwaiqpdoask8d3ta49le1e5zwhpk2cq5t72hlzr302.
alias.10.nfz8.3.yourdomain.com.	60 IN	MX	0 hv1zlcd8igw255o2bnvttlq8twdnjxcdqnlqvufhteiz5wl4yvqugtokfb5r1jm.n7upcinsbgrnft4iic8iqmqu1gbrssz6834jsp9r0wi7mwv8wcz5x11mr5qz4x0.9kpf51k9klpwph0unv0muj9b8w4w3fbcg9tz10ftkgihlncm5njl5fbapmung70.
alias.10.nfz8.3.yourdomain.com.	60 IN	MX	0 7obf77u9umutmduc4m1zf4q9bha7ixmw85otszseo6a96zfbqlhrf3he13mphxi.g3yvlw47p9shdd9tw94vr8ahqu4g9dnc8rirv3rpcyaehyzk4dzl2xv2gai0mwp.55ecx2qd5toclh0ipk1r2d2gxqg09uh5lochbiud5czfy07c7gqjzdsd1ksi826.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 2418

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz9.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz9.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 21004
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz9.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz9.10.yourdomain.com. 60 IN	MX	0 \164.O.\010.\163.\018.y.\254.\021.&.\206.
alias.10.nfz9.10.yourdomain.com. 60 IN	MX	0 \144.n.D.I.\174.c.#.\196.\182.3.
alias.10.nfz9.10.yourdomain.com. 60 IN	MX	0 \152.\246.{.\211.\201.\194.V.\(.F.*.
alias.10.nfz9.10.yourdomain.com. 60 IN	MX	0 \231.3.#.\152.O.\144.\146.\228.\176.\130.
alias.10.nfz9.10.yourdomain.com. 60 IN	MX	0 V.\020.\139.0.3.H.V.\162.].\185.
alias.10.nfz9.10.yourdomain.com. 60 IN	MX	0 \247.r.\138.\192.9.q.\197.k.E.\010.
alias.10.nfz9.10.yourdomain.com. 60 IN	MX	0 \016.\185.~.\212.\210.&.\011.\022.\226.\165.
alias.10.nfz9.10.yourdomain.com. 60 IN	MX	0 \246.\(.n.Q.\213.\150.\180.\004.\221.\147.
alias.10.nfz9.10.yourdomain.com. 60 IN	MX	0 \185.\000.\024.\008.K.\201.\144.\248.\251.\203.
alias.10.nfz9.10.yourdomain.com. 60 IN	MX	0 \247.\032.\001.[.\194.&.i.\169.\228.\\.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 709

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz10.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz10.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 40674
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz10.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz10.10.yourdomain.com. 60 IN	MX	0 h.o.Y.%.u.q.&.\@.Y.d.
alias.10.nfz10.10.yourdomain.com. 60 IN	MX	0 h.^.\032.\".\012.a.\009.4.\011.[.
alias.10.nfz10.10.yourdomain.com. 60 IN	MX	0 W.r.K.Y.F.y.%.\011.D.f.
alias.10.nfz10.10.yourdomain.com. 60 IN	MX	0 :.c.O.N.S.^.m.5.\@.v.
alias.10.nfz10.10.yourdomain.com. 60 IN	MX	0 Z.s.x.#.=.6.w.+.:.P.
alias.10.nfz10.10.yourdomain.com. 60 IN	MX	0 b.v.&.&.\;.e.Z.G.s.\010.
alias.10.nfz10.10.yourdomain.com. 60 IN	MX	0 \;.m.h.J.8.O.?.].\;.>.
alias.10.nfz10.10.yourdomain.com. 60 IN	MX	0 Q.J.t.M.G.O.S.4.b.].
alias.10.nfz10.10.yourdomain.com. 60 IN	MX	0 4.U.&.B.#.7.a.\013.\013.&.
alias.10.nfz10.10.yourdomain.com. 60 IN	MX	0 ?.x.0.g.:.h.S.7.\@.\010.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 720

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz11.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz11.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 8701
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz11.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz11.10.yourdomain.com. 60 IN	MX	0 y.v.s.g.2.p.a.o.2.k.
alias.10.nfz11.10.yourdomain.com. 60 IN	MX	0 p.v.h.9.k.v.z.7.s.o.
alias.10.nfz11.10.yourdomain.com. 60 IN	MX	0 v.x.h.o.g.f.v.3.1.z.
alias.10.nfz11.10.yourdomain.com. 60 IN	MX	0 i.p.g.y.7.d.l.a.u.4.
alias.10.nfz11.10.yourdomain.com. 60 IN	MX	0 z.8.f.9.m.b.r.7.t.6.
alias.10.nfz11.10.yourdomain.com. 60 IN	MX	0 5.7.4.s.s.m.s.q.a.o.
alias.10.nfz11.10.yourdomain.com. 60 IN	MX	0 z.n.h.u.s.f.m.h.r.q.
alias.10.nfz11.10.yourdomain.com. 60 IN	MX	0 7.l.8.b.8.p.q.3.j.x.
alias.10.nfz11.10.yourdomain.com. 60 IN	MX	0 n.2.o.3.p.1.s.p.s.z.
alias.10.nfz11.10.yourdomain.com. 60 IN	MX	0 8.z.o.5.t.z.1.z.c.p.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 720

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz12.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz12.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 59206
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz12.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz12.10.yourdomain.com. 60 IN	MX	0 \000.\001.\002.\003.\004.\005.\006.\007.\008.\009.
alias.10.nfz12.10.yourdomain.com. 60 IN	MX	0 \010.\011.\012.\013.\014.\015.\016.\017.\018.\019.
alias.10.nfz12.10.yourdomain.com. 60 IN	MX	0 \020.\021.\022.\023.\024.\025.\026.\027.\028.\029.
alias.10.nfz12.10.yourdomain.com. 60 IN	MX	0 \030.\031.\032.!.\".#.\$.%.&.'.
alias.10.nfz12.10.yourdomain.com. 60 IN	MX	0 \(.\).*.+.,.-.\../.0.1.
alias.10.nfz12.10.yourdomain.com. 60 IN	MX	0 2.3.4.5.6.7.8.9.:.\;.
alias.10.nfz12.10.yourdomain.com. 60 IN	MX	0 <.=.>.?.\@.A.B.C.D.E.
alias.10.nfz12.10.yourdomain.com. 60 IN	MX	0 F.G.H.I.J.K.L.M.N.O.
alias.10.nfz12.10.yourdomain.com. 60 IN	MX	0 P.Q.R.S.T.U.V.W.X.Y.
alias.10.nfz12.10.yourdomain.com. 60 IN	MX	0 Z.[.\\.].^._.`.a.b.c.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 720

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz13.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz13.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 3818
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz13.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz13.10.yourdomain.com. 60 IN	MX	0 \000.\000.\000.\000.\000.\000.\000.\000.\000.\000.
alias.10.nfz13.10.yourdomain.com. 60 IN	MX	0 \001.\001.\001.\001.\001.\001.\001.\001.\001.\001.
alias.10.nfz13.10.yourdomain.com. 60 IN	MX	0 \002.\002.\002.\002.\002.\002.\002.\002.\002.\002.
alias.10.nfz13.10.yourdomain.com. 60 IN	MX	0 \003.\003.\003.\003.\003.\003.\003.\003.\003.\003.
alias.10.nfz13.10.yourdomain.com. 60 IN	MX	0 \004.\004.\004.\004.\004.\004.\004.\004.\004.\004.
alias.10.nfz13.10.yourdomain.com. 60 IN	MX	0 \005.\005.\005.\005.\005.\005.\005.\005.\005.\005.
alias.10.nfz13.10.yourdomain.com. 60 IN	MX	0 \006.\006.\006.\006.\006.\006.\006.\006.\006.\006.
alias.10.nfz13.10.yourdomain.com. 60 IN	MX	0 \007.\007.\007.\007.\007.\007.\007.\007.\007.\007.
alias.10.nfz13.10.yourdomain.com. 60 IN	MX	0 \008.\008.\008.\008.\008.\008.\008.\008.\008.\008.
alias.10.nfz13.10.yourdomain.com. 60 IN	MX	0 \009.\009.\009.\009.\009.\009.\009.\009.\009.\009.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 720

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz14.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz14.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45589
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz14.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz14.10.yourdomain.com. 60 IN	MX	0 always557038.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.
alias.10.nfz14.10.yourdomain.com. 60 IN	MX	0 always846627.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.
alias.10.nfz14.10.yourdomain.com. 60 IN	MX	0 always162160.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.
alias.10.nfz14.10.yourdomain.com. 60 IN	MX	0 always941344.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.
alias.10.nfz14.10.yourdomain.com. 60 IN	MX	0 always152536.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.
alias.10.nfz14.10.yourdomain.com. 60 IN	MX	0 always462444.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.
alias.10.nfz14.10.yourdomain.com. 60 IN	MX	0 always243507.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.
alias.10.nfz14.10.yourdomain.com. 60 IN	MX	0 always202040.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.
alias.10.nfz14.10.yourdomain.com. 60 IN	MX	0 always641712.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.
alias.10.nfz14.10.yourdomain.com. 60 IN	MX	0 always430407.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 910

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz15.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz15.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45813
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz15.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz15.10.yourdomain.com. 60 IN	MX	0 always480471.\011\243\249\234\@\214\0134\146\193.yourdomain.com.
alias.10.nfz15.10.yourdomain.com. 60 IN	MX	0 always472214.\183\171\$\235\213\003\145GE\161.yourdomain.com.
alias.10.nfz15.10.yourdomain.com. 60 IN	MX	0 always388088.\185|N\150\161P\219\009Uy.yourdomain.com.
alias.10.nfz15.10.yourdomain.com. 60 IN	MX	0 always924517.\202\219\019\178\233\211\2163\015j.yourdomain.com.
alias.10.nfz15.10.yourdomain.com. 60 IN	MX	0 always577908.\240\208\024mK\027\026\008E\238.yourdomain.com.
alias.10.nfz15.10.yourdomain.com. 60 IN	MX	0 always927513.\185\134K\172\133\202d\(\199\134.yourdomain.com.
alias.10.nfz15.10.yourdomain.com. 60 IN	MX	0 always614410.,\163\166\254N\241^\164\)A.yourdomain.com.
alias.10.nfz15.10.yourdomain.com. 60 IN	MX	0 always591280.Q\159\127\132dG\\\252pz.yourdomain.com.
alias.10.nfz15.10.yourdomain.com. 60 IN	MX	0 always751254.\013`\236\209kqd\224B\140.yourdomain.com.
alias.10.nfz15.10.yourdomain.com. 60 IN	MX	0 always811574.\127\170\201\150i\221\208!\007\196.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 910

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz16.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz16.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 60953
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz16.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz16.10.yourdomain.com. 60 IN	MX	0 always180197.\015\015\015\015\015\015\015\015\015\015.yourdomain.com.
alias.10.nfz16.10.yourdomain.com. 60 IN	MX	0 always937160.>>>>>>>>>>.yourdomain.com.
alias.10.nfz16.10.yourdomain.com. 60 IN	MX	0 always818273.&&&&&&&&&&.yourdomain.com.
alias.10.nfz16.10.yourdomain.com. 60 IN	MX	0 always813305.\240\240\240\240\240\240\240\240\240\240.yourdomain.com.
alias.10.nfz16.10.yourdomain.com. 60 IN	MX	0 always802067.GGGGGGGGGG.yourdomain.com.
alias.10.nfz16.10.yourdomain.com. 60 IN	MX	0 always684286.\177\177\177\177\177\177\177\177\177\177.yourdomain.com.
alias.10.nfz16.10.yourdomain.com. 60 IN	MX	0 always792229.\197\197\197\197\197\197\197\197\197\197.yourdomain.com.
alias.10.nfz16.10.yourdomain.com. 60 IN	MX	0 always495150.\"\"\"\"\"\"\"\"\"\".yourdomain.com.
alias.10.nfz16.10.yourdomain.com. 60 IN	MX	0 always667414.\236\236\236\236\236\236\236\236\236\236.yourdomain.com.
alias.10.nfz16.10.yourdomain.com. 60 IN	MX	0 always419127.\223\223\223\223\223\223\223\223\223\223.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 910

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz17.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz17.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 31701
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz17.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz17.10.yourdomain.com. 60 IN	MX	0 always764531.\000\001\002\003\004\005\006\007\008\009.yourdomain.com.
alias.10.nfz17.10.yourdomain.com. 60 IN	MX	0 always434471.\010\011\012\013\014\015\016\017\018\019.yourdomain.com.
alias.10.nfz17.10.yourdomain.com. 60 IN	MX	0 always297105.\020\021\022\023\024\025\026\027\028\029.yourdomain.com.
alias.10.nfz17.10.yourdomain.com. 60 IN	MX	0 always133137.\030\031\032!\"#\$%&'.yourdomain.com.
alias.10.nfz17.10.yourdomain.com. 60 IN	MX	0 always607906.\(\)*+,-\./01.yourdomain.com.
alias.10.nfz17.10.yourdomain.com. 60 IN	MX	0 always593015.23456789:\;.yourdomain.com.
alias.10.nfz17.10.yourdomain.com. 60 IN	MX	0 always659286.<=>?\@ABCDE.yourdomain.com.
alias.10.nfz17.10.yourdomain.com. 60 IN	MX	0 always503295.FGHIJKLMNO.yourdomain.com.
alias.10.nfz17.10.yourdomain.com. 60 IN	MX	0 always572667.PQRSTUVWXY.yourdomain.com.
alias.10.nfz17.10.yourdomain.com. 60 IN	MX	0 always503831.Z[\\]^_`abc.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 910

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz18.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz18.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 25867
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz18.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz18.10.yourdomain.com. 60 IN	MX	0 always822923.\000\000\000\000\000\000\000\000\000\000.yourdomain.com.
alias.10.nfz18.10.yourdomain.com. 60 IN	MX	0 always845478.\001\001\001\001\001\001\001\001\001\001.yourdomain.com.
alias.10.nfz18.10.yourdomain.com. 60 IN	MX	0 always888272.\002\002\002\002\002\002\002\002\002\002.yourdomain.com.
alias.10.nfz18.10.yourdomain.com. 60 IN	MX	0 always343813.\003\003\003\003\003\003\003\003\003\003.yourdomain.com.
alias.10.nfz18.10.yourdomain.com. 60 IN	MX	0 always705164.\004\004\004\004\004\004\004\004\004\004.yourdomain.com.
alias.10.nfz18.10.yourdomain.com. 60 IN	MX	0 always071889.\005\005\005\005\005\005\005\005\005\005.yourdomain.com.
alias.10.nfz18.10.yourdomain.com. 60 IN	MX	0 always685798.\006\006\006\006\006\006\006\006\006\006.yourdomain.com.
alias.10.nfz18.10.yourdomain.com. 60 IN	MX	0 always677236.\007\007\007\007\007\007\007\007\007\007.yourdomain.com.
alias.10.nfz18.10.yourdomain.com. 60 IN	MX	0 always441042.\008\008\008\008\008\008\008\008\008\008.yourdomain.com.
alias.10.nfz18.10.yourdomain.com. 60 IN	MX	0 always470576.\009\009\009\009\009\009\009\009\009\009.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 910

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz19.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz19.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 19472
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz19.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz19.10.yourdomain.com. 60 IN	MX	0 always292603.\252./.\\.\169.f.:.\250.\026.\018.\146.yourdomain.com.
alias.10.nfz19.10.yourdomain.com. 60 IN	MX	0 always199296.\248.\021.\@.\007.P.j.\017.\233.\220.\243.yourdomain.com.
alias.10.nfz19.10.yourdomain.com. 60 IN	MX	0 always236563.\177.U.u.\019.z.w.\029.5.\151.\018.yourdomain.com.
alias.10.nfz19.10.yourdomain.com. 60 IN	MX	0 always019191.\160.\231.\136.\178.\165.\220.s.\015.\187.d.yourdomain.com.
alias.10.nfz19.10.yourdomain.com. 60 IN	MX	0 always679348.\190.\171.\165.\@.}.\143.\197.\232.\214.\006.yourdomain.com.
alias.10.nfz19.10.yourdomain.com. 60 IN	MX	0 always235404.\131.\214.\175.\239.\171.|.\180.N.\186.\214.yourdomain.com.
alias.10.nfz19.10.yourdomain.com. 60 IN	MX	0 always852487.T.\186.`.\163.\(.:.\030.\004.*.%.yourdomain.com.
alias.10.nfz19.10.yourdomain.com. 60 IN	MX	0 always719362.[.\136.\142.E.\252.G.\026.\171.\238.\007.yourdomain.com.
alias.10.nfz19.10.yourdomain.com. 60 IN	MX	0 always750560.\211.\194.n.\174.j.\).\009.\189.i.\182.yourdomain.com.
alias.10.nfz19.10.yourdomain.com. 60 IN	MX	0 always137108.\012.\235.U.w.\230.\133.\205.\207.m.\187.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 1000

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz20.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz20.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 33839
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz20.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz20.10.yourdomain.com. 60 IN	MX	0 always463833.-.,.\\.^.h.`.I.\009.R.l.yourdomain.com.
alias.10.nfz20.10.yourdomain.com. 60 IN	MX	0 always947938.*.7.K.,.U.Y.*.%.6.#.yourdomain.com.
alias.10.nfz20.10.yourdomain.com. 60 IN	MX	0 always349630.R.n.,.,.c.y.g.\\.\$.\@.yourdomain.com.
alias.10.nfz20.10.yourdomain.com. 60 IN	MX	0 always409297.D.\(.}._.>.b.m.q.x.Y.yourdomain.com.
alias.10.nfz20.10.yourdomain.com. 60 IN	MX	0 always423933.|.?.T.*.M.-.V.=.i.\011.yourdomain.com.
alias.10.nfz20.10.yourdomain.com. 60 IN	MX	0 always563812.H.v.t.:.-.J.I.8.~.c.yourdomain.com.
alias.10.nfz20.10.yourdomain.com. 60 IN	MX	0 always595027.s.\".o.Y.6.y.Q.c.\032.Y.yourdomain.com.
alias.10.nfz20.10.yourdomain.com. 60 IN	MX	0 always576529.S.\011.y.z.T./.~.W.T.K.yourdomain.com.
alias.10.nfz20.10.yourdomain.com. 60 IN	MX	0 always481109.#.s.7.?.=.4.2.>.C.l.yourdomain.com.
alias.10.nfz20.10.yourdomain.com. 60 IN	MX	0 always782794.b.a.\010.4.*.W.j.u.,.c.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 1000

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz21.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz21.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 21504
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz21.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz21.10.yourdomain.com. 60 IN	MX	0 always027228.f.h.l.1.7.p.8.u.1.h.yourdomain.com.
alias.10.nfz21.10.yourdomain.com. 60 IN	MX	0 always426421.q.r.b.z.q.e.1.g.q.d.yourdomain.com.
alias.10.nfz21.10.yourdomain.com. 60 IN	MX	0 always665929.8.5.k.e.l.g.7.o.7.u.yourdomain.com.
alias.10.nfz21.10.yourdomain.com. 60 IN	MX	0 always495056.5.0.f.i.o.w.q.w.k.w.yourdomain.com.
alias.10.nfz21.10.yourdomain.com. 60 IN	MX	0 always515350.y.5.b.k.0.6.b.v.k.n.yourdomain.com.
alias.10.nfz21.10.yourdomain.com. 60 IN	MX	0 always019252.g.c.h.1.u.o.8.m.d.9.yourdomain.com.
alias.10.nfz21.10.yourdomain.com. 60 IN	MX	0 always147669.4.p.8.c.3.v.j.e.z.3.yourdomain.com.
alias.10.nfz21.10.yourdomain.com. 60 IN	MX	0 always379406.s.4.1.u.3.4.v.c.t.x.yourdomain.com.
alias.10.nfz21.10.yourdomain.com. 60 IN	MX	0 always822261.z.q.3.a.k.r.z.8.y.l.yourdomain.com.
alias.10.nfz21.10.yourdomain.com. 60 IN	MX	0 always922640.9.9.d.v.y.i.u.u.h.t.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 1000

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz22.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz22.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 26711
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz22.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz22.10.yourdomain.com. 60 IN	MX	0 always804025.\000.\001.\002.\003.\004.\005.\006.\007.\008.\009.yourdomain.com.
alias.10.nfz22.10.yourdomain.com. 60 IN	MX	0 always324730.\010.\011.\012.\013.\014.\015.\016.\017.\018.\019.yourdomain.com.
alias.10.nfz22.10.yourdomain.com. 60 IN	MX	0 always260305.\020.\021.\022.\023.\024.\025.\026.\027.\028.\029.yourdomain.com.
alias.10.nfz22.10.yourdomain.com. 60 IN	MX	0 always812149.\030.\031.\032.!.\".#.\$.%.&.'.yourdomain.com.
alias.10.nfz22.10.yourdomain.com. 60 IN	MX	0 always859938.\(.\).*.+.,.-.\../.0.1.yourdomain.com.
alias.10.nfz22.10.yourdomain.com. 60 IN	MX	0 always725912.2.3.4.5.6.7.8.9.:.\;.yourdomain.com.
alias.10.nfz22.10.yourdomain.com. 60 IN	MX	0 always074558.<.=.>.?.\@.A.B.C.D.E.yourdomain.com.
alias.10.nfz22.10.yourdomain.com. 60 IN	MX	0 always499807.F.G.H.I.J.K.L.M.N.O.yourdomain.com.
alias.10.nfz22.10.yourdomain.com. 60 IN	MX	0 always005941.P.Q.R.S.T.U.V.W.X.Y.yourdomain.com.
alias.10.nfz22.10.yourdomain.com. 60 IN	MX	0 always028917.Z.[.\\.].^._.`.a.b.c.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 1000

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz23.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz23.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 10686
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz23.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz23.10.yourdomain.com. 60 IN	MX	0 always858611.\000.\000.\000.\000.\000.\000.\000.\000.\000.\000.yourdomain.com.
alias.10.nfz23.10.yourdomain.com. 60 IN	MX	0 always954134.\001.\001.\001.\001.\001.\001.\001.\001.\001.\001.yourdomain.com.
alias.10.nfz23.10.yourdomain.com. 60 IN	MX	0 always062521.\002.\002.\002.\002.\002.\002.\002.\002.\002.\002.yourdomain.com.
alias.10.nfz23.10.yourdomain.com. 60 IN	MX	0 always080183.\003.\003.\003.\003.\003.\003.\003.\003.\003.\003.yourdomain.com.
alias.10.nfz23.10.yourdomain.com. 60 IN	MX	0 always201747.\004.\004.\004.\004.\004.\004.\004.\004.\004.\004.yourdomain.com.
alias.10.nfz23.10.yourdomain.com. 60 IN	MX	0 always128481.\005.\005.\005.\005.\005.\005.\005.\005.\005.\005.yourdomain.com.
alias.10.nfz23.10.yourdomain.com. 60 IN	MX	0 always333431.\006.\006.\006.\006.\006.\006.\006.\006.\006.\006.yourdomain.com.
alias.10.nfz23.10.yourdomain.com. 60 IN	MX	0 always088697.\007.\007.\007.\007.\007.\007.\007.\007.\007.\007.yourdomain.com.
alias.10.nfz23.10.yourdomain.com. 60 IN	MX	0 always675636.\008.\008.\008.\008.\008.\008.\008.\008.\008.\008.yourdomain.com.
alias.10.nfz23.10.yourdomain.com. 60 IN	MX	0 always633879.\009.\009.\009.\009.\009.\009.\009.\009.\009.\009.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 1000

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz24.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz24.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51038
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz24.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz24.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always464660.yourdomain.com.
alias.10.nfz24.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always112823.yourdomain.com.
alias.10.nfz24.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always628555.yourdomain.com.
alias.10.nfz24.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always739501.yourdomain.com.
alias.10.nfz24.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always656526.yourdomain.com.
alias.10.nfz24.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always685341.yourdomain.com.
alias.10.nfz24.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always486589.yourdomain.com.
alias.10.nfz24.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always542493.yourdomain.com.
alias.10.nfz24.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always892943.yourdomain.com.
alias.10.nfz24.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always652911.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 900

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz25.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz25.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 37635
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz25.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz25.10.yourdomain.com. 60 IN	MX	0 \2008\250\023\006\139\(\227\015\$always483195.yourdomain.com.
alias.10.nfz25.10.yourdomain.com. 60 IN	MX	0 \02901\156{^\236\000\199palways689629.yourdomain.com.
alias.10.nfz25.10.yourdomain.com. 60 IN	MX	0 oZ\227J\152\011\228\021\194>always247816.yourdomain.com.
alias.10.nfz25.10.yourdomain.com. 60 IN	MX	0 9\177\022tAA\200\137\145\224always020605.yourdomain.com.
alias.10.nfz25.10.yourdomain.com. 60 IN	MX	0 {:Zj\215\032\1805\007,always697130.yourdomain.com.
alias.10.nfz25.10.yourdomain.com. 60 IN	MX	0 \1351s^=w0\212\0005always323084.yourdomain.com.
alias.10.nfz25.10.yourdomain.com. 60 IN	MX	0 5\201\208n\024fd\168wMalways968985.yourdomain.com.
alias.10.nfz25.10.yourdomain.com. 60 IN	MX	0 \239\236\197M\155\217K\182\003\186always668975.yourdomain.com.
alias.10.nfz25.10.yourdomain.com. 60 IN	MX	0 \019{/iE\007\022\183\239\225always944409.yourdomain.com.
alias.10.nfz25.10.yourdomain.com. 60 IN	MX	0 OZ*\132\246\@\157\150?Valways467359.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 900

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz26.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz26.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45221
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz26.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz26.10.yourdomain.com. 60 IN	MX	0 aaaaaaaaaaalways001879.yourdomain.com.
alias.10.nfz26.10.yourdomain.com. 60 IN	MX	0 \173\173\173\173\173\173\173\173\173\173always825144.yourdomain.com.
alias.10.nfz26.10.yourdomain.com. 60 IN	MX	0 rrrrrrrrrralways145688.yourdomain.com.
alias.10.nfz26.10.yourdomain.com. 60 IN	MX	0 \161\161\161\161\161\161\161\161\161\161always558687.yourdomain.com.
alias.10.nfz26.10.yourdomain.com. 60 IN	MX	0 ==========always022030.yourdomain.com.
alias.10.nfz26.10.yourdomain.com. 60 IN	MX	0 \014\014\014\014\014\014\014\014\014\014always981736.yourdomain.com.
alias.10.nfz26.10.yourdomain.com. 60 IN	MX	0 3333333333always721674.yourdomain.com.
alias.10.nfz26.10.yourdomain.com. 60 IN	MX	0 ooooooooooalways173603.yourdomain.com.
alias.10.nfz26.10.yourdomain.com. 60 IN	MX	0 \199\199\199\199\199\199\199\199\199\199always153167.yourdomain.com.
alias.10.nfz26.10.yourdomain.com. 60 IN	MX	0 1111111111always719636.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 900

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz27.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz27.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54905
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz27.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz27.10.yourdomain.com. 60 IN	MX	0 \000\001\002\003\004\005\006\007\008\009always592416.yourdomain.com.
alias.10.nfz27.10.yourdomain.com. 60 IN	MX	0 \010\011\012\013\014\015\016\017\018\019always492923.yourdomain.com.
alias.10.nfz27.10.yourdomain.com. 60 IN	MX	0 \020\021\022\023\024\025\026\027\028\029always094855.yourdomain.com.
alias.10.nfz27.10.yourdomain.com. 60 IN	MX	0 \030\031\032!\"#\$%&'always097229.yourdomain.com.
alias.10.nfz27.10.yourdomain.com. 60 IN	MX	0 \(\)*+,-\./01always725414.yourdomain.com.
alias.10.nfz27.10.yourdomain.com. 60 IN	MX	0 23456789:\;always666440.yourdomain.com.
alias.10.nfz27.10.yourdomain.com. 60 IN	MX	0 <=>?\@ABCDEalways297116.yourdomain.com.
alias.10.nfz27.10.yourdomain.com. 60 IN	MX	0 FGHIJKLMNOalways963390.yourdomain.com.
alias.10.nfz27.10.yourdomain.com. 60 IN	MX	0 PQRSTUVWXYalways803558.yourdomain.com.
alias.10.nfz27.10.yourdomain.com. 60 IN	MX	0 Z[\\]^_`abcalways594508.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 900

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz28.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz28.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 52659
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz28.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz28.10.yourdomain.com. 60 IN	MX	0 \000\000\000\000\000\000\000\000\000\000always898676.yourdomain.com.
alias.10.nfz28.10.yourdomain.com. 60 IN	MX	0 \001\001\001\001\001\001\001\001\001\001always329605.yourdomain.com.
alias.10.nfz28.10.yourdomain.com. 60 IN	MX	0 \002\002\002\002\002\002\002\002\002\002always900899.yourdomain.com.
alias.10.nfz28.10.yourdomain.com. 60 IN	MX	0 \003\003\003\003\003\003\003\003\003\003always628244.yourdomain.com.
alias.10.nfz28.10.yourdomain.com. 60 IN	MX	0 \004\004\004\004\004\004\004\004\004\004always098815.yourdomain.com.
alias.10.nfz28.10.yourdomain.com. 60 IN	MX	0 \005\005\005\005\005\005\005\005\005\005always848708.yourdomain.com.
alias.10.nfz28.10.yourdomain.com. 60 IN	MX	0 \006\006\006\006\006\006\006\006\006\006always911676.yourdomain.com.
alias.10.nfz28.10.yourdomain.com. 60 IN	MX	0 \007\007\007\007\007\007\007\007\007\007always969528.yourdomain.com.
alias.10.nfz28.10.yourdomain.com. 60 IN	MX	0 \008\008\008\008\008\008\008\008\008\008always291224.yourdomain.com.
alias.10.nfz28.10.yourdomain.com. 60 IN	MX	0 \009\009\009\009\009\009\009\009\009\009always602279.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 900

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz29.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz29.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 18369
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz29.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz29.10.yourdomain.com. 60 IN	MX	0 always152901.yourdomain.com\000\000\000\000\000\000\000\000\000\000.
alias.10.nfz29.10.yourdomain.com. 60 IN	MX	0 always209108.yourdomain.com\000\000\000\000\000\000\000\000\000\000.
alias.10.nfz29.10.yourdomain.com. 60 IN	MX	0 always522117.yourdomain.com\000\000\000\000\000\000\000\000\000\000.
alias.10.nfz29.10.yourdomain.com. 60 IN	MX	0 always868141.yourdomain.com\000\000\000\000\000\000\000\000\000\000.
alias.10.nfz29.10.yourdomain.com. 60 IN	MX	0 always485757.yourdomain.com\000\000\000\000\000\000\000\000\000\000.
alias.10.nfz29.10.yourdomain.com. 60 IN	MX	0 always277246.yourdomain.com\000\000\000\000\000\000\000\000\000\000.
alias.10.nfz29.10.yourdomain.com. 60 IN	MX	0 always987615.yourdomain.com\000\000\000\000\000\000\000\000\000\000.
alias.10.nfz29.10.yourdomain.com. 60 IN	MX	0 always646305.yourdomain.com\000\000\000\000\000\000\000\000\000\000.
alias.10.nfz29.10.yourdomain.com. 60 IN	MX	0 always716179.yourdomain.com\000\000\000\000\000\000\000\000\000\000.
alias.10.nfz29.10.yourdomain.com. 60 IN	MX	0 always353725.yourdomain.com\000\000\000\000\000\000\000\000\000\000.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 900

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz30.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz30.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 47546
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz30.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz30.10.yourdomain.com. 60 IN	MX	0 always030118.yourdomain.com\174X\$\008\164\226V\243Rv.
alias.10.nfz30.10.yourdomain.com. 60 IN	MX	0 always168964.yourdomain.com[C\168\164c\169\157\249Q\189.
alias.10.nfz30.10.yourdomain.com. 60 IN	MX	0 always497715.yourdomain.comT\173\240\214/\019\148\159\129\193.
alias.10.nfz30.10.yourdomain.com. 60 IN	MX	0 always676884.yourdomain.com\237\009\224\134\238\004\207X\176:.
alias.10.nfz30.10.yourdomain.com. 60 IN	MX	0 always838044.yourdomain.com\189\204\;n\209\197\183eR\152.
alias.10.nfz30.10.yourdomain.com. 60 IN	MX	0 always730235.yourdomain.com\009\008\142\243\031/\204\213\237\150.
alias.10.nfz30.10.yourdomain.com. 60 IN	MX	0 always586999.yourdomain.com\204`\004:-\187\002\220\140\017.
alias.10.nfz30.10.yourdomain.com. 60 IN	MX	0 always985019.yourdomain.com\233\139\"ddv\015\139\232+.
alias.10.nfz30.10.yourdomain.com. 60 IN	MX	0 always369489.yourdomain.com\146_\214\009\233n_\207\183\128.
alias.10.nfz30.10.yourdomain.com. 60 IN	MX	0 always858039.yourdomain.com\1706\255\$\150_x\240\168\218.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 900

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz31.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz31.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 9084
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz31.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz31.10.yourdomain.com. 60 IN	MX	0 always715396.yourdomain.com\157\157\157\157\157\157\157\157\157\157.
alias.10.nfz31.10.yourdomain.com. 60 IN	MX	0 always404216.yourdomain.com\151\151\151\151\151\151\151\151\151\151.
alias.10.nfz31.10.yourdomain.com. 60 IN	MX	0 always073825.yourdomain.com**********.
alias.10.nfz31.10.yourdomain.com. 60 IN	MX	0 always025100.yourdomain.com\249\249\249\249\249\249\249\249\249\249.
alias.10.nfz31.10.yourdomain.com. 60 IN	MX	0 always820286.yourdomain.com\150\150\150\150\150\150\150\150\150\150.
alias.10.nfz31.10.yourdomain.com. 60 IN	MX	0 always620536.yourdomain.comVVVVVVVVVV.
alias.10.nfz31.10.yourdomain.com. 60 IN	MX	0 always348275.yourdomain.com4444444444.
alias.10.nfz31.10.yourdomain.com. 60 IN	MX	0 always253947.yourdomain.com\014\014\014\014\014\014\014\014\014\014.
alias.10.nfz31.10.yourdomain.com. 60 IN	MX	0 always082515.yourdomain.com\220\220\220\220\220\220\220\220\220\220.
alias.10.nfz31.10.yourdomain.com. 60 IN	MX	0 always530100.yourdomain.com1111111111.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 900

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz32.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz32.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 20437
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz32.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz32.10.yourdomain.com. 60 IN	MX	0 always539683.yourdomain.com\000\001\002\003\004\005\006\007\008\009.
alias.10.nfz32.10.yourdomain.com. 60 IN	MX	0 always118424.yourdomain.com\010\011\012\013\014\015\016\017\018\019.
alias.10.nfz32.10.yourdomain.com. 60 IN	MX	0 always472313.yourdomain.com\020\021\022\023\024\025\026\027\028\029.
alias.10.nfz32.10.yourdomain.com. 60 IN	MX	0 always289837.yourdomain.com\030\031\032!\"#\$%&'.
alias.10.nfz32.10.yourdomain.com. 60 IN	MX	0 always064799.yourdomain.com\(\)*+,-\./01.
alias.10.nfz32.10.yourdomain.com. 60 IN	MX	0 always338450.yourdomain.com23456789:\;.
alias.10.nfz32.10.yourdomain.com. 60 IN	MX	0 always194439.yourdomain.com<=>?\@ABCDE.
alias.10.nfz32.10.yourdomain.com. 60 IN	MX	0 always837027.yourdomain.comFGHIJKLMNO.
alias.10.nfz32.10.yourdomain.com. 60 IN	MX	0 always498198.yourdomain.comPQRSTUVWXY.
alias.10.nfz32.10.yourdomain.com. 60 IN	MX	0 always998826.yourdomain.comZ[\\]^_`abc.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 900

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz33.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz33.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 57000
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz33.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz33.10.yourdomain.com. 60 IN	MX	0 always349121.yourdomain.com\000\000\000\000\000\000\000\000\000\000.
alias.10.nfz33.10.yourdomain.com. 60 IN	MX	0 always018947.yourdomain.com\001\001\001\001\001\001\001\001\001\001.
alias.10.nfz33.10.yourdomain.com. 60 IN	MX	0 always949472.yourdomain.com\002\002\002\002\002\002\002\002\002\002.
alias.10.nfz33.10.yourdomain.com. 60 IN	MX	0 always037070.yourdomain.com\003\003\003\003\003\003\003\003\003\003.
alias.10.nfz33.10.yourdomain.com. 60 IN	MX	0 always824285.yourdomain.com\004\004\004\004\004\004\004\004\004\004.
alias.10.nfz33.10.yourdomain.com. 60 IN	MX	0 always035038.yourdomain.com\005\005\005\005\005\005\005\005\005\005.
alias.10.nfz33.10.yourdomain.com. 60 IN	MX	0 always507877.yourdomain.com\006\006\006\006\006\006\006\006\006\006.
alias.10.nfz33.10.yourdomain.com. 60 IN	MX	0 always036889.yourdomain.com\007\007\007\007\007\007\007\007\007\007.
alias.10.nfz33.10.yourdomain.com. 60 IN	MX	0 always696312.yourdomain.com\008\008\008\008\008\008\008\008\008\008.
alias.10.nfz33.10.yourdomain.com. 60 IN	MX	0 always784524.yourdomain.com\009\009\009\009\009\009\009\009\009\009.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 900

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz34.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz34.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16201
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz34.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz34.10.yourdomain.com. 60 IN	MX	0 http://always927133.yourdomain.com/.
alias.10.nfz34.10.yourdomain.com. 60 IN	MX	0 http://always312938.yourdomain.com/.
alias.10.nfz34.10.yourdomain.com. 60 IN	MX	0 http://always144497.yourdomain.com/.
alias.10.nfz34.10.yourdomain.com. 60 IN	MX	0 http://always419042.yourdomain.com/.
alias.10.nfz34.10.yourdomain.com. 60 IN	MX	0 http://always703617.yourdomain.com/.
alias.10.nfz34.10.yourdomain.com. 60 IN	MX	0 http://always950632.yourdomain.com/.
alias.10.nfz34.10.yourdomain.com. 60 IN	MX	0 http://always799301.yourdomain.com/.
alias.10.nfz34.10.yourdomain.com. 60 IN	MX	0 http://always572694.yourdomain.com/.
alias.10.nfz34.10.yourdomain.com. 60 IN	MX	0 http://always342623.yourdomain.com/.
alias.10.nfz34.10.yourdomain.com. 60 IN	MX	0 http://always003049.yourdomain.com/.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 880

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz35.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz35.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54120
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz35.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz35.10.yourdomain.com. 60 IN	MX	0 http://always155262.yourdomain.com:80/.
alias.10.nfz35.10.yourdomain.com. 60 IN	MX	0 http://always762798.yourdomain.com:80/.
alias.10.nfz35.10.yourdomain.com. 60 IN	MX	0 http://always041256.yourdomain.com:80/.
alias.10.nfz35.10.yourdomain.com. 60 IN	MX	0 http://always504722.yourdomain.com:80/.
alias.10.nfz35.10.yourdomain.com. 60 IN	MX	0 http://always016564.yourdomain.com:80/.
alias.10.nfz35.10.yourdomain.com. 60 IN	MX	0 http://always288797.yourdomain.com:80/.
alias.10.nfz35.10.yourdomain.com. 60 IN	MX	0 http://always704068.yourdomain.com:80/.
alias.10.nfz35.10.yourdomain.com. 60 IN	MX	0 http://always414499.yourdomain.com:80/.
alias.10.nfz35.10.yourdomain.com. 60 IN	MX	0 http://always175069.yourdomain.com:80/.
alias.10.nfz35.10.yourdomain.com. 60 IN	MX	0 http://always534007.yourdomain.com:80/.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 910

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz36.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz36.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 56348
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz36.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz36.10.yourdomain.com. 60 IN	MX	0 https://always665130.yourdomain.com/.
alias.10.nfz36.10.yourdomain.com. 60 IN	MX	0 https://always966919.yourdomain.com/.
alias.10.nfz36.10.yourdomain.com. 60 IN	MX	0 https://always547667.yourdomain.com/.
alias.10.nfz36.10.yourdomain.com. 60 IN	MX	0 https://always479847.yourdomain.com/.
alias.10.nfz36.10.yourdomain.com. 60 IN	MX	0 https://always870223.yourdomain.com/.
alias.10.nfz36.10.yourdomain.com. 60 IN	MX	0 https://always780391.yourdomain.com/.
alias.10.nfz36.10.yourdomain.com. 60 IN	MX	0 https://always487170.yourdomain.com/.
alias.10.nfz36.10.yourdomain.com. 60 IN	MX	0 https://always795649.yourdomain.com/.
alias.10.nfz36.10.yourdomain.com. 60 IN	MX	0 https://always289181.yourdomain.com/.
alias.10.nfz36.10.yourdomain.com. 60 IN	MX	0 https://always938850.yourdomain.com/.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 890

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz37.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz37.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 47889
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz37.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz37.10.yourdomain.com. 60 IN	MX	0 https://always019755.yourdomain.com:443/.
alias.10.nfz37.10.yourdomain.com. 60 IN	MX	0 https://always699560.yourdomain.com:443/.
alias.10.nfz37.10.yourdomain.com. 60 IN	MX	0 https://always049067.yourdomain.com:443/.
alias.10.nfz37.10.yourdomain.com. 60 IN	MX	0 https://always520555.yourdomain.com:443/.
alias.10.nfz37.10.yourdomain.com. 60 IN	MX	0 https://always588674.yourdomain.com:443/.
alias.10.nfz37.10.yourdomain.com. 60 IN	MX	0 https://always287876.yourdomain.com:443/.
alias.10.nfz37.10.yourdomain.com. 60 IN	MX	0 https://always118507.yourdomain.com:443/.
alias.10.nfz37.10.yourdomain.com. 60 IN	MX	0 https://always529671.yourdomain.com:443/.
alias.10.nfz37.10.yourdomain.com. 60 IN	MX	0 https://always013499.yourdomain.com:443/.
alias.10.nfz37.10.yourdomain.com. 60 IN	MX	0 https://always537725.yourdomain.com:443/.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:23 +04 2024
;; MSG SIZE  rcvd: 930

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz38.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz38.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 57671
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz38.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz38.10.yourdomain.com. 60 IN	MX	0 always024908.yourdomain.com:80.
alias.10.nfz38.10.yourdomain.com. 60 IN	MX	0 always991887.yourdomain.com:80.
alias.10.nfz38.10.yourdomain.com. 60 IN	MX	0 always448622.yourdomain.com:80.
alias.10.nfz38.10.yourdomain.com. 60 IN	MX	0 always227377.yourdomain.com:80.
alias.10.nfz38.10.yourdomain.com. 60 IN	MX	0 always523994.yourdomain.com:80.
alias.10.nfz38.10.yourdomain.com. 60 IN	MX	0 always558297.yourdomain.com:80.
alias.10.nfz38.10.yourdomain.com. 60 IN	MX	0 always097516.yourdomain.com:80.
alias.10.nfz38.10.yourdomain.com. 60 IN	MX	0 always033531.yourdomain.com:80.
alias.10.nfz38.10.yourdomain.com. 60 IN	MX	0 always533400.yourdomain.com:80.
alias.10.nfz38.10.yourdomain.com. 60 IN	MX	0 always367927.yourdomain.com:80.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:24 +04 2024
;; MSG SIZE  rcvd: 830

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz39.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz39.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 38522
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz39.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz39.10.yourdomain.com. 60 IN	MX	0 always598869.yourdomain.com:443.
alias.10.nfz39.10.yourdomain.com. 60 IN	MX	0 always979887.yourdomain.com:443.
alias.10.nfz39.10.yourdomain.com. 60 IN	MX	0 always971046.yourdomain.com:443.
alias.10.nfz39.10.yourdomain.com. 60 IN	MX	0 always160442.yourdomain.com:443.
alias.10.nfz39.10.yourdomain.com. 60 IN	MX	0 always037592.yourdomain.com:443.
alias.10.nfz39.10.yourdomain.com. 60 IN	MX	0 always002884.yourdomain.com:443.
alias.10.nfz39.10.yourdomain.com. 60 IN	MX	0 always499018.yourdomain.com:443.
alias.10.nfz39.10.yourdomain.com. 60 IN	MX	0 always410751.yourdomain.com:443.
alias.10.nfz39.10.yourdomain.com. 60 IN	MX	0 always833163.yourdomain.com:443.
alias.10.nfz39.10.yourdomain.com. 60 IN	MX	0 always076680.yourdomain.com:443.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:24 +04 2024
;; MSG SIZE  rcvd: 840

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz40.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz40.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1958
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz40.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz40.10.yourdomain.com. 60 IN	MX	0 1.2.3.4.
alias.10.nfz40.10.yourdomain.com. 60 IN	MX	0 1.2.3.4.
alias.10.nfz40.10.yourdomain.com. 60 IN	MX	0 1.2.3.4.
alias.10.nfz40.10.yourdomain.com. 60 IN	MX	0 1.2.3.4.
alias.10.nfz40.10.yourdomain.com. 60 IN	MX	0 1.2.3.4.
alias.10.nfz40.10.yourdomain.com. 60 IN	MX	0 1.2.3.4.
alias.10.nfz40.10.yourdomain.com. 60 IN	MX	0 1.2.3.4.
alias.10.nfz40.10.yourdomain.com. 60 IN	MX	0 1.2.3.4.
alias.10.nfz40.10.yourdomain.com. 60 IN	MX	0 1.2.3.4.
alias.10.nfz40.10.yourdomain.com. 60 IN	MX	0 1.2.3.4.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:24 +04 2024
;; MSG SIZE  rcvd: 600

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz41.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz41.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 14668
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz41.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz41.10.yourdomain.com. 60 IN	MX	0 1.2.3.4:80.
alias.10.nfz41.10.yourdomain.com. 60 IN	MX	0 1.2.3.4:80.
alias.10.nfz41.10.yourdomain.com. 60 IN	MX	0 1.2.3.4:80.
alias.10.nfz41.10.yourdomain.com. 60 IN	MX	0 1.2.3.4:80.
alias.10.nfz41.10.yourdomain.com. 60 IN	MX	0 1.2.3.4:80.
alias.10.nfz41.10.yourdomain.com. 60 IN	MX	0 1.2.3.4:80.
alias.10.nfz41.10.yourdomain.com. 60 IN	MX	0 1.2.3.4:80.
alias.10.nfz41.10.yourdomain.com. 60 IN	MX	0 1.2.3.4:80.
alias.10.nfz41.10.yourdomain.com. 60 IN	MX	0 1.2.3.4:80.
alias.10.nfz41.10.yourdomain.com. 60 IN	MX	0 1.2.3.4:80.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:24 +04 2024
;; MSG SIZE  rcvd: 630

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz42.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz42.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 48574
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz42.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz42.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4.
alias.10.nfz42.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4.
alias.10.nfz42.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4.
alias.10.nfz42.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4.
alias.10.nfz42.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4.
alias.10.nfz42.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4.
alias.10.nfz42.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4.
alias.10.nfz42.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4.
alias.10.nfz42.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4.
alias.10.nfz42.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:24 +04 2024
;; MSG SIZE  rcvd: 600

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz43.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz43.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 30272
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz43.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz43.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4:80.
alias.10.nfz43.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4:80.
alias.10.nfz43.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4:80.
alias.10.nfz43.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4:80.
alias.10.nfz43.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4:80.
alias.10.nfz43.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4:80.
alias.10.nfz43.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4:80.
alias.10.nfz43.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4:80.
alias.10.nfz43.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4:80.
alias.10.nfz43.10.yourdomain.com. 60 IN	MX	0 1\.2\.3\.4:80.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:24 +04 2024
;; MSG SIZE  rcvd: 630

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz44.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz44.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 50025
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz44.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz44.10.yourdomain.com. 60 IN	MX	0 127.0.0.1.
alias.10.nfz44.10.yourdomain.com. 60 IN	MX	0 127.0.0.1.
alias.10.nfz44.10.yourdomain.com. 60 IN	MX	0 127.0.0.1.
alias.10.nfz44.10.yourdomain.com. 60 IN	MX	0 127.0.0.1.
alias.10.nfz44.10.yourdomain.com. 60 IN	MX	0 127.0.0.1.
alias.10.nfz44.10.yourdomain.com. 60 IN	MX	0 127.0.0.1.
alias.10.nfz44.10.yourdomain.com. 60 IN	MX	0 127.0.0.1.
alias.10.nfz44.10.yourdomain.com. 60 IN	MX	0 127.0.0.1.
alias.10.nfz44.10.yourdomain.com. 60 IN	MX	0 127.0.0.1.
alias.10.nfz44.10.yourdomain.com. 60 IN	MX	0 127.0.0.1.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:24 +04 2024
;; MSG SIZE  rcvd: 620

-------------------------------------------------------------------------------------------
# dig MX alias.10.nfz45.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> MX alias.10.nfz45.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 62178
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.10.nfz45.10.yourdomain.com. IN	MX

;; ANSWER SECTION:
alias.10.nfz45.10.yourdomain.com. 60 IN	MX	0 127.0.0.1:80.
alias.10.nfz45.10.yourdomain.com. 60 IN	MX	0 127.0.0.1:80.
alias.10.nfz45.10.yourdomain.com. 60 IN	MX	0 127.0.0.1:80.
alias.10.nfz45.10.yourdomain.com. 60 IN	MX	0 127.0.0.1:80.
alias.10.nfz45.10.yourdomain.com. 60 IN	MX	0 127.0.0.1:80.
alias.10.nfz45.10.yourdomain.com. 60 IN	MX	0 127.0.0.1:80.
alias.10.nfz45.10.yourdomain.com. 60 IN	MX	0 127.0.0.1:80.
alias.10.nfz45.10.yourdomain.com. 60 IN	MX	0 127.0.0.1:80.
alias.10.nfz45.10.yourdomain.com. 60 IN	MX	0 127.0.0.1:80.
alias.10.nfz45.10.yourdomain.com. 60 IN	MX	0 127.0.0.1:80.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Jun 04 15:07:24 +04 2024
;; MSG SIZE  rcvd: 650
```

##
Go back to [menu](#polardns-catalogue---response-modifiers).

