# PolarDNS catalogue - Empty responses
1. [General features](general-features.md)
1. [Response modifiers](response-modifiers.md)
1. [CNAME fuzzing](cname-fuzzing.md)
1. [Bad compression](bad-compression.md)
1. [Empty responses](empty-responses.md)
	- [Close the connection (close)](#close-the-connection-close)
	- [Don't respond (timeout)](#don't-respond-timeout)
	- [Empty response (empty1)](#empty-response-empty1)
	- [Only NULL bytes (empty2)](#only-null-bytes-empty2)
	- [Only NULL bytes, suitable for TCP (empty3)](#only-null-bytes-suitable-for-tcp-empty3)
	- [Only TXID and NULL bytes (empty4)](#only-txid-and-null-bytes-empty4)
	- [Only TXID, flags, RRs and NULL bytes (empty5)](#only-txid-flags-rrs-and-null-bytes-empty5)
	- [ANSWER section is missing (empty6)](#answer-section-is-missing-empty6)
	- [ANSWER section is NULL bytes (empty7)](#answer-section-is-null-bytes-empty7)
	- [Query reflection (queryback1)](#query-reflection-queryback1)
	- [Query reflection, stripped (queryback2)](#query-reflection-stripped-queryback2)
	- [Query reflection, to port 53 (queryback3)](#query-reflection-to-port-53-queryback3)
1. [Record injections](record-injections.md)

These scenarios include sending out variety of empty responses, sending back incomplete responses, responses with NULL bytes, sending back nothing, sending back the query itself (query reflection) etc.

##
### Close the connection (close)
Don't respond, just close the connection immediately.

<table>
<tr><td>format:</td><td>close.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig close.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig close.yourdomain.com @127.0.0.1 +tcp</code></td></tr>
<tr><td>example:</td><td><code>dig close123whatever.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig close.yourdomain.com @127.0.0.1 +tcp
;; communications error to 127.0.0.1#53: end of file
;; communications error to 127.0.0.1#53: end of file
;; communications error to 127.0.0.1#53: end of file

; <<>> DiG 9.18.10-2-Debian <<>> close.yourdomain.com @127.0.0.1 +tcp
;; global options: +cmd
;; no servers could be reached

```
### Don't respond (timeout)
Don't respond, just let the connection timeout.

<table>
<tr><td>format:</td><td>timeout.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig timeout.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig timeout.yourdomain.com @127.0.0.1 +tcp</code></td></tr>
<tr><td>example:</td><td><code>dig timeout123whatever.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig timeout.yourdomain.com @127.0.0.1
;; communications error to 127.0.0.1#53: timed out
;; communications error to 127.0.0.1#53: timed out
;; communications error to 127.0.0.1#53: timed out

; <<>> DiG 9.18.10-2-Debian <<>> timeout.yourdomain.com @127.0.0.1
;; global options: +cmd
;; no servers could be reached

```
### Empty response (empty1)
Send empty response, simply an empty packet.

<table>
<tr><td>format:</td><td>empty1.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig empty1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig empty1whatever.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig empty1.yourdomain.com @127.0.0.1
;; Warning: short (< header size) message received
;; communications error to 127.0.0.1#53: timed out
;; Warning: short (< header size) message received
;; communications error to 127.0.0.1#53: timed out
;; Warning: short (< header size) message received
;; communications error to 127.0.0.1#53: timed out

; <<>> DiG 9.18.10-2-Debian <<>> empty1.yourdomain.com @127.0.0.1
;; global options: +cmd
;; no servers could be reached

```
### Only NULL bytes (empty2)
Send empty response with arbitrary number of NULLs (x00).

<table>
<tr><td>format:</td><td>empty2.&lt;NUMBER-OF-NULLS>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig empty2.50.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig empty2whatever.50.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig empty2.50.yourdomain.com @127.0.0.1
;; Warning: ID mismatch: expected ID 26526, got 0
;; Warning: query response not set
;; communications error to 127.0.0.1#53: timed out
;; Warning: ID mismatch: expected ID 26526, got 0
;; Warning: query response not set
;; communications error to 127.0.0.1#53: timed out
;; Warning: ID mismatch: expected ID 26526, got 0
;; Warning: query response not set
;; communications error to 127.0.0.1#53: timed out

; <<>> DiG 9.18.10-2-Debian <<>> empty2.50.yourdomain.com @127.0.0.1
;; global options: +cmd
;; no servers could be reached

```
### Only NULL bytes, suitable for TCP (empty3)
Like empty2, but in TCP mode make sure the length is properly provided in the beginning, so just sending 1 NULL will be x00x01x00 in TCP.

<table>
<tr><td>format:</td><td>empty3.&lt;NUMBER-OF-NULLS>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig empty3.50.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig empty3whatever.50.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig empty3.50.yourdomain.com @127.0.0.1
;; Warning: ID mismatch: expected ID 7931, got 0
;; Warning: query response not set
;; communications error to 127.0.0.1#53: timed out
;; Warning: ID mismatch: expected ID 7931, got 0
;; Warning: query response not set
;; communications error to 127.0.0.1#53: timed out
;; Warning: ID mismatch: expected ID 7931, got 0
;; Warning: query response not set
;; communications error to 127.0.0.1#53: timed out

; <<>> DiG 9.18.10-2-Debian <<>> empty3.50.yourdomain.com @127.0.0.1
;; global options: +cmd
;; no servers could be reached

```
### Only TXID and NULL bytes (empty4)
Send empty response with only the TXID (first 2 bytes of every DNS response) + arbitrary number of NULLs.

<table>
<tr><td>remark:</td><td>In TCP the length will be properly provided in the beginning</td></tr>
<tr><td>format:</td><td>empty4.&lt;NUMBER-OF-NULLS>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig empty4.50.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig empty4whatever.50.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig empty4.0.len200.tc.yourdomain.com @127.0.0.1</code> This means the response will be TCP DNS packet with length indicating it is a 200 B packet in size, but there will be just the TXID and nothing else (0 number of NULLs)</td></tr>
</table>

Sample:
```
# dig empty4.50.yourdomain.com @127.0.0.1
;; Warning: query response not set

; <<>> DiG 9.18.10-2-Debian <<>> empty4.50.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 13447
;; flags:; QUERY: 0, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: Message has 40 extra bytes at end

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:04 +04 2023
;; MSG SIZE  rcvd: 52
```
### Only TXID, flags, RRs and NULL bytes (empty5)
Send normal DNS header including TXID, flags and number of RRs, but then send only arbitrary number of NULLs.

<table>
<tr><td>format:</td><td>empty5.&lt;NUMBER-OF-NULLS>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig empty5.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig empty5.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig empty5whatever.50.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig empty5.10.yourdomain.com @127.0.0.1
;; Warning: Message parser reports malformed message packet.
;; ;; Question section mismatch: got ./TYPE0/RESERVED0
;; communications error to 127.0.0.1#53: timed out
;; Warning: Message parser reports malformed message packet.
;; ;; Question section mismatch: got ./TYPE0/RESERVED0
;; communications error to 127.0.0.1#53: timed out
;; Warning: Message parser reports malformed message packet.
;; ;; Question section mismatch: got ./TYPE0/RESERVED0
;; communications error to 127.0.0.1#53: timed out

; <<>> DiG 9.18.10-2-Debian <<>> empty5.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; no servers could be reached

```
### ANSWER section is missing (empty6)
Send normal DNS response, but remove the ANSWER section.

<table>
<tr><td>format:</td><td>empty6.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig empty6.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig empty6whatever.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig empty6.yourdomain.com @127.0.0.1
;; Warning: Message parser reports malformed message packet.

; <<>> DiG 9.18.10-2-Debian <<>> empty6.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 23430
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;empty6.yourdomain.com.		IN	A

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sat Nov 04 01:42:41 +04 2023
;; MSG SIZE  rcvd: 39

```
### ANSWER section is NULL bytes (empty7)
Send normal DNS response, but replace the ANSWER section with NULLs.

<table>
<tr><td>format:</td><td>empty7.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig empty7.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig empty7whatever.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig empty7.yourdomain.com @127.0.0.1
;; Got bad packet: FORMERR
76 bytes
de fe 84 00 00 01 00 01 00 00 00 00 06 65 6d 70          .............emp
74 79 37 0a 79 6f 75 72 64 6f 6d 61 69 6e 03 63          ty7.yourdomain.c
6f 6d 00 00 01 00 01 00 00 00 00 00 00 00 00 00          om..............
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00          ................
00 00 00 00 00 00 00 00 00 00 00 00                      ............
```
### Query reflection (queryback1)
Instead of a proper response, send back the exact same query.

<table>
<tr><td>format:</td><td>queryback1.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig queryback1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig queryback1.newid.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig queryback1.yourdomain.com @127.0.0.1
;; Warning: query response not set

; <<>> DiG 9.18.10-2-Debian <<>> queryback1.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 23676
;; flags: rd ad; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;queryback1.yourdomain.com.	IN	A

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:04 +04 2023
;; MSG SIZE  rcvd: 43
```
### Query reflection, stripped (queryback2)
Send back the same query, stripped. Send back only the same question, without any additional sections (e.g. the OPT / EDNS0).

<table>
<tr><td>format:</td><td>queryback2.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig queryback2.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig queryback2.newid.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig queryback2.yourdomain.com @127.0.0.1
;; Warning: query response not set

; <<>> DiG 9.18.10-2-Debian <<>> queryback2.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 47217
;; flags: rd ad; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;queryback2.yourdomain.com.	IN	A

;; Query time: 4 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sat Nov 04 01:46:20 +04 2023
;; MSG SIZE  rcvd: 43

```
### Query reflection, to port 53 (queryback3)
Send back the same query to the sender to port udp/53. This might create a loop if the resolver uses the same IP address for listening for queries and for performing the resolution as well.

<table>
<tr><td>format:</td><td>queryback3.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig queryback3.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig queryback3.newid.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig queryback3.yourdomain.com @127.0.0.1
;; communications error to 127.0.0.1#53: timed out
;; communications error to 127.0.0.1#53: timed out
;; communications error to 127.0.0.1#53: timed out

; <<>> DiG 9.18.10-2-Debian <<>> queryback3.yourdomain.com @127.0.0.1
;; global options: +cmd
;; no servers could be reached

```

##
Go back to [menu](#polardns-catalogue---empty-responses).

