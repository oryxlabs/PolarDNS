# PolarDNS catalogue - CNAME fuzzing
1. [General features](general-features.md)
1. [Response modifiers](response-modifiers.md)
1. [CNAME fuzzing](cname-fuzzing.md)
	- [Long CNAME alias of arbitrary size (bigcname)](#long-cname-alias-of-arbitrary-size-bigcname)
	- [Long CNAME with arbitrary number of labels (manylabels)](#long-cname-with-arbitrary-number-of-labels-manylabels)
	- [Many always CNAME aliases (manycnames)](#many-always-cname-aliases-manycnames)
	- [Many random CNAME aliases, textual (cnamefuzz1)](#many-random-cname-aliases-textual-cnamefuzz1)
	- [Many random CNAME aliases, binary (cnamefuzz2)](#many-random-cname-aliases-binary-cnamefuzz2)
	- [CNAME alias with a dot in different positions (dotcname)](#cname-alias-with-a-dot-in-different-positions-dotcname)
	- [Resolvable CNAME with arbitrary byte string (cgena)](#resolvable-cname-with-arbitrary-byte-string-cgena)
	- [Unresolvable CNAME with arbitrary byte string (cgenb)](#unresolvable-cname-with-arbitrary-byte-string-cgenb)
	- [Illegal CNAME formats (badcname)](#illegal-cname-formats-badcname)
1. [Bad compression](bad-compression.md)
1. [Empty responses](empty-responses.md)
1. [Record injections](record-injections.md)

Variety of scenarios involving illegally specified CNAME record(s) in the response.

##
### Long CNAME alias of arbitrary size (bigcname)
Respond with a randomly generated CNAME of arbitrary size, capable of creating oversized domain labels and domain names.

<table>
<tr><td>format:</td><td>bigcname.&lt;LABEL-SIZE-1>.[&lt;LABEL-SIZE-N>].yourdomain.com</td></tr>
<tr><td>remark:</td><td>Max label size is 63</td></tr>
<tr><td>remark:</td><td>Max size of the whole domain name is 255</td></tr>
<tr><td>example:</td><td><code>dig bigcname.63.63.63.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig bigcname.63.63.63.63.63.63.63.63.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig bigcname.63.63.63.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> bigcname.63.63.63.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 39565
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;bigcname.63.63.63.yourdomain.com. IN	A

;; ANSWER SECTION:
bigcname.63.63.63.yourdomain.com. 60 IN	CNAME	always.up42ifbdztiqsnagsvkxw6x5i2fhhnqp8zrxpi8srwom391cdxfnlhkuckg9c9l.r53nipw6v2fqabq1f4bqy5l3hslopexhn4nm8kahrahopef4417kcsued0b74ae.dl0g71w52tudrv1wuotg9o6oayhaxl0liyckknjw6tf6zrxcw7knobzzfboa54x.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:35:02 +04 2023
;; MSG SIZE  rcvd: 309
```
### Long CNAME with arbitrary number of labels (manylabels)
Respond with a CNAME containing arbitrary number of labels (domain components), capable of creating oversized domain labels and domain names.

<table>
<tr><td>format:</td><td>manylabels.&lt;NUMBER-OF-LABELS>.&lt;LABEL-SIZE>.yourdomain.com</td></tr>
<tr><td>remark:</td><td>Max label size is 63</td></tr>
<tr><td>remark:</td><td>Max size of the whole domain name is 255</td></tr>
<tr><td>example:</td><td><code>dig manylabels.100.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig manylabels.50.2.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig manylabels.300.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig manylabels.100.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> manylabels.100.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4688
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;manylabels.100.yourdomain.com.	IN	A

;; ANSWER SECTION:
manylabels.100.yourdomain.com. 60 IN	CNAME	always.t.g.k.s.h.z.b.u.s.d.y.s.b.6.o.h.8.5.r.z.r.z.b.n.w.g.r.r.y.p.9.b.7.9.m.w.r.m.d.3.9.d.q.1.x.d.m.1.f.0.i.u.3.4.e.5.4.u.i.5.k.u.y.x.i.s.v.s.k.p.h.a.r.q.w.g.7.m.t.z.s.x.n.g.g.0.2.h.n.f.q.o.2.e.0.c.3.2.v.h.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Wed Nov 08 16:37:15 +04 2023
;; MSG SIZE  rcvd: 311

```
### Many always CNAME aliases (manycnames)
Respond with a arbitrary number of randomly generated CNAME records.

<table>
<tr><td>format:</td><td>manycnames.&lt;NUMBER-OF-RECORDS>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig manycnames.50.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig manynames$((RANDOM)).800.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig manycnames.50.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> manycnames.50.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 56180
;; flags: qr aa; QUERY: 1, ANSWER: 50, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;manycnames.50.yourdomain.com.	IN	A

;; ANSWER SECTION:
manycnames.50.yourdomain.com. 60 IN	CNAME	always278.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always22570.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always17742.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always64673.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always23037.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always97747.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always75494.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always15521.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always93306.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always18545.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always68064.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always80183.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always77186.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always91741.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always71768.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always71703.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always39237.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always50368.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always85898.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always35779.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always99936.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always79473.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always32149.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always77880.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always295.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always10366.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always10792.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always86822.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always45845.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always40760.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always98867.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always68554.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always72340.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always13631.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always82567.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always74815.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always40411.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always18058.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always34323.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always31600.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always78690.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always44918.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always85167.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always81033.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always40362.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always69852.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always49212.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always39463.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always96455.yourdomain.com.
manycnames.50.yourdomain.com. 60 IN	CNAME	always3338.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Wed Nov 08 10:40:18 +04 2023
;; MSG SIZE  rcvd: 3441

```
### Many random CNAME aliases, textual (cnamefuzz1)
Respond with many CNAME answers where each answer contains a random string of specified length, made of all kinds of illegal ASCII characters that are likely not allowed in a domain name.

<table>
<tr><td>format:</td><td>cnamefuzz1.&lt;NUMBER-OF-CNAMES>.&lt;CNAME-STRING-SIZE>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig cnamefuzz1.10.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig cnamefuzz1whatever.10.10.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig cnamefuzz1.10.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> cnamefuzz1.10.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 24247
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;cnamefuzz1.10.10.yourdomain.com. IN	A

;; ANSWER SECTION:
cnamefuzz1.10.10.yourdomain.com. 60 IN	CNAME	]i\$?U^*[kQ.
cnamefuzz1.10.10.yourdomain.com. 60 IN	CNAME	h\011oK0+loF?.
cnamefuzz1.10.10.yourdomain.com. 60 IN	CNAME	mbLbcD]gMG.
cnamefuzz1.10.10.yourdomain.com. 60 IN	CNAME	:%}pDmLVd*.
cnamefuzz1.10.10.yourdomain.com. 60 IN	CNAME	eqZ2e]LnnI.
cnamefuzz1.10.10.yourdomain.com. 60 IN	CNAME	70D&,\013\012>`<.
cnamefuzz1.10.10.yourdomain.com. 60 IN	CNAME	B]\$!Ct-Dlr.
cnamefuzz1.10.10.yourdomain.com. 60 IN	CNAME	'p\010\(~XC2KA.
cnamefuzz1.10.10.yourdomain.com. 60 IN	CNAME	_#3<%FcG6~.
cnamefuzz1.10.10.yourdomain.com. 60 IN	CNAME	/._\012\009rr\"\;q.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:44:56 +04 2023
;; MSG SIZE  rcvd: 599
```
### Many random CNAME aliases, binary (cnamefuzz2)
Respond with many CNAME answers where each answer contains a random binary string (NULL terminated) of specified length.

<table>
<tr><td>format:</td><td>cnamefuzz2.&lt;NUMBER-OF-CNAMES>.&lt;CNAME-STRING-SIZE>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig cnamefuzz2.10.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig cnamefuzz2whatever.10.10.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig cnamefuzz2.10.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> cnamefuzz2.10.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 46795
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;cnamefuzz2.10.10.yourdomain.com. IN	A

;; ANSWER SECTION:
cnamefuzz2.10.10.yourdomain.com. 60 IN	CNAME	\143\239\161d\21575%3\172.
cnamefuzz2.10.10.yourdomain.com. 60 IN	CNAME	\146y%\255!\)\174\175\222n.
cnamefuzz2.10.10.yourdomain.com. 60 IN	CNAME	\165\224\189\022o\008\137Uz\186.
cnamefuzz2.10.10.yourdomain.com. 60 IN	CNAME	\229\158\191\1526\179se\012\234.
cnamefuzz2.10.10.yourdomain.com. 60 IN	CNAME	\218C\004\018W\130\222W+\154.
cnamefuzz2.10.10.yourdomain.com. 60 IN	CNAME	\025\027\246|\136w\223K\019\221.
cnamefuzz2.10.10.yourdomain.com. 60 IN	CNAME	\149\149m\149\214s\167\198\015r.
cnamefuzz2.10.10.yourdomain.com. 60 IN	CNAME	\209\240k\185\206\144:s6\235.
cnamefuzz2.10.10.yourdomain.com. 60 IN	CNAME	\237\192]q\137\027\016\248\214\192.
cnamefuzz2.10.10.yourdomain.com. 60 IN	CNAME	\231\011<\186\023\145\232j\208\..

;; Query time: 4 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:35:02 +04 2023
;; MSG SIZE  rcvd: 599
```
### CNAME alias with a dot in different positions (dotcname)
Respond with CNAME (always123456.yourdomain.com) containing dot character (`.`) in different positions based on selected variant.

<table>
<tr><td>format:</td><td>dotcname.&lt;VARIANT-1-7>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig dotcname.1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig dotcnameanything.1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>remark:</td><td>VARIANT-1: always[DOT]123456.yourdomain.com</td></tr>
<tr><td>remark:</td><td>VARIANT-2: always[DOT]a123456.yourdomain.com</td></tr>
<tr><td>remark:</td><td>VARIANT-3: always123456[DOT]yourdomain.com</td></tr>
<tr><td>remark:</td><td>VARIANT-4: always123456.yourdomain[DOT]com</td></tr>
<tr><td>remark:</td><td>VARIANT-5: always123456.yourdomain.com[DOT]</td></tr>
<tr><td>remark:</td><td>VARIANT-6: always123456.yourdomain.com.[DOT]</td></tr>
<tr><td>remark:</td><td>VARIANT-7: always123456[DOT]yourdomain[DOT]com</td></tr>
</table>

Sample:
```
# dig dotcname.1.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> dotcname.1.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54790
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;dotcname.1.yourdomain.com.	IN	A

;; ANSWER SECTION:
dotcname.1.yourdomain.com. 60	IN	CNAME	always\.656868.yourdomain.com.

;; Query time: 4 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Wed Nov 08 00:33:00 +04 2023
;; MSG SIZE  rcvd: 110

```
### Resolvable CNAME with arbitrary byte string (cgena)
Respond with CNAME (always123456.yourdomain.com) containing arbitrary number of characters (bytes) in different positions based on the selected variant.

<table>
<tr><td>format:</td><td>cgena.&lt;VARIANT-1-6>.&lt;BYTE-0-255>.&lt;HOWMANY>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig cgena.4.0.1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig cgena.1.0.5.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig cgenaanything.1.255.100.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>remark:</td><td>VARIANT-1: &lt;BAD>.always123456.yourdomain.com</td></tr>
<tr><td>remark:</td><td>VARIANT-2: &lt;BAD>always123456.yourdomain.com</td></tr>
<tr><td>remark:</td><td>VARIANT-3: always&lt;BAD>123456.yourdomain.com</td></tr>
<tr><td>remark:</td><td>VARIANT-4: always123456.yourdomain.&lt;BAD>com</td></tr>
<tr><td>remark:</td><td>VARIANT-5: always123456.yourdomain.com&lt;BAD></td></tr>
<tr><td>remark:</td><td>VARIANT-6: always123456.yourdomain.com.&lt;BAD></td></tr>
</table>

Sample:
```
# dig cgena.4.0.1.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> cgena.4.0.1.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54488
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;cgena.4.0.1.yourdomain.com.	IN	A

;; ANSWER SECTION:
cgena.4.0.1.yourdomain.com. 60	IN	CNAME	always123633.yourdomain.\000com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Wed Nov 08 10:11:14 +04 2023
;; MSG SIZE  rcvd: 112

```
### Unresolvable CNAME with arbitrary byte string (cgenb)
Respond with CNAME (nonres123456.yourdomain.com) containing arbitrary number of characters (bytes) in different positions based on the selected variant.

<table>
<tr><td>format:</td><td>cgenb.&lt;VARIANT-1-6>.&lt;BYTE-0-255>.&lt;HOWMANY>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig cgenb.5.255.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig cgenb.5.39.5.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig cgenbanything.1.255.100.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>remark:</td><td>VARIANT-1: &lt;BAD>.nonres123456.yourdomain.com</td></tr>
<tr><td>remark:</td><td>VARIANT-2: &lt;BAD>nonres123456.yourdomain.com</td></tr>
<tr><td>remark:</td><td>VARIANT-3: nonres&lt;BAD>123456.yourdomain.com</td></tr>
<tr><td>remark:</td><td>VARIANT-4: nonres123456.yourdomain.&lt;BAD>com</td></tr>
<tr><td>remark:</td><td>VARIANT-5: nonres123456.yourdomain.com&lt;BAD></td></tr>
<tr><td>remark:</td><td>VARIANT-6: nonres123456.yourdomain.com.&lt;BAD></td></tr>
</table>

Sample:
```
# dig cgenb.5.255.10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> cgenb.5.255.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4227
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;cgenb.5.255.10.yourdomain.com.	IN	A

;; ANSWER SECTION:
cgenb.5.255.10.yourdomain.com. 60 IN	CNAME	nonres008646.yourdomain.com\255\255\255\255\255\255\255\255\255\255.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Wed Nov 08 10:46:54 +04 2023
;; MSG SIZE  rcvd: 127

```
### Illegal CNAME formats (badcname)
Respond with CNAME alias containing a hostname in an illegal form e.g. containing an IP address, a port number or an URL, based on the selected variant.

<table>
<tr><td>format:</td><td>badcname.&lt;VARIANT-1-11>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig badcname.0.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig badcname.9.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig badcnameanything.1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>remark:</td><td>VARIANT-0: http://always779768.yourdomain.com/</td></tr>
<tr><td>remark:</td><td>VARIANT-1: http://always799902.yourdomain.com:80/</td></tr>
<tr><td>remark:</td><td>VARIANT-2: https://always725764.yourdomain.com/</td></tr>
<tr><td>remark:</td><td>VARIANT-3: https://always006450.yourdomain.com:443/</td></tr>
<tr><td>remark:</td><td>VARIANT-4: always279856.yourdomain.com:80</td></tr>
<tr><td>remark:</td><td>VARIANT-5: always260211.yourdomain.com:443</td></tr>
<tr><td>remark:</td><td>VARIANT-6: 1.2.3.4 (IP address as a hostname)</td></tr>
<tr><td>remark:</td><td>VARIANT-7: 1.2.3.4:80</td></tr>
<tr><td>remark:</td><td>VARIANT-8: 1\.2\.3\.4 (IP address as a hostname as a single label by using actual dot symbols)</td></tr>
<tr><td>remark:</td><td>VARIANT-9: 1\.2\.3\.4:80</td></tr>
<tr><td>remark:</td><td>VARIANT-10: 44.196.123.123</td></tr>
<tr><td>remark:</td><td>VARIANT-11: 44.196.123.123:80</td></tr>
</table>

Sample:
```
# dig badcname.9.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> badcname.9.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 9827
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;badcname.9.yourdomain.com.	IN	A

;; ANSWER SECTION:
badcname.9.yourdomain.com. 60	IN	CNAME	1\.2\.3\.4:80.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Wed Nov 08 11:22:22 +04 2023
;; MSG SIZE  rcvd: 92

```

##
Go back to [menu](#polardns-catalogue---cname-fuzzing).

