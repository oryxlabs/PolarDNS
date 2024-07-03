# PolarDNS catalogue - General features
1. [General features](general-features.md)
	- [Always resolve to IP (always)](#always-resolve-to-ip-always)
	- [Client IP address (self / whatismyip)](#client-ip-address-self--whatismyip)
	- [Chunked CNAME aliases (chunkedcnames)](#chunked-cname-aliases-chunkedcnames)
	- [Cut A record from the end (cutabuf)](#cut-a-record-from-the-end-cutabuf)
	- [Cut CNAME record from the end (cutcnamebuf)](#cut-cname-record-from-the-end-cutcnamebuf)
	- [TXT record with multiple text strings (bigtxt)](#txt-record-with-multiple-text-strings-bigtxt)
	- [TXT record with multiple binary strings (bigbintxt)](#txt-record-with-multiple-binary-strings-bigbintxt)
	- [Many TXT records with random text (manytxt)](#many-txt-records-with-random-text-manytxt)
	- [Many TXT records with binary data (manybintxt)](#many-txt-records-with-binary-data-manybintxt)
	- [Single A record with arbitrary byte (afuzz1)](#single-a-record-with-arbitrary-byte-afuzz1)
	- [Many bogus A records and legit A record (afuzz2)](#many-bogus-a-records-and-legit-a-record-afuzz2)
	- [Arbitrary record type with random data (customtype)](#arbitrary-record-type-with-random-data-customtype)
1. [Aliases, loops and chains](aliases-loops-and-chains.md)
1. [Response modifiers](response-modifiers.md)
1. [CNAME fuzzing](cname-fuzzing.md)
1. [Bad compression](bad-compression.md)
1. [Empty responses](empty-responses.md)
1. [Record injections](record-injections.md)

##
### Always resolve to IP (always)
The most basic functionality to always respond with A record (2.3.4.5).

<table>
<tr><td>format:</td><td>always&lt;ANYTHING>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig always.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig always123.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig always.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> always.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 14548
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;always.yourdomain.com.		IN	A

;; ANSWER SECTION:
always.yourdomain.com.	60	IN	A	2.3.4.5

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Fri Nov 03 14:30:50 +04 2023
;; MSG SIZE  rcvd: 76

```
### Client IP address (self / whatismyip)
Respond with A and TXT records containing the IP address of the connecting client. The TXT record also contains the port information.

<table>
<tr><td>format:</td><td>self.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig self.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig A self.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig TXT self.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig TXT whatismyip.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig TXT whatismyip.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> TXT whatismyip.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15082
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;whatismyip.yourdomain.com.	IN	TXT

;; ANSWER SECTION:
whatismyip.yourdomain.com. 60	IN	TXT	"127.0.0.1:43732"

;; ADDITIONAL SECTION:
whatismyip.yourdomain.com. 60	IN	A	127.0.0.1

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Mon May 27 17:10:12 +04 2024
;; MSG SIZE  rcvd: 137

```
### Chunked CNAME aliases (chunkedcnames)
Respond with N random always####.yourdomain.com CNAMEs in a chunked manner (Truncated flag is set). Add a delay for sending the chunks slowly.

<table>
<tr><td>format:</td><td>chunkedcnames&lt;ANYTHING>.&lt;NUMBER-OF-CNAMES>.slp&lt;MILISECONDS>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig chunkedcnames.12.slp150.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig chunkedcnames.12.slp150.yourdomain.com @127.0.0.1
;; Truncated, retrying in TCP mode.

; <<>> DiG 9.18.10-2-Debian <<>> chunkedcnames.12.slp150.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45135
;; flags: qr aa; QUERY: 1, ANSWER: 12, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;chunkedcnames.12.slp150.yourdomain.com.	IN A

;; ANSWER SECTION:
chunkedcnames.12.slp150.yourdomain.com.	60 IN CNAME always96836.yourdomain.com.
chunkedcnames.12.slp150.yourdomain.com.	60 IN CNAME always81752.yourdomain.com.
chunkedcnames.12.slp150.yourdomain.com.	60 IN CNAME always87613.yourdomain.com.
chunkedcnames.12.slp150.yourdomain.com.	60 IN CNAME always964.yourdomain.com.
chunkedcnames.12.slp150.yourdomain.com.	60 IN CNAME always9521.yourdomain.com.
chunkedcnames.12.slp150.yourdomain.com.	60 IN CNAME always74395.yourdomain.com.
chunkedcnames.12.slp150.yourdomain.com.	60 IN CNAME always22818.yourdomain.com.
chunkedcnames.12.slp150.yourdomain.com.	60 IN CNAME always48858.yourdomain.com.
chunkedcnames.12.slp150.yourdomain.com.	60 IN CNAME always57418.yourdomain.com.
chunkedcnames.12.slp150.yourdomain.com.	60 IN CNAME always48583.yourdomain.com.
chunkedcnames.12.slp150.yourdomain.com.	60 IN CNAME always43443.yourdomain.com.
chunkedcnames.12.slp150.yourdomain.com.	60 IN CNAME always63975.yourdomain.com.

;; Query time: 2004 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (TCP)
;; WHEN: Fri Nov 03 14:30:53 +04 2023
;; MSG SIZE  rcvd: 989

```
### Cut A record from the end (cutabuf)
Respond with legit A record, but cut arbitrary number of bytes from the end of the buffer.

<table>
<tr><td>format:</td><td>cutabuf.&lt;BYTES-TO-CUT>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig cutabuf.10.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig cutabuf.10.yourdomain.com @127.0.0.1
;; Warning: Message parser reports malformed message packet.

; <<>> DiG 9.18.10-2-Debian <<>> cutabuf.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 26597
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: Message has 4 extra bytes at end

;; QUESTION SECTION:
;cutabuf.10.yourdomain.com.	IN	A

;; Query time: 4 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Nov 07 15:46:28 +04 2023
;; MSG SIZE  rcvd: 74

```
### Cut CNAME record from the end (cutcnamebuf)
Respond with legit CNAME record, but cut arbitrary number of bytes from the end of the buffer.

<table>
<tr><td>format:</td><td>cutcnamebuf.&lt;BYTES-TO-CUT>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig cutcnamebuf.10.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig cutcnamebuf.10.yourdomain.com @127.0.0.1
;; Warning: Message parser reports malformed message packet.

; <<>> DiG 9.18.10-2-Debian <<>> cutcnamebuf.10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 46729
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: Message has 19 extra bytes at end

;; QUESTION SECTION:
;cutcnamebuf.10.yourdomain.com.	IN	A

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue Nov 07 15:46:28 +04 2023
;; MSG SIZE  rcvd: 107

```
### TXT record with multiple text strings (bigtxt)
Send a big TXT record with arbitrary number of labels of arbitrary size. The labels will contain a random ASCII text.

<table>
<tr><td>format:</td><td>bigtxt.&lt;NUMBER-OF-LABELS>.&lt;LABEL-SIZE>.yourdomain.com</td></tr>
<tr><td>remark:</td><td>Max number of labels is 65535 (theoretical)</td></tr>
<tr><td>remark:</td><td>Max label size is 255</td></tr>
<tr><td>example:</td><td><code>dig bigtxt.10.20.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig bigtxt.10.20.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> bigtxt.10.20.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 43007
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;bigtxt.10.20.yourdomain.com.	IN	A

;; ANSWER SECTION:
bigtxt.10.20.yourdomain.com. 60	IN	TXT	"bnubjblv7x6us4mzbl0d" "6hn8gw0uda3a4924jzcu" "utc2qkr2ir0p2p8cqmo1" "mq5axh8wd8rvt0qojxno" "35ssnto21898r6fhg026" "fzjd4cbnnt647ju6ykon" "mzy4thilst0doyzhmznf" "90uok4hi0j7m7e6ve243" "dosq5zn97a8xaadpx1um" "ld9it7jalv14cc49k180"

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:39:41 +04 2023
;; MSG SIZE  rcvd: 294
```
### TXT record with multiple binary strings (bigbintxt)
Send a big TXT record with arbitrary number of labels of arbitrary size. The labels will contain a random binary data.

<table>
<tr><td>format:</td><td>bigbintxt.&lt;NUMBER-OF-LABELS>.&lt;LABEL-SIZE>.yourdomain.com</td></tr>
<tr><td>remark:</td><td>Max number of labels is 65535 (theoretical)</td></tr>
<tr><td>remark:</td><td>Max label size is 255</td></tr>
<tr><td>example:</td><td><code>dig bigbintxt.10.20.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig bigbintxt.10.20.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> bigbintxt.10.20.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12913
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;bigbintxt.10.20.yourdomain.com.	IN	A

;; ANSWER SECTION:
bigbintxt.10.20.yourdomain.com.	60 IN	TXT	"\130R\215\137\168\015\129\231kZ\160\234\246-\131]\160\202N\028" "\151U\223/'\009\153\158{#C&\2040\152u-\015\015\173" "\017d\198\006\180t\177\221\243bM\182\166\1339z\255\2292\003" "\009@\187\180\190\217\200\014\001\175\243\255\225\1423z0\030%C" "\204\001\164\225\024\138P\251Mc\193\239\021<\180\231\"\021\222*" "6\218\220\146\218\020\161S\235\130Q\026\190)\158`R\234\140\167" "JP\196H\025\211J\235\194\236\209\198i\144q\250\152\185r\201" "\176\197E\253_y\005\207\202\201\156\140\186\025\253\020\189\209\171\239" "\220\251\161\191s\031\165\235C\019X&\244\159\148\153\192!\238\207" "\159b~]J\147\144\226\252\243\201Z\183\238\238UO!\156\215"

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:39:41 +04 2023
;; MSG SIZE  rcvd: 300
```
### Many TXT records with random text (manytxt)
Send arbitrary number of TXT records of arbitrary size. The contents of the TXT records will be a random ASCII text.

<table>
<tr><td>format:</td><td>manytxt.&lt;NUMBER-OF-TXT-RECORDS>.&lt;TXT-RECORD-SIZE>.yourdomain.com</td></tr>
<tr><td>remark:</td><td>Max number of txt records is 65535 (theoretical)</td></tr>
<tr><td>remark:</td><td>Max TXT record size is 255</td></tr>
<tr><td>example:</td><td><code>dig manytxt.10.20.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig manytxt.10.20.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> manytxt.10.20.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 28244
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;manytxt.10.20.yourdomain.com.	IN	A

;; ANSWER SECTION:
manytxt.10.20.yourdomain.com. 60 IN	TXT	"0mutk1c8023pql25utsa"
manytxt.10.20.yourdomain.com. 60 IN	TXT	"dn1hv722v9fmokgx0hrk"
manytxt.10.20.yourdomain.com. 60 IN	TXT	"s2zpccjjn099dausy0y8"
manytxt.10.20.yourdomain.com. 60 IN	TXT	"3w2yx46m43lhlk7x7sz2"
manytxt.10.20.yourdomain.com. 60 IN	TXT	"u373a2rof2uaprhaj5jk"
manytxt.10.20.yourdomain.com. 60 IN	TXT	"yspfk9uu5cjsseud3un1"
manytxt.10.20.yourdomain.com. 60 IN	TXT	"v6qm7apeejs7pdoysrph"
manytxt.10.20.yourdomain.com. 60 IN	TXT	"9doq6g20um2l5xmq9hn1"
manytxt.10.20.yourdomain.com. 60 IN	TXT	"280o5wrp2nj8xjh8f4lv"
manytxt.10.20.yourdomain.com. 60 IN	TXT	"mlzoe7lhhgxczmrdk6at"

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:39:41 +04 2023
;; MSG SIZE  rcvd: 656
```
### Many TXT records with binary data (manybintxt)
Send arbitrary number of TXT records of arbitrary size. The contents of the TXT records will be a random binary data.

<table>
<tr><td>format:</td><td>manybintxt.&lt;NUMBER-OF-TXT-RECORDS>.&lt;TXT-RECORD-SIZE>.yourdomain.com</td></tr>
<tr><td>remark:</td><td>Max number of txt records is 65535 (theoretical)</td></tr>
<tr><td>remark:</td><td>Max TXT record size is 255</td></tr>
<tr><td>example:</td><td><code>dig manybintxt.10.20.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig manybintxt.10.20.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> manybintxt.10.20.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45522
;; flags: qr aa; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;manybintxt.10.20.yourdomain.com. IN	A

;; ANSWER SECTION:
manybintxt.10.20.yourdomain.com. 60 IN	TXT	"8\007n\145BFO\245\245)V\227\167\000\161\249\176\172\160\168"
manybintxt.10.20.yourdomain.com. 60 IN	TXT	"\249\022u\167\195\220\135 L\173\157A5\230J\201OJ\207\192"
manybintxt.10.20.yourdomain.com. 60 IN	TXT	"\143\001cF\221\031\190\141\0178\240\028\217S\142r\"\027q\137"
manybintxt.10.20.yourdomain.com. 60 IN	TXT	"\140\017\204\159\221d b\150\189J\029\191\140m5Wog\248"
manybintxt.10.20.yourdomain.com. 60 IN	TXT	"\138v/\156\154\189\193\153x\135\1845\156\220\175\165\169\214\162$"
manybintxt.10.20.yourdomain.com. 60 IN	TXT	"\135\011\018\238\209\198j\003\239b\1545\2052=\179\230\157\178\012"
manybintxt.10.20.yourdomain.com. 60 IN	TXT	"\028\020\016\201\234\243\132A\166\169;\152\250/EW\185\234\004\237"
manybintxt.10.20.yourdomain.com. 60 IN	TXT	"\237\026\214\202\162\165\243\194>>\237\242\227\022\204\245\228\\M\132"
manybintxt.10.20.yourdomain.com. 60 IN	TXT	"\205\005\176fO.\017\233\200U\021av\013\243C\185x\221\222"
manybintxt.10.20.yourdomain.com. 60 IN	TXT	"\235\248\229\223\026R\155?\193 K\255a\218\226\234!i\176Z"

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:39:41 +04 2023
;; MSG SIZE  rcvd: 689
```
### Single A record with arbitrary byte (afuzz1)
Respond with A record containing arbitrary byte in the middle of the name in the ANSWER section, essentially giving an incorrect answer.

<table>
<tr><td>format:</td><td>afuzz1.&lt;BYTE-0-255>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig afuzz1.0.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig afuzz1anything.255.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig afuzz1.0.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> afuzz1.0.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 39386
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;afuzz1.0.yourdomain.com.	IN	A

;; ANSWER SECTION:
af\000zz1.0.yourdomain.com. 60	IN	A	6.6.6.0

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Wed Nov 08 13:52:40 +04 2023
;; MSG SIZE  rcvd: 80

```
### Many bogus A records and legit A record (afuzz2)
Respond with many bogus A records containing byte values starting from 0 up to 255 max, followed by a legitimate answer (proper A record) in the end.

<table>
<tr><td>format:</td><td>afuzz2.&lt;NUMBER-OF-RECORDS-0-256>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig afuzz2.256.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig afuzz2anything.10.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig afuzz2.256.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> afuzz2.256.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 35958
;; flags: qr aa; QUERY: 1, ANSWER: 257, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;afuzz2.256.yourdomain.com.	IN	A

;; ANSWER SECTION:
af\000zz2.256.yourdomain.com. 60 IN	A	6.6.6.0
af\001zz2.256.yourdomain.com. 60 IN	A	6.6.6.1
af\002zz2.256.yourdomain.com. 60 IN	A	6.6.6.2
af\003zz2.256.yourdomain.com. 60 IN	A	6.6.6.3
af\004zz2.256.yourdomain.com. 60 IN	A	6.6.6.4
af\005zz2.256.yourdomain.com. 60 IN	A	6.6.6.5
af\006zz2.256.yourdomain.com. 60 IN	A	6.6.6.6
af\007zz2.256.yourdomain.com. 60 IN	A	6.6.6.7
af\008zz2.256.yourdomain.com. 60 IN	A	6.6.6.8
af\009zz2.256.yourdomain.com. 60 IN	A	6.6.6.9
af\010zz2.256.yourdomain.com. 60 IN	A	6.6.6.10
af\011zz2.256.yourdomain.com. 60 IN	A	6.6.6.11
af\012zz2.256.yourdomain.com. 60 IN	A	6.6.6.12
af\013zz2.256.yourdomain.com. 60 IN	A	6.6.6.13
af\014zz2.256.yourdomain.com. 60 IN	A	6.6.6.14
af\015zz2.256.yourdomain.com. 60 IN	A	6.6.6.15
af\016zz2.256.yourdomain.com. 60 IN	A	6.6.6.16
af\017zz2.256.yourdomain.com. 60 IN	A	6.6.6.17
af\018zz2.256.yourdomain.com. 60 IN	A	6.6.6.18
af\019zz2.256.yourdomain.com. 60 IN	A	6.6.6.19
af\020zz2.256.yourdomain.com. 60 IN	A	6.6.6.20
af\021zz2.256.yourdomain.com. 60 IN	A	6.6.6.21
af\022zz2.256.yourdomain.com. 60 IN	A	6.6.6.22
af\023zz2.256.yourdomain.com. 60 IN	A	6.6.6.23
af\024zz2.256.yourdomain.com. 60 IN	A	6.6.6.24
af\025zz2.256.yourdomain.com. 60 IN	A	6.6.6.25
af\026zz2.256.yourdomain.com. 60 IN	A	6.6.6.26
af\027zz2.256.yourdomain.com. 60 IN	A	6.6.6.27
af\028zz2.256.yourdomain.com. 60 IN	A	6.6.6.28
af\029zz2.256.yourdomain.com. 60 IN	A	6.6.6.29
af\030zz2.256.yourdomain.com. 60 IN	A	6.6.6.30
af\031zz2.256.yourdomain.com. 60 IN	A	6.6.6.31
af\032zz2.256.yourdomain.com. 60 IN	A	6.6.6.32
af!zz2.256.yourdomain.com. 60	IN	A	6.6.6.33
af\"zz2.256.yourdomain.com. 60	IN	A	6.6.6.34
af#zz2.256.yourdomain.com. 60	IN	A	6.6.6.35
af\$zz2.256.yourdomain.com. 60	IN	A	6.6.6.36
af%zz2.256.yourdomain.com. 60	IN	A	6.6.6.37
af&zz2.256.yourdomain.com. 60	IN	A	6.6.6.38
af'zz2.256.yourdomain.com. 60	IN	A	6.6.6.39
af\(zz2.256.yourdomain.com. 60	IN	A	6.6.6.40
af\)zz2.256.yourdomain.com. 60	IN	A	6.6.6.41
af*zz2.256.yourdomain.com. 60	IN	A	6.6.6.42
af+zz2.256.yourdomain.com. 60	IN	A	6.6.6.43
af,zz2.256.yourdomain.com. 60	IN	A	6.6.6.44
af-zz2.256.yourdomain.com. 60	IN	A	6.6.6.45
af\.zz2.256.yourdomain.com. 60	IN	A	6.6.6.46
af/zz2.256.yourdomain.com. 60	IN	A	6.6.6.47
af0zz2.256.yourdomain.com. 60	IN	A	6.6.6.48
af1zz2.256.yourdomain.com. 60	IN	A	6.6.6.49
af2zz2.256.yourdomain.com. 60	IN	A	6.6.6.50
af3zz2.256.yourdomain.com. 60	IN	A	6.6.6.51
af4zz2.256.yourdomain.com. 60	IN	A	6.6.6.52
af5zz2.256.yourdomain.com. 60	IN	A	6.6.6.53
af6zz2.256.yourdomain.com. 60	IN	A	6.6.6.54
af7zz2.256.yourdomain.com. 60	IN	A	6.6.6.55
af8zz2.256.yourdomain.com. 60	IN	A	6.6.6.56
af9zz2.256.yourdomain.com. 60	IN	A	6.6.6.57
af:zz2.256.yourdomain.com. 60	IN	A	6.6.6.58
af\;zz2.256.yourdomain.com. 60	IN	A	6.6.6.59
af<zz2.256.yourdomain.com. 60	IN	A	6.6.6.60
af=zz2.256.yourdomain.com. 60	IN	A	6.6.6.61
af>zz2.256.yourdomain.com. 60	IN	A	6.6.6.62
af?zz2.256.yourdomain.com. 60	IN	A	6.6.6.63
af\@zz2.256.yourdomain.com. 60	IN	A	6.6.6.64
afAzz2.256.yourdomain.com. 60	IN	A	6.6.6.65
afBzz2.256.yourdomain.com. 60	IN	A	6.6.6.66
afCzz2.256.yourdomain.com. 60	IN	A	6.6.6.67
afDzz2.256.yourdomain.com. 60	IN	A	6.6.6.68
afEzz2.256.yourdomain.com. 60	IN	A	6.6.6.69
afFzz2.256.yourdomain.com. 60	IN	A	6.6.6.70
afGzz2.256.yourdomain.com. 60	IN	A	6.6.6.71
afHzz2.256.yourdomain.com. 60	IN	A	6.6.6.72
afIzz2.256.yourdomain.com. 60	IN	A	6.6.6.73
afJzz2.256.yourdomain.com. 60	IN	A	6.6.6.74
afKzz2.256.yourdomain.com. 60	IN	A	6.6.6.75
afLzz2.256.yourdomain.com. 60	IN	A	6.6.6.76
afMzz2.256.yourdomain.com. 60	IN	A	6.6.6.77
afNzz2.256.yourdomain.com. 60	IN	A	6.6.6.78
afOzz2.256.yourdomain.com. 60	IN	A	6.6.6.79
afPzz2.256.yourdomain.com. 60	IN	A	6.6.6.80
afQzz2.256.yourdomain.com. 60	IN	A	6.6.6.81
afRzz2.256.yourdomain.com. 60	IN	A	6.6.6.82
afSzz2.256.yourdomain.com. 60	IN	A	6.6.6.83
afTzz2.256.yourdomain.com. 60	IN	A	6.6.6.84
afUzz2.256.yourdomain.com. 60	IN	A	6.6.6.85
afVzz2.256.yourdomain.com. 60	IN	A	6.6.6.86
afWzz2.256.yourdomain.com. 60	IN	A	6.6.6.87
afXzz2.256.yourdomain.com. 60	IN	A	6.6.6.88
afYzz2.256.yourdomain.com. 60	IN	A	6.6.6.89
afZzz2.256.yourdomain.com. 60	IN	A	6.6.6.90
af[zz2.256.yourdomain.com. 60	IN	A	6.6.6.91
af\\zz2.256.yourdomain.com. 60	IN	A	6.6.6.92
af]zz2.256.yourdomain.com. 60	IN	A	6.6.6.93
af^zz2.256.yourdomain.com. 60	IN	A	6.6.6.94
af_zz2.256.yourdomain.com. 60	IN	A	6.6.6.95
af`zz2.256.yourdomain.com. 60	IN	A	6.6.6.96
afazz2.256.yourdomain.com. 60	IN	A	6.6.6.97
afbzz2.256.yourdomain.com. 60	IN	A	6.6.6.98
afczz2.256.yourdomain.com. 60	IN	A	6.6.6.99
afdzz2.256.yourdomain.com. 60	IN	A	6.6.6.100
afezz2.256.yourdomain.com. 60	IN	A	6.6.6.101
affzz2.256.yourdomain.com. 60	IN	A	6.6.6.102
afgzz2.256.yourdomain.com. 60	IN	A	6.6.6.103
afhzz2.256.yourdomain.com. 60	IN	A	6.6.6.104
afizz2.256.yourdomain.com. 60	IN	A	6.6.6.105
afjzz2.256.yourdomain.com. 60	IN	A	6.6.6.106
afkzz2.256.yourdomain.com. 60	IN	A	6.6.6.107
aflzz2.256.yourdomain.com. 60	IN	A	6.6.6.108
afmzz2.256.yourdomain.com. 60	IN	A	6.6.6.109
afnzz2.256.yourdomain.com. 60	IN	A	6.6.6.110
afozz2.256.yourdomain.com. 60	IN	A	6.6.6.111
afpzz2.256.yourdomain.com. 60	IN	A	6.6.6.112
afqzz2.256.yourdomain.com. 60	IN	A	6.6.6.113
afrzz2.256.yourdomain.com. 60	IN	A	6.6.6.114
afszz2.256.yourdomain.com. 60	IN	A	6.6.6.115
aftzz2.256.yourdomain.com. 60	IN	A	6.6.6.116
afuzz2.256.yourdomain.com. 60	IN	A	6.6.6.117
afvzz2.256.yourdomain.com. 60	IN	A	6.6.6.118
afwzz2.256.yourdomain.com. 60	IN	A	6.6.6.119
afxzz2.256.yourdomain.com. 60	IN	A	6.6.6.120
afyzz2.256.yourdomain.com. 60	IN	A	6.6.6.121
afzzz2.256.yourdomain.com. 60	IN	A	6.6.6.122
af{zz2.256.yourdomain.com. 60	IN	A	6.6.6.123
af|zz2.256.yourdomain.com. 60	IN	A	6.6.6.124
af}zz2.256.yourdomain.com. 60	IN	A	6.6.6.125
af~zz2.256.yourdomain.com. 60	IN	A	6.6.6.126
af\127zz2.256.yourdomain.com. 60 IN	A	6.6.6.127
af\128zz2.256.yourdomain.com. 60 IN	A	6.6.6.128
af\129zz2.256.yourdomain.com. 60 IN	A	6.6.6.129
af\130zz2.256.yourdomain.com. 60 IN	A	6.6.6.130
af\131zz2.256.yourdomain.com. 60 IN	A	6.6.6.131
af\132zz2.256.yourdomain.com. 60 IN	A	6.6.6.132
af\133zz2.256.yourdomain.com. 60 IN	A	6.6.6.133
af\134zz2.256.yourdomain.com. 60 IN	A	6.6.6.134
af\135zz2.256.yourdomain.com. 60 IN	A	6.6.6.135
af\136zz2.256.yourdomain.com. 60 IN	A	6.6.6.136
af\137zz2.256.yourdomain.com. 60 IN	A	6.6.6.137
af\138zz2.256.yourdomain.com. 60 IN	A	6.6.6.138
af\139zz2.256.yourdomain.com. 60 IN	A	6.6.6.139
af\140zz2.256.yourdomain.com. 60 IN	A	6.6.6.140
af\141zz2.256.yourdomain.com. 60 IN	A	6.6.6.141
af\142zz2.256.yourdomain.com. 60 IN	A	6.6.6.142
af\143zz2.256.yourdomain.com. 60 IN	A	6.6.6.143
af\144zz2.256.yourdomain.com. 60 IN	A	6.6.6.144
af\145zz2.256.yourdomain.com. 60 IN	A	6.6.6.145
af\146zz2.256.yourdomain.com. 60 IN	A	6.6.6.146
af\147zz2.256.yourdomain.com. 60 IN	A	6.6.6.147
af\148zz2.256.yourdomain.com. 60 IN	A	6.6.6.148
af\149zz2.256.yourdomain.com. 60 IN	A	6.6.6.149
af\150zz2.256.yourdomain.com. 60 IN	A	6.6.6.150
af\151zz2.256.yourdomain.com. 60 IN	A	6.6.6.151
af\152zz2.256.yourdomain.com. 60 IN	A	6.6.6.152
af\153zz2.256.yourdomain.com. 60 IN	A	6.6.6.153
af\154zz2.256.yourdomain.com. 60 IN	A	6.6.6.154
af\155zz2.256.yourdomain.com. 60 IN	A	6.6.6.155
af\156zz2.256.yourdomain.com. 60 IN	A	6.6.6.156
af\157zz2.256.yourdomain.com. 60 IN	A	6.6.6.157
af\158zz2.256.yourdomain.com. 60 IN	A	6.6.6.158
af\159zz2.256.yourdomain.com. 60 IN	A	6.6.6.159
af\160zz2.256.yourdomain.com. 60 IN	A	6.6.6.160
af\161zz2.256.yourdomain.com. 60 IN	A	6.6.6.161
af\162zz2.256.yourdomain.com. 60 IN	A	6.6.6.162
af\163zz2.256.yourdomain.com. 60 IN	A	6.6.6.163
af\164zz2.256.yourdomain.com. 60 IN	A	6.6.6.164
af\165zz2.256.yourdomain.com. 60 IN	A	6.6.6.165
af\166zz2.256.yourdomain.com. 60 IN	A	6.6.6.166
af\167zz2.256.yourdomain.com. 60 IN	A	6.6.6.167
af\168zz2.256.yourdomain.com. 60 IN	A	6.6.6.168
af\169zz2.256.yourdomain.com. 60 IN	A	6.6.6.169
af\170zz2.256.yourdomain.com. 60 IN	A	6.6.6.170
af\171zz2.256.yourdomain.com. 60 IN	A	6.6.6.171
af\172zz2.256.yourdomain.com. 60 IN	A	6.6.6.172
af\173zz2.256.yourdomain.com. 60 IN	A	6.6.6.173
af\174zz2.256.yourdomain.com. 60 IN	A	6.6.6.174
af\175zz2.256.yourdomain.com. 60 IN	A	6.6.6.175
af\176zz2.256.yourdomain.com. 60 IN	A	6.6.6.176
af\177zz2.256.yourdomain.com. 60 IN	A	6.6.6.177
af\178zz2.256.yourdomain.com. 60 IN	A	6.6.6.178
af\179zz2.256.yourdomain.com. 60 IN	A	6.6.6.179
af\180zz2.256.yourdomain.com. 60 IN	A	6.6.6.180
af\181zz2.256.yourdomain.com. 60 IN	A	6.6.6.181
af\182zz2.256.yourdomain.com. 60 IN	A	6.6.6.182
af\183zz2.256.yourdomain.com. 60 IN	A	6.6.6.183
af\184zz2.256.yourdomain.com. 60 IN	A	6.6.6.184
af\185zz2.256.yourdomain.com. 60 IN	A	6.6.6.185
af\186zz2.256.yourdomain.com. 60 IN	A	6.6.6.186
af\187zz2.256.yourdomain.com. 60 IN	A	6.6.6.187
af\188zz2.256.yourdomain.com. 60 IN	A	6.6.6.188
af\189zz2.256.yourdomain.com. 60 IN	A	6.6.6.189
af\190zz2.256.yourdomain.com. 60 IN	A	6.6.6.190
af\191zz2.256.yourdomain.com. 60 IN	A	6.6.6.191
af\192zz2.256.yourdomain.com. 60 IN	A	6.6.6.192
af\193zz2.256.yourdomain.com. 60 IN	A	6.6.6.193
af\194zz2.256.yourdomain.com. 60 IN	A	6.6.6.194
af\195zz2.256.yourdomain.com. 60 IN	A	6.6.6.195
af\196zz2.256.yourdomain.com. 60 IN	A	6.6.6.196
af\197zz2.256.yourdomain.com. 60 IN	A	6.6.6.197
af\198zz2.256.yourdomain.com. 60 IN	A	6.6.6.198
af\199zz2.256.yourdomain.com. 60 IN	A	6.6.6.199
af\200zz2.256.yourdomain.com. 60 IN	A	6.6.6.200
af\201zz2.256.yourdomain.com. 60 IN	A	6.6.6.201
af\202zz2.256.yourdomain.com. 60 IN	A	6.6.6.202
af\203zz2.256.yourdomain.com. 60 IN	A	6.6.6.203
af\204zz2.256.yourdomain.com. 60 IN	A	6.6.6.204
af\205zz2.256.yourdomain.com. 60 IN	A	6.6.6.205
af\206zz2.256.yourdomain.com. 60 IN	A	6.6.6.206
af\207zz2.256.yourdomain.com. 60 IN	A	6.6.6.207
af\208zz2.256.yourdomain.com. 60 IN	A	6.6.6.208
af\209zz2.256.yourdomain.com. 60 IN	A	6.6.6.209
af\210zz2.256.yourdomain.com. 60 IN	A	6.6.6.210
af\211zz2.256.yourdomain.com. 60 IN	A	6.6.6.211
af\212zz2.256.yourdomain.com. 60 IN	A	6.6.6.212
af\213zz2.256.yourdomain.com. 60 IN	A	6.6.6.213
af\214zz2.256.yourdomain.com. 60 IN	A	6.6.6.214
af\215zz2.256.yourdomain.com. 60 IN	A	6.6.6.215
af\216zz2.256.yourdomain.com. 60 IN	A	6.6.6.216
af\217zz2.256.yourdomain.com. 60 IN	A	6.6.6.217
af\218zz2.256.yourdomain.com. 60 IN	A	6.6.6.218
af\219zz2.256.yourdomain.com. 60 IN	A	6.6.6.219
af\220zz2.256.yourdomain.com. 60 IN	A	6.6.6.220
af\221zz2.256.yourdomain.com. 60 IN	A	6.6.6.221
af\222zz2.256.yourdomain.com. 60 IN	A	6.6.6.222
af\223zz2.256.yourdomain.com. 60 IN	A	6.6.6.223
af\224zz2.256.yourdomain.com. 60 IN	A	6.6.6.224
af\225zz2.256.yourdomain.com. 60 IN	A	6.6.6.225
af\226zz2.256.yourdomain.com. 60 IN	A	6.6.6.226
af\227zz2.256.yourdomain.com. 60 IN	A	6.6.6.227
af\228zz2.256.yourdomain.com. 60 IN	A	6.6.6.228
af\229zz2.256.yourdomain.com. 60 IN	A	6.6.6.229
af\230zz2.256.yourdomain.com. 60 IN	A	6.6.6.230
af\231zz2.256.yourdomain.com. 60 IN	A	6.6.6.231
af\232zz2.256.yourdomain.com. 60 IN	A	6.6.6.232
af\233zz2.256.yourdomain.com. 60 IN	A	6.6.6.233
af\234zz2.256.yourdomain.com. 60 IN	A	6.6.6.234
af\235zz2.256.yourdomain.com. 60 IN	A	6.6.6.235
af\236zz2.256.yourdomain.com. 60 IN	A	6.6.6.236
af\237zz2.256.yourdomain.com. 60 IN	A	6.6.6.237
af\238zz2.256.yourdomain.com. 60 IN	A	6.6.6.238
af\239zz2.256.yourdomain.com. 60 IN	A	6.6.6.239
af\240zz2.256.yourdomain.com. 60 IN	A	6.6.6.240
af\241zz2.256.yourdomain.com. 60 IN	A	6.6.6.241
af\242zz2.256.yourdomain.com. 60 IN	A	6.6.6.242
af\243zz2.256.yourdomain.com. 60 IN	A	6.6.6.243
af\244zz2.256.yourdomain.com. 60 IN	A	6.6.6.244
af\245zz2.256.yourdomain.com. 60 IN	A	6.6.6.245
af\246zz2.256.yourdomain.com. 60 IN	A	6.6.6.246
af\247zz2.256.yourdomain.com. 60 IN	A	6.6.6.247
af\248zz2.256.yourdomain.com. 60 IN	A	6.6.6.248
af\249zz2.256.yourdomain.com. 60 IN	A	6.6.6.249
af\250zz2.256.yourdomain.com. 60 IN	A	6.6.6.250
af\251zz2.256.yourdomain.com. 60 IN	A	6.6.6.251
af\252zz2.256.yourdomain.com. 60 IN	A	6.6.6.252
af\253zz2.256.yourdomain.com. 60 IN	A	6.6.6.253
af\254zz2.256.yourdomain.com. 60 IN	A	6.6.6.254
af\255zz2.256.yourdomain.com. 60 IN	A	6.6.6.255
afuzz2.256.yourdomain.com. 60	IN	A	2.3.4.5

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Wed Nov 08 13:53:56 +04 2023
;; MSG SIZE  rcvd: 10580

```
### Arbitrary record type with random data (customtype)
Respond with arbitrary DNS record type e.g., A, NS, CNAME, MX, TXT, SOA by specifying the type code in decimal. The content will be a sample random data. Please note not all record types are implemented.

<table>
<tr><td>format:</td><td>customtype&lt;ANYTHING>.&lt;DNS-TYPE-IN-DECIMAL>.yourdomain.com</td></tr>
<tr><td>remark:</td><td>Under development</td></tr>
<tr><td>example:</td><td><code>dig customtype.1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig customtype.5.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig customtype.1.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> customtype.1.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 37229
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;customtype.1.yourdomain.com.	IN	A

;; ANSWER SECTION:
customtype.1.yourdomain.com. 60	IN	A	61.18.164.138

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:35:02 +04 2023
;; MSG SIZE  rcvd: 88
```

##
Go back to [menu](#polardns-catalogue---general-features).

