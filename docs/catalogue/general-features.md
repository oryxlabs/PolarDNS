# PolarDNS catalogue - General features
1. [General features](general-features.md)
	- [Always resolve to IP (always)](#always-resolve-to-ip-always)
	- [CNAME alias chain (chain)](#cname-alias-chain-chain)
	- [CNAME alias chain - 3 records (schain)](#cname-alias-chain---3-records-schain)
	- [DNAME alias chain (dchain)](#dname-alias-chain-dchain)
	- [Chunked CNAME aliases (chunkedcnames)](#chunked-cname-aliases-chunkedcnames)
	- [Cut A record from the end (cutabuf)](#cut-a-record-from-the-end-cutabuf)
	- [Cut CNAME record from the end (cutcnamebuf)](#cut-cname-record-from-the-end-cutcnamebuf)
	- [TXT record with multiple text strings (bigtxt)](#txt-record-with-multiple-text-strings-bigtxt)
	- [TXT record with multiple binary strings (bigbintxt)](#txt-record-with-multiple-binary-strings-bigbintxt)
	- [Many TXT records with random text (manytxt)](#many-txt-records-with-random-text-manytxt)
	- [Many TXT records with binary data (manybintxt)](#many-txt-records-with-binary-data-manybintxt)
	- [Arbitrary record type with random data (customtype)](#arbitrary-record-type-with-random-data-customtype)
1. [Response modifiers](response-modifiers.md)
1. [CNAME fuzzing](cname-fuzzing.md)
1. [Bad compression](bad-compression.md)
1. [Empty responses](empty-responses.md)
1. [Record injections](record-injections.md)

##
### Always resolve to IP (always)
Always respond with A record (2.3.4.5).

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
### CNAME alias chain (chain)
Respond with an incremented CNAME record.

<table>
<tr><td>format:</td><td>chain&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig chain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig chain123456.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig chain123456.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> chain123456.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 49493
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;chain123456.yourdomain.com.	IN	A

;; ANSWER SECTION:
chain123456.yourdomain.com. 60	IN	CNAME	chain123457.yourdomain.com.

;; Query time: 4 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Fri Nov 03 14:30:51 +04 2023
;; MSG SIZE  rcvd: 110

```
### CNAME alias chain - 3 records (schain)
Respond with 3 random CNAME records (schain####.yourdomain.com).

<table>
<tr><td>format:</td><td>schain&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig schain123456.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig schain123456.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> schain123456.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 65398
;; flags: qr aa; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;schain123456.yourdomain.com.	IN	A

;; ANSWER SECTION:
schain123456.yourdomain.com. 60	IN	CNAME	schain600556.yourdomain.com.
schain123456.yourdomain.com. 60	IN	CNAME	schain916228.yourdomain.com.
schain123456.yourdomain.com. 60	IN	CNAME	schain381071.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Fri Nov 03 14:30:51 +04 2023
;; MSG SIZE  rcvd: 249

```
### DNAME alias chain (dchain)
Respond with an incremented DNAME record.

<table>
<tr><td>format:</td><td>dchain&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig dchain123456.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig dchain123456.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> dchain123456.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 14205
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;dchain123456.yourdomain.com.	IN	A

;; ANSWER SECTION:
dchain123456.yourdomain.com. 60	IN	DNAME	dchain123457.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Fri Nov 03 14:30:51 +04 2023
;; MSG SIZE  rcvd: 113

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

