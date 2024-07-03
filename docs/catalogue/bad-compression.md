# PolarDNS catalogue - Bad compression
1. [General features](general-features.md)
1. [Aliases, loops and chains](aliases-loops-and-chains.md)
1. [Response modifiers](response-modifiers.md)
1. [CNAME fuzzing](cname-fuzzing.md)
1. [Bad compression](bad-compression.md)
	- [Custom offset in Name field (badcompress1)](#custom-offset-in-name-field-badcompress1)
	- [Custom offset in CNAME field (badcompress2)](#custom-offset-in-cname-field-badcompress2)
	- [Forward pointer in Name field (badcompressfwptr1)](#forward-pointer-in-name-field-badcompressfwptr1)
	- [Double compression pointer (badcompressfwptr2)](#double-compression-pointer-badcompressfwptr2)
	- [Pointer loop in Name field 1 (badcompressloop1)](#pointer-loop-in-name-field-1-badcompressloop1)
	- [Pointer loop in Name field 2 (badcompressloop2)](#pointer-loop-in-name-field-2-badcompressloop2)
	- [Double pointer loop (badcompressloop3)](#double-pointer-loop-badcompressloop3)
	- [Pointer loop in CNAME field 1 (badcompressloop4)](#pointer-loop-in-cname-field-1-badcompressloop4)
	- [Pointer loop in CNAME field 2 (badcompressloop5)](#pointer-loop-in-cname-field-2-badcompressloop5)
	- [Compression in the middle of CNAME (badcompressmid1)](#compression-in-the-middle-of-cname-badcompressmid1)
1. [Empty responses](empty-responses.md)
1. [Record injections](record-injections.md)

Scenarios of bad DNS compression schemes.

##
### Custom offset in Name field (badcompress1)
Respond with CNAME (always&lt;RANDOM>.yourdomain.com), where you can specify an arbitrary offset in the answer Name field compression pointer.

<table>
<tr><td>format:</td><td>badcompress1.&lt;OFFSET>.yourdomain.com</td></tr>
<tr><td>remark:</td><td>OFFSET of 12 will point correctly to the beginning to the domain name in the query</td></tr>
<tr><td>example:</td><td><code>dig badcompress1.12.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig badcompress1whatever.12.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig badcompress1.12.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> badcompress1.12.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 64723
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;badcompress1.12.yourdomain.com.	IN	A

;; ANSWER SECTION:
badcompress1.12.yourdomain.com.	60 IN	CNAME	always15141.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:19 +04 2023
;; MSG SIZE  rcvd: 88
```
### Custom offset in CNAME field (badcompress2)
Respond with CNAME (abc.badcompress2.yourdomain.com), where you can specify an arbitrary offset in the answer CNAME field compression pointer.

<table>
<tr><td>format:</td><td>badcompress2.&lt;OFFSET>.yourdomain.com</td></tr>
<tr><td>remark:</td><td>OFFSET of 12 will point correctly to the beginning to the domain name in the query</td></tr>
<tr><td>example:</td><td><code>dig badcompress2.12.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig badcompress2whatever.12.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig badcompress2.12.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> badcompress2.12.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 20964
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;badcompress2.12.yourdomain.com.	IN	A

;; ANSWER SECTION:
badcompress2.12.yourdomain.com.	60 IN	CNAME	abc.badcompress2.12.yourdomain.com.

;; Query time: 4 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:19 +04 2023
;; MSG SIZE  rcvd: 66
```
### Forward pointer in Name field (badcompressfwptr1)
Respond with CNAME (abc.badcompressfwptr1.yourdomain.com) and use a forward pointer in the answer Name field to point to the end (the actual CNAME), where there is "abc" + a pointer to the beginning (to the domain name in the query).

<table>
<tr><td>format:</td><td>badcompressfwptr1.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig badcompressfwptr1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig badcompressfwptr1whatever.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig badcompressfwptr1.yourdomain.com @127.0.0.1
;; Got bad packet: bad compression pointer
68 bytes
bf c4 84 00 00 01 00 01 00 00 00 00 11 62 61 64          .............bad
63 6f 6d 70 72 65 73 73 66 77 70 74 72 31 0a 79          compressfwptr1.y
6f 75 72 64 6f 6d 61 69 6e 03 63 6f 6d 00 00 01          ourdomain.com...
00 01 c0 3e 00 05 00 01 00 00 00 3c 00 06 03 61          ...>.......<...a
62 63 c0 0c                                              bc..
```
### Double compression pointer (badcompressfwptr2)
Respond with CNAME (abc.badcompressfwptr2.yourdomain.com) and use a forward pointer in the answer Name field to point to the end (the actual CNAME). But, skip the "abc" portion so that it will point directly to another pointer pointing to the beginning (to the domain name in the query).

<table>
<tr><td>format:</td><td>badcompressfwptr2.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig badcompressfwptr2.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig badcompressfwptr2whatever.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig badcompressfwptr2.yourdomain.com @127.0.0.1
;; Got bad packet: bad compression pointer
68 bytes
df 28 84 00 00 01 00 01 00 00 00 00 11 62 61 64          .(...........bad
63 6f 6d 70 72 65 73 73 66 77 70 74 72 32 0a 79          compressfwptr2.y
6f 75 72 64 6f 6d 61 69 6e 03 63 6f 6d 00 00 01          ourdomain.com...
00 01 c0 42 00 05 00 01 00 00 00 3c 00 06 03 61          ...B.......<...a
62 63 c0 0c                                              bc..
```
### Pointer loop in Name field 1 (badcompressloop1)
Respond with CNAME, where the answer Name field only contains a pointer to itself (=> a loop).

<table>
<tr><td>format:</td><td>badcompressloop1.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig badcompressloop1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig badcompressloop1whatever.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig badcompressloop1.yourdomain.com @127.0.0.1
;; Got bad packet: bad compression pointer
89 bytes
6c c9 84 00 00 01 00 01 00 00 00 00 10 62 61 64          l............bad
63 6f 6d 70 72 65 73 73 6c 6f 6f 70 31 0a 79 6f          compressloop1.yo
75 72 64 6f 6d 61 69 6e 03 63 6f 6d 00 00 01 00          urdomain.com....
01 c0 31 00 05 00 01 00 00 00 3c 00 1c 0b 61 6c          ..1.......<...al
77 61 79 73 32 39 35 36 33 0a 79 6f 75 72 64 6f          ways29563.yourdo
6d 61 69 6e 03 63 6f 6d 00                               main.com.
```
### Pointer loop in Name field 2 (badcompressloop2)
Respond with CNAME, where the answer Name field only contains "abc" and a pointer to the beginning of the "abc" (=> a loop).

<table>
<tr><td>format:</td><td>badcompressloop2.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig badcompressloop2.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig badcompressloop2whatever.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig badcompressloop2.yourdomain.com @127.0.0.1
;; Got bad packet: bad compression pointer
93 bytes
11 f3 84 00 00 01 00 01 00 00 00 00 10 62 61 64          .............bad
63 6f 6d 70 72 65 73 73 6c 6f 6f 70 32 0a 79 6f          compressloop2.yo
75 72 64 6f 6d 61 69 6e 03 63 6f 6d 00 00 01 00          urdomain.com....
01 03 61 62 63 c0 31 00 05 00 01 00 00 00 3c 00          ..abc.1.......<.
1c 0b 61 6c 77 61 79 73 36 38 38 35 39 0a 79 6f          ..always68859.yo
75 72 64 6f 6d 61 69 6e 03 63 6f 6d 00                   urdomain.com.
```
### Double pointer loop (badcompressloop3)
Respond with CNAME, use a forward pointer in the answer Name field pointing to the end (the actual CNAME). The actual CNAME points to the answer Name field, effectively creating a loop.

<table>
<tr><td>format:</td><td>badcompressloop3.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig badcompressloop3.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig badcompressloop3whatever.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig badcompressloop3.yourdomain.com @127.0.0.1
;; Got bad packet: bad compression pointer
67 bytes
e1 4c 84 00 00 01 00 01 00 00 00 00 10 62 61 64          .L...........bad
63 6f 6d 70 72 65 73 73 6c 6f 6f 70 33 0a 79 6f          compressloop3.yo
75 72 64 6f 6d 61 69 6e 03 63 6f 6d 00 00 01 00          urdomain.com....
01 c0 3d 00 05 00 01 00 00 00 3c 00 06 03 61 62          ..=.......<...ab
63 c0 31                                                 c.1
```
### Pointer loop in CNAME field 1 (badcompressloop4)
Respond with CNAME, where the CNAME only contains a pointer to itself (=> a loop).

<table>
<tr><td>format:</td><td>badcompressloop4.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig badcompressloop4.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig badcompressloop4whatever.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig badcompressloop4.yourdomain.com @127.0.0.1
;; Got bad packet: bad compression pointer
63 bytes
c0 c6 84 00 00 01 00 01 00 00 00 00 10 62 61 64          .............bad
63 6f 6d 70 72 65 73 73 6c 6f 6f 70 34 0a 79 6f          compressloop4.yo
75 72 64 6f 6d 61 69 6e 03 63 6f 6d 00 00 01 00          urdomain.com....
01 c0 0c 00 05 00 01 00 00 00 3c 00 02 c0 3d             ..........<...=
```
### Pointer loop in CNAME field 2 (badcompressloop5)
Respond with CNAME, where the CNAME only contains "abc" + a pointer to the beginning of the "abc" (=> a loop).

<table>
<tr><td>format:</td><td>badcompressloop5.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig badcompressloop5.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig badcompressloop5whatever.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig badcompressloop5.yourdomain.com @127.0.0.1
;; Got bad packet: bad compression pointer
67 bytes
26 37 84 00 00 01 00 01 00 00 00 00 10 62 61 64          &7...........bad
63 6f 6d 70 72 65 73 73 6c 6f 6f 70 35 0a 79 6f          compressloop5.yo
75 72 64 6f 6d 61 69 6e 03 63 6f 6d 00 00 01 00          urdomain.com....
01 c0 0c 00 05 00 01 00 00 00 3c 00 06 03 61 62          ..........<...ab
63 c0 3d                                                 c.=
```
### Compression in the middle of CNAME (badcompressmid1)
Respond with CNAME, where the CNAME contains "abc" + a pointer to the query name + additional "hello" string. Data length indicates the "hello" string should be included in the CNAME.

<table>
<tr><td>format:</td><td>badcompressmid1.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig badcompressmid1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig badcompressmid1whatever.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig badcompressmid1.yourdomain.com @127.0.0.1
;; Got bad packet: extra input data
73 bytes
98 93 84 00 00 01 00 01 00 00 00 00 0f 62 61 64          .............bad
63 6f 6d 70 72 65 73 73 6d 69 64 31 0a 79 6f 75          compressmid1.you
72 64 6f 6d 61 69 6e 03 63 6f 6d 00 00 01 00 01          rdomain.com.....
c0 0c 00 05 00 01 00 00 00 3c 00 0d 03 61 62 63          .........<...abc
c0 0c 05 68 65 6c 6c 6f 00                               ...hello.
```

##
Go back to [menu](#polardns-catalogue---bad-compression).

