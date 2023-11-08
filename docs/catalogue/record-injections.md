# PolarDNS catalogue - Record injections
1. [General features](general-features.md)
1. [Response modifiers](response-modifiers.md)
1. [CNAME fuzzing](cname-fuzzing.md)
1. [Bad compression](bad-compression.md)
1. [Empty responses](empty-responses.md)
1. [Record injections](record-injections.md)
	- [inj01](#inj01)
	- [inj02](#inj02)
	- [inj03](#inj03)
	- [inj04](#inj04)
	- [inj05](#inj05)
	- [inj06](#inj06)
	- [inj07](#inj07)
	- [inj08](#inj08)
	- [inj09](#inj09)
	- [inj10](#inj10)
	- [inj11](#inj11)
	- [inj12](#inj12)
	- [inj13](#inj13)
	- [inj14](#inj14)

These injection scenarios typically provide a legitimate answer as the response, but also include an injected additional information, testing whether the resolver will cache the injected information or not.

##
### inj01
Injection test 1: Respond with legit CNAME (end.yourdomain.com) + injected A record (inj1poc.yourdomain.com -> 6.6.6.6).

<table>
<tr><td>format:</td><td>inj01.[replq].[addq].[3rdparty].yourdomain.com</td></tr>
<tr><td>remark:</td><td>replq (optional) - will replace the question in the response with inj1poc.yourdomain.com</td></tr>
<tr><td>remark:</td><td>addq (optional) - will add additional question for inj1poc.yourdomain.com in the response</td></tr>
<tr><td>remark:</td><td>3rdparty (optional) - will do injection for 3rd party (whatever.com), rather than yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig inj01.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig inj01.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> inj01.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 18296
;; flags: qr aa; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;inj01.yourdomain.com.		IN	A

;; ANSWER SECTION:
inj01.yourdomain.com.	60	IN	CNAME	end.yourdomain.com.
injected01.yourdomain.com. 60	IN	A	6.6.6.1

;; Query time: 4 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:19 +04 2023
;; MSG SIZE  rcvd: 131
```
### inj02
Injection test 2: Respond with injected A record (inj2poc.yourdomain.com -> 6.6.6.6) + legit CNAME (end.yourdomain.com).

<table>
<tr><td>format:</td><td>inj02.[replq].[addq].[3rdparty].yourdomain.com</td></tr>
<tr><td>remark:</td><td>replq (optional) - will replace the question in the response with inj2poc.yourdomain.com</td></tr>
<tr><td>remark:</td><td>addq (optional) - will add additional question for inj2poc.yourdomain.com in the response</td></tr>
<tr><td>remark:</td><td>3rdparty (optional) - will do injection for 3rd party (whatever.com), rather than yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig inj02.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig inj02.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> inj02.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2805
;; flags: qr aa; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;inj02.yourdomain.com.		IN	A

;; ANSWER SECTION:
injected02.yourdomain.com. 60	IN	A	6.6.6.2
inj02.yourdomain.com.	60	IN	CNAME	end.yourdomain.com.

;; Query time: 4 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:19 +04 2023
;; MSG SIZE  rcvd: 131
```
### inj03
Injection test 3: Respond with legit A record (1.2.3.4) + injected A record (inj3poc.yourdomain.com -> 6.6.6.6).

<table>
<tr><td>format:</td><td>inj03.[replq].[addq].yourdomain.com</td></tr>
<tr><td>remark:</td><td>replq (optional) - will replace the question in the response with inj3poc.yourdomain.com</td></tr>
<tr><td>remark:</td><td>addq (optional) - will add additional question for inj3poc.yourdomain.com in the response</td></tr>
<tr><td>remark:</td><td>3rdparty (optional) - will do injection for 3rd party (whatever.com), rather than yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig inj03.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig inj03.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> inj03.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 40820
;; flags: qr aa; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;inj03.yourdomain.com.		IN	A

;; ANSWER SECTION:
inj03.yourdomain.com.	60	IN	A	1.2.3.4
injected03.yourdomain.com. 60	IN	A	6.6.6.3

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:19 +04 2023
;; MSG SIZE  rcvd: 115
```
### inj04
Injection test 4: Respond with injected A record (inj4poc.yourdomain.com -> 6.6.6.6) + legit A record (1.2.3.4).

<table>
<tr><td>format:</td><td>inj04.[replq].[addq].[3rdparty].yourdomain.com</td></tr>
<tr><td>remark:</td><td>replq (optional) - will replace the question in the response with inj4poc.yourdomain.com</td></tr>
<tr><td>remark:</td><td>addq (optional) - will add additional question for inj4poc.yourdomain.com in the response</td></tr>
<tr><td>remark:</td><td>3rdparty (optional) - will do injection for 3rd party (whatever.com), rather than yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig inj04.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig inj04.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> inj04.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 29353
;; flags: qr aa; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;inj04.yourdomain.com.		IN	A

;; ANSWER SECTION:
injected04.yourdomain.com. 60	IN	A	6.6.6.4
inj04.yourdomain.com.	60	IN	A	1.2.3.4

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:19 +04 2023
;; MSG SIZE  rcvd: 115
```
### inj05
Injection test 5: Respond with CNAME (inj05poc.yourdomain.com) in all sections + inject also A record of it (inj05poc.yourdomain.com -> 6.6.6.6) in all sections.

<table>
<tr><td>format:</td><td>inj05.[replq].[addq].[3rdparty].yourdomain.com</td></tr>
<tr><td>remark:</td><td>replq (optional) - will replace the question in the response with inj05poc.yourdomain.com</td></tr>
<tr><td>remark:</td><td>addq (optional) - will add additional question for inj05poc.yourdomain.com in the response</td></tr>
<tr><td>remark:</td><td>3rdparty (optional) - will do injection for 3rd party (whatever.com), rather than yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig inj05.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig inj05.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> inj05.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4990
;; flags: qr aa; QUERY: 1, ANSWER: 2, AUTHORITY: 2, ADDITIONAL: 2

;; QUESTION SECTION:
;inj05.yourdomain.com.		IN	A

;; ANSWER SECTION:
inj05.yourdomain.com.	60	IN	CNAME	injected05.yourdomain.com.
injected05.yourdomain.com. 60	IN	A	6.6.6.5

;; AUTHORITY SECTION:
inj05.yourdomain.com.	60	IN	CNAME	injected05.yourdomain.com.
injected05.yourdomain.com. 60	IN	A	6.6.6.5

;; ADDITIONAL SECTION:
inj05.yourdomain.com.	60	IN	CNAME	injected05.yourdomain.com.
injected05.yourdomain.com. 60	IN	A	6.6.6.5

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:19 +04 2023
;; MSG SIZE  rcvd: 338
```
### inj06
Injection test 6: Respond with CNAME (inj06poc.yourdomain.com) in all sections + inject also AAAA record of it (inj06poc.yourdomain.com -> 6666:6666:6666:6666:6666:6666:6666:6666) in all sections.

<table>
<tr><td>format:</td><td>inj06.[replq].[addq].[3rdparty].yourdomain.com</td></tr>
<tr><td>remark:</td><td>replq (optional) - will replace the question in the response with inj06poc.yourdomain.com</td></tr>
<tr><td>remark:</td><td>addq (optional) - will add additional question for inj06poc.yourdomain.com in the response</td></tr>
<tr><td>remark:</td><td>3rdparty (optional) - will do injection for 3rd party (whatever.com), rather than yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig inj06.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig inj06.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> inj06.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 6246
;; flags: qr aa; QUERY: 1, ANSWER: 2, AUTHORITY: 2, ADDITIONAL: 2

;; QUESTION SECTION:
;inj06.yourdomain.com.		IN	A

;; ANSWER SECTION:
inj06.yourdomain.com.	60	IN	CNAME	injected06.yourdomain.com.
injected06.yourdomain.com. 60	IN	AAAA	6666:6666:6666:6666:6666:6666:6666:6666

;; AUTHORITY SECTION:
inj06.yourdomain.com.	60	IN	CNAME	injected06.yourdomain.com.
injected06.yourdomain.com. 60	IN	AAAA	6666:6666:6666:6666:6666:6666:6666:6666

;; ADDITIONAL SECTION:
inj06.yourdomain.com.	60	IN	CNAME	injected06.yourdomain.com.
injected06.yourdomain.com. 60	IN	AAAA	6666:6666:6666:6666:6666:6666:6666:6666

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:19 +04 2023
;; MSG SIZE  rcvd: 374
```
### inj07
Injection test 7: Respond only with injected A record (inj07poc.yourdomain.com -> 6.6.6.6).

<table>
<tr><td>format:</td><td>inj07.[replq].[addq].[3rdparty].yourdomain.com</td></tr>
<tr><td>remark:</td><td>replq (optional) - will replace the question in the response with inj07poc.yourdomain.com</td></tr>
<tr><td>remark:</td><td>addq (optional) - will add additional question for inj07poc.yourdomain.com in the response</td></tr>
<tr><td>remark:</td><td>3rdparty (optional) - will do injection for 3rd party (whatever.com), rather than yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig inj07.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig inj07.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> inj07.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7798
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;inj07.yourdomain.com.		IN	A

;; ANSWER SECTION:
injected07.yourdomain.com. 60	IN	A	6.6.6.7

;; Query time: 4 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:19 +04 2023
;; MSG SIZE  rcvd: 79
```
### inj08
Injection test 8: Respond only with injected A record (inj08poc.yourdomain.com -> 6.6.6.6) in all sections.

<table>
<tr><td>format:</td><td>inj08.[replq].[addq].[3rdparty].yourdomain.com</td></tr>
<tr><td>remark:</td><td>replq (optional) - will replace the question in the response with inj08poc.yourdomain.com</td></tr>
<tr><td>remark:</td><td>addq (optional) - will add additional question for inj108poc.yourdomain.com in the response</td></tr>
<tr><td>remark:</td><td>3rdparty (optional) - will do injection for 3rd party (whatever.com), rather than yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig inj08.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig inj08.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> inj08.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 43151
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 1

;; QUESTION SECTION:
;inj08.yourdomain.com.		IN	A

;; ANSWER SECTION:
injected08.yourdomain.com. 60	IN	A	6.6.6.8

;; AUTHORITY SECTION:
injected08.yourdomain.com. 60	IN	A	6.6.6.8

;; ADDITIONAL SECTION:
injected08.yourdomain.com. 60	IN	A	6.6.6.8

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:19 +04 2023
;; MSG SIZE  rcvd: 161
```
### inj09
Injection test 9: Respond only with injected PTR record (6.6.6.6 -> inj09poc.yourdomain.com) in all sections.

<table>
<tr><td>format:</td><td>inj09.[replq].[addq].[3rdparty].yourdomain.com</td></tr>
<tr><td>remark:</td><td>replq (optional) - will replace the question in the response with inj09poc.yourdomain.com</td></tr>
<tr><td>remark:</td><td>addq (optional) - will add additional question for inj09poc.yourdomain.com in the response</td></tr>
<tr><td>remark:</td><td>3rdparty (optional) - will do injection for 3rd party (whatever.com), rather than yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig inj09.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig inj09.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> inj09.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41925
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 1

;; QUESTION SECTION:
;inj09.yourdomain.com.		IN	A

;; ANSWER SECTION:
9.6.6.6.in-addr.arpa.	60	IN	PTR	injected09.yourdomain.com.

;; AUTHORITY SECTION:
9.6.6.6.in-addr.arpa.	60	IN	PTR	injected09.yourdomain.com.

;; ADDITIONAL SECTION:
9.6.6.6.in-addr.arpa.	60	IN	PTR	injected09.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:19 +04 2023
;; MSG SIZE  rcvd: 215
```
### inj10
Injection test 10 (NS): Respond with empty answer, but include information in the AUTHORITY section that NS for yourdomain.com is ns1.whatever.com and in the ADDITIONAL section, provide our IP for the ns1.whatever.com.

<table>
<tr><td>format:</td><td>inj10.[replq].[addq].[3rdparty].yourdomain.com</td></tr>
<tr><td>remark:</td><td>replq (optional) - will replace the question in the response with yourdomain.com/whatever.com (depending on the 3rdparty option)</td></tr>
<tr><td>remark:</td><td>addq (optional) - will add additional question for yourdomain.com/whatever.com (depending on the 3rdparty option) in the response</td></tr>
<tr><td>remark:</td><td>3rdparty (optional) - will include information in the AUTHORITY section that NS for whatever.com is ns1.yourdomain.com and in the ADDITIONAL section, provide our IP for the ns1.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig inj10.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig inj10.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> inj10.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 38388
;; flags: qr aa; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; QUESTION SECTION:
;inj10.yourdomain.com.		IN	A

;; AUTHORITY SECTION:
yourdomain.com.		60	IN	NS	ns1.whatever.com.

;; ADDITIONAL SECTION:
ns1.whatever.com.	60	IN	A	44.196.212.212

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:19 +04 2023
;; MSG SIZE  rcvd: 114
```
### inj11
Injection test 11 (NS): Respond with empty answer, but include information in the AUTHORITY section that NS for whatever.com is ns1.yourdomain.com.whatever.com and in the ADDITIONAL section, provide our IP for the ns1.yourdomain.com.whatever.com.

<table>
<tr><td>format:</td><td>inj11.[replq].[addq].[3rdparty].yourdomain.com</td></tr>
<tr><td>remark:</td><td>replq (optional) - will replace the question in the response with whatever.com</td></tr>
<tr><td>remark:</td><td>addq (optional) - will add additional question for whatever.com in the response</td></tr>
<tr><td>remark:</td><td>3rdparty (optional) - will include information in the AUTHORITY section that NS for whatever.com is ns1.whatever.com.yourdomain.com and in the ADDITIONAL section, provide our IP for the ns1.whatever.com.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig inj11.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig inj11.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> inj11.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 27425
;; flags: qr aa; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; QUESTION SECTION:
;inj11.yourdomain.com.		IN	A

;; AUTHORITY SECTION:
whatever.com.		60	IN	NS	ns1.yourdomain.com.whatever.com.

;; ADDITIONAL SECTION:
ns1.yourdomain.com.whatever.com. 60 IN	A	44.196.212.212

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:19 +04 2023
;; MSG SIZE  rcvd: 142
```
### inj12
Injection test 12 (NS): Respond with empty answer, but include information in all sections that NS for yourdomain.com is ns1.whatever.com and also provide our IP for the ns1.whatever.com.

<table>
<tr><td>format:</td><td>inj12.[replq].[addq].[3rdparty].yourdomain.com</td></tr>
<tr><td>remark:</td><td>replq (optional) - will replace the question in the response with yourdomain.com/whatever.com (depending on the 3rdparty option)</td></tr>
<tr><td>remark:</td><td>addq (optional) - will add additional question for yourdomain.com/whatever.com (depending on the 3rdparty option) in the response</td></tr>
<tr><td>remark:</td><td>3rdparty (optional) - will provide information in all sections that NS for whatever.com is ns1.yourdomain.com and also provide our IP for the ns1.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig inj12.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig inj12.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> inj12.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 64736
;; flags: qr aa; QUERY: 1, ANSWER: 2, AUTHORITY: 2, ADDITIONAL: 2

;; QUESTION SECTION:
;inj12.yourdomain.com.		IN	A

;; ANSWER SECTION:
yourdomain.com.		60	IN	NS	ns1.whatever.com.
ns1.whatever.com.	60	IN	A	44.196.212.212

;; AUTHORITY SECTION:
yourdomain.com.		60	IN	NS	ns1.whatever.com.
ns1.whatever.com.	60	IN	A	44.196.212.212

;; ADDITIONAL SECTION:
yourdomain.com.		60	IN	NS	ns1.whatever.com.
ns1.whatever.com.	60	IN	A	44.196.212.212

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:19 +04 2023
;; MSG SIZE  rcvd: 266
```
### inj13
Injection test 13 (NS): Respond with a CNAME (inj13poc.whatever.com), but include information in all sections that NS for whatever.com is ns1.yourdomain.com and also provide our IP for the ns1.yourdomain.com.

<table>
<tr><td>format:</td><td>inj13.[replq].[addq].[3rdparty].yourdomain.com</td></tr>
<tr><td>remark:</td><td>replq (optional) - will replace the question in the response with whatever.com</td></tr>
<tr><td>remark:</td><td>addq (optional) - will add additional question for whatever.com in the response</td></tr>
<tr><td>remark:</td><td>3rdparty (optional) - will respond with a CNAME (inj13poc.whatever.com), but include information in all sections that NS for whatever.com is ns1.whatever.com and also provide our IP for the ns1.whatever.com</td></tr>
<tr><td>example:</td><td><code>dig inj13.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig inj13.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> inj13.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 61538
;; flags: qr aa; QUERY: 1, ANSWER: 3, AUTHORITY: 2, ADDITIONAL: 2

;; QUESTION SECTION:
;inj13.yourdomain.com.		IN	A

;; ANSWER SECTION:
inj13.yourdomain.com.	60	IN	CNAME	injected13.whatever.com.
whatever.com.		60	IN	NS	ns1.yourdomain.com.
ns1.yourdomain.com.	60	IN	A	44.196.212.212

;; AUTHORITY SECTION:
whatever.com.		60	IN	NS	ns1.yourdomain.com.
ns1.yourdomain.com.	60	IN	A	44.196.212.212

;; ADDITIONAL SECTION:
whatever.com.		60	IN	NS	ns1.yourdomain.com.
ns1.yourdomain.com.	60	IN	A	44.196.212.212

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:19 +04 2023
;; MSG SIZE  rcvd: 329
```
### inj14
Injection test 14: Respond only with CNAME record of a 3rd party (inj14poc.yourdomain.com -> alwaysXXX.yourdomain.com) in all sections, to see if it will try to resolve the alwaysXXX.

<table>
<tr><td>format:</td><td>inj14.[replq].[addq].[3rdparty].yourdomain.com</td></tr>
<tr><td>remark:</td><td>replq (optional) - will replace the question in the response with inj14poc.yourdomain.com</td></tr>
<tr><td>remark:</td><td>addq (optional) - will add additional question for inj14poc.yourdomain.com in the response</td></tr>
<tr><td>remark:</td><td>3rdparty (optional) - will do injection for 3rd party (whatever.com), rather than yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig inj14.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig inj14.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> inj14.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 5622
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 1

;; QUESTION SECTION:
;inj14.yourdomain.com.		IN	A

;; ANSWER SECTION:
injected14.yourdomain.com. 60	IN	CNAME	always78400.yourdomain.com.

;; AUTHORITY SECTION:
injected14.yourdomain.com. 60	IN	CNAME	always78400.yourdomain.com.

;; ADDITIONAL SECTION:
injected14.yourdomain.com. 60	IN	CNAME	always78400.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Nov 02 16:37:19 +04 2023
;; MSG SIZE  rcvd: 233
```

##
Go back to [menu](#polardns-catalogue---record-injections).

