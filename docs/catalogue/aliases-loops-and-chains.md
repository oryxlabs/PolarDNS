# PolarDNS catalogue - Aliases, loops and chains
1. [General features](general-features.md)
1. [Aliases, loops and chains](aliases-loops-and-chains.md)
	- [Alias loop (loop)](#alias-loop-loop)
	- [Alias chain (chain)](#alias-chain-chain)
	- [Random N aliases (alias)](#random-n-aliases-alias)
	- [CNAME alias loop (cnloop)](#cname-alias-loop-cnloop)
	- [CNAME alias chain (cnchain)](#cname-alias-chain-cnchain)
	- [CNAME random N aliases (cnalias)](#cname-random-n-aliases-cnalias)
	- [DNAME alias loop (dnloop)](#dname-alias-loop-dnloop)
	- [DNAME alias chain (dnchain)](#dname-alias-chain-dnchain)
	- [DNAME random N aliases (dnalias)](#dname-random-n-aliases-dnalias)
	- [HTTPS alias loop (htloop)](#https-alias-loop-htloop)
	- [HTTPS alias chain (htchain)](#https-alias-chain-htchain)
	- [HTTPS random N aliases (htalias)](#https-random-n-aliases-htalias)
	- [SVCB alias loop (svloop)](#svcb-alias-loop-svloop)
	- [SVCB alias chain (svchain)](#svcb-alias-chain-svchain)
	- [SVCB random N aliases (svalias)](#svcb-random-n-aliases-svalias)
	- [SRV alias loop (srloop)](#srv-alias-loop-srloop)
	- [SRV alias chain (srchain)](#srv-alias-chain-srchain)
	- [SRV random N aliases (sralias)](#srv-random-n-aliases-sralias)
	- [MX alias loop (mxloop)](#mx-alias-loop-mxloop)
	- [MX alias chain (mxchain)](#mx-alias-chain-mxchain)
	- [MX random N aliases (mxalias)](#mx-random-n-aliases-mxalias)
1. [Response modifiers](response-modifiers.md)
1. [CNAME fuzzing](cname-fuzzing.md)
1. [Bad compression](bad-compression.md)
1. [Empty responses](empty-responses.md)
1. [Record injections](record-injections.md)

##
### Alias loop (loop)
Respond with a record that creates an infinite loop with any number of elements. This feature supports CNAME/DNAME/HTTPS/SVCB/SRV/MX resource types.

<table>
<tr><td>format:</td><td>loop.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig loop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig loop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig CNAME loop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig DNAME loop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig HTTPS loop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig SVCB loop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig SRV loop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig MX loop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig loop.15.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig loop.15.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> loop.15.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 33552
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;loop.15.yourdomain.com.		IN	A

;; ANSWER SECTION:
loop.15.yourdomain.com.	60	IN	CNAME	loop.15.1.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Mon Jun 03 14:44:44 +04 2024
;; MSG SIZE  rcvd: 100

```
### Alias chain (chain)
Respond with an incrementing alias record, creating an infinite alias chain that continues to increment indefinitely. This feature supports CNAME/DNAME/HTTPS/SVCB/SRV/MX resource types.

<table>
<tr><td>format:</td><td>chain&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig chain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig CNAME chain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig DNAME chain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig HTTPS chain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig SVCB chain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig SRV chain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig MX chain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig chain100.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig chain100.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> chain100.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 27069
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;chain100.yourdomain.com.	IN	A

;; ANSWER SECTION:
chain100.yourdomain.com. 60	IN	CNAME	chain101.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Mon Jun 03 01:15:16 +04 2024
;; MSG SIZE  rcvd: 101

```
### Random N aliases (alias)
Send multiple (3 by default) random aliases (`alias####.yourdomain.com`). This feature supports CNAME/DNAME/HTTPS/SVCB/SRV/MX resource types. Note: This could lead to multiplication (DoS).

<table>
<tr><td>format:</td><td>cnalias.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig alias.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig alias.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig CNAME alias.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig DNAME alias.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig HTTPS alias.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig SVCB alias.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig SRV alias.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig MX alias.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig alias.15.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig alias.15.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> alias.15.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 28485
;; flags: qr aa; QUERY: 1, ANSWER: 15, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.15.yourdomain.com.	IN	A

;; ANSWER SECTION:
alias.15.yourdomain.com. 60	IN	CNAME	alias335880.15.yourdomain.com.
alias.15.yourdomain.com. 60	IN	CNAME	alias371593.15.yourdomain.com.
alias.15.yourdomain.com. 60	IN	CNAME	alias701017.15.yourdomain.com.
alias.15.yourdomain.com. 60	IN	CNAME	alias952217.15.yourdomain.com.
alias.15.yourdomain.com. 60	IN	CNAME	alias480742.15.yourdomain.com.
alias.15.yourdomain.com. 60	IN	CNAME	alias888189.15.yourdomain.com.
alias.15.yourdomain.com. 60	IN	CNAME	alias592847.15.yourdomain.com.
alias.15.yourdomain.com. 60	IN	CNAME	alias119427.15.yourdomain.com.
alias.15.yourdomain.com. 60	IN	CNAME	alias397506.15.yourdomain.com.
alias.15.yourdomain.com. 60	IN	CNAME	alias875792.15.yourdomain.com.
alias.15.yourdomain.com. 60	IN	CNAME	alias970792.15.yourdomain.com.
alias.15.yourdomain.com. 60	IN	CNAME	alias487932.15.yourdomain.com.
alias.15.yourdomain.com. 60	IN	CNAME	alias322886.15.yourdomain.com.
alias.15.yourdomain.com. 60	IN	CNAME	alias932603.15.yourdomain.com.
alias.15.yourdomain.com. 60	IN	CNAME	alias49907.15.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Mon Jun 03 14:44:44 +04 2024
;; MSG SIZE  rcvd: 1030

```
### CNAME alias loop (cnloop)
Respond with CNAME record that creates an infinite loop with any number of elements. Note that this provides the same functionality as requesting the CNAME record for the `loop` feature.

<table>
<tr><td>format:</td><td>cnloop.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig cnloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig cnloop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig cnloop.15.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig cnloop.15.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> cnloop.15.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 17766
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;cnloop.15.yourdomain.com.	IN	A

;; ANSWER SECTION:
cnloop.15.yourdomain.com. 60	IN	CNAME	cnloop.15.1.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Mon Jun 03 14:44:44 +04 2024
;; MSG SIZE  rcvd: 106

```
### CNAME alias chain (cnchain)
Respond with an incrementing CNAME record, creating an infinite alias chain that continues to increment indefinitely. Note that this provides the same functionality as requesting the CNAME record for the `chain` feature.

<table>
<tr><td>format:</td><td>cnchain&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig cnchain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig cnchain100.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig cnchain100.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> cnchain100.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 9010
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;cnchain100.yourdomain.com.	IN	A

;; ANSWER SECTION:
cnchain100.yourdomain.com. 60	IN	CNAME	cnchain101.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sat Jun 01 00:46:11 +04 2024
;; MSG SIZE  rcvd: 107

```
### CNAME random N aliases (cnalias)
Send multiple (3 by default) random CNAME aliases (`cnalias####.yourdomain.com`). Note: This could lead to multiplication (DoS).

<table>
<tr><td>format:</td><td>cnalias.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig cnalias.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig cnalias.1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig cnalias.5.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig cnalias.5.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> cnalias.5.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 8560
;; flags: qr aa; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;cnalias.5.yourdomain.com.	IN	A

;; ANSWER SECTION:
cnalias.5.yourdomain.com. 60	IN	CNAME	cnalias559648.5.yourdomain.com.
cnalias.5.yourdomain.com. 60	IN	CNAME	cnalias938954.5.yourdomain.com.
cnalias.5.yourdomain.com. 60	IN	CNAME	cnalias292192.5.yourdomain.com.
cnalias.5.yourdomain.com. 60	IN	CNAME	cnalias644854.5.yourdomain.com.
cnalias.5.yourdomain.com. 60	IN	CNAME	cnalias304807.5.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sat Jun 01 00:46:11 +04 2024
;; MSG SIZE  rcvd: 382

```
### DNAME alias loop (dnloop)
Respond with DNAME record that creates an infinite loop with any number of elements. Note that this provides the same functionality as requesting the DNAME record for the `loop` feature.

<table>
<tr><td>format:</td><td>dnloop.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig dnloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig dnloop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig dnloop.15.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig dnloop.15.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> dnloop.15.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 9286
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;dnloop.15.yourdomain.com.	IN	A

;; ANSWER SECTION:
dnloop.15.yourdomain.com. 60	IN	DNAME	dnloop.15.1.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Mon Jun 03 14:44:44 +04 2024
;; MSG SIZE  rcvd: 106

```
### DNAME alias chain (dnchain)
Respond with an incrementing DNAME record, creating an infinite alias chain that continues to increment indefinitely. Note that this provides the same functionality as requesting the DNAME record for the `chain` feature.

<table>
<tr><td>format:</td><td>dnchain&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig dnchain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig dnchain100.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig dnchain100.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> dnchain100.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 46743
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;dnchain100.yourdomain.com.	IN	A

;; ANSWER SECTION:
dnchain100.yourdomain.com. 60	IN	DNAME	dnchain101.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sat Jun 01 00:46:11 +04 2024
;; MSG SIZE  rcvd: 107

```
### DNAME random N aliases (dnalias)
Send multiple (3 by default) random DNAME aliases (`dnalias####.yourdomain.com`). Note: This could lead to multiplication (DoS).

<table>
<tr><td>format:</td><td>dnalias.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig dnalias.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig dnalias.1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig dnalias.5.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig dnalias.5.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> dnalias.5.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 21696
;; flags: qr aa; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;dnalias.5.yourdomain.com.	IN	A

;; ANSWER SECTION:
dnalias.5.yourdomain.com. 60	IN	DNAME	dnalias533593.5.yourdomain.com.
dnalias.5.yourdomain.com. 60	IN	DNAME	dnalias877276.5.yourdomain.com.
dnalias.5.yourdomain.com. 60	IN	DNAME	dnalias644088.5.yourdomain.com.
dnalias.5.yourdomain.com. 60	IN	DNAME	dnalias366486.5.yourdomain.com.
dnalias.5.yourdomain.com. 60	IN	DNAME	dnalias753117.5.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sat Jun 01 00:46:11 +04 2024
;; MSG SIZE  rcvd: 382

```
### HTTPS alias loop (htloop)
Respond with HTTPS alias record (SvcPriority 0) that creates an infinite loop with any number of elements. Note that this provides the same functionality as requesting the HTTPS record for the `loop` feature.

<table>
<tr><td>format:</td><td>htloop.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig htloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig htloop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig htloop.15.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig htloop.15.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> htloop.15.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 21633
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;htloop.15.yourdomain.com.	IN	A

;; ANSWER SECTION:
htloop.15.yourdomain.com. 60	IN	HTTPS	0 htloop.15.1.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Mon Jun 03 14:44:44 +04 2024
;; MSG SIZE  rcvd: 108

```
### HTTPS alias chain (htchain)
Respond with an incrementing HTTPS alias record (SvcPriority 0), creating an infinite alias chain that continues to increment indefinitely. Note that this provides the same functionality as requesting the HTTPS record for the `chain` feature.

<table>
<tr><td>format:</td><td>htchain&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig htchain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig htchain100.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig htchain100.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> htchain100.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1020
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;htchain100.yourdomain.com.	IN	A

;; ANSWER SECTION:
htchain100.yourdomain.com. 60	IN	HTTPS	0 htchain101.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sat Jun 01 00:46:11 +04 2024
;; MSG SIZE  rcvd: 109

```
### HTTPS random N aliases (htalias)
Send multiple (3 by default) random HTTPS aliases (`htalias####.yourdomain.com`). Note: This could lead to multiplication (DoS).

<table>
<tr><td>format:</td><td>htalias.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig htalias.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig htalias.1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig htalias.5.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig htalias.5.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> htalias.5.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 47932
;; flags: qr aa; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;htalias.5.yourdomain.com.	IN	A

;; ANSWER SECTION:
htalias.5.yourdomain.com. 60	IN	HTTPS	0 htalias103536.5.yourdomain.com.
htalias.5.yourdomain.com. 60	IN	HTTPS	0 htalias771588.5.yourdomain.com.
htalias.5.yourdomain.com. 60	IN	HTTPS	0 htalias784421.5.yourdomain.com.
htalias.5.yourdomain.com. 60	IN	HTTPS	0 htalias283125.5.yourdomain.com.
htalias.5.yourdomain.com. 60	IN	HTTPS	0 htalias939599.5.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sat Jun 01 00:46:12 +04 2024
;; MSG SIZE  rcvd: 392

```
### SVCB alias loop (svloop)
Respond with SVCB alias record (SvcPriority 0) that creates an infinite loop with any number of elements. Note that this provides the same functionality as requesting the SVCB record for the `loop` feature.

<table>
<tr><td>format:</td><td>svloop.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig svloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig svloop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _sip.svloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _sip._udp.svloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _http._tcp.svloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _mobile._http._tcp.svloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig svloop.15.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig svloop.15.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> svloop.15.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 25698
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;svloop.15.yourdomain.com.	IN	A

;; ANSWER SECTION:
svloop.15.yourdomain.com. 60	IN	SVCB	0 svloop.15.1.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Mon Jun 03 14:44:44 +04 2024
;; MSG SIZE  rcvd: 108

```
### SVCB alias chain (svchain)
Respond with an incrementing SVCB alias record (SvcPriority 0), creating an infinite alias chain that continues to increment indefinitely. Note that this provides the same functionality as requesting the SVCB record for the `chain` feature.

<table>
<tr><td>format:</td><td>svchain&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig svchain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _sip.svchain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _sip._udp.svchain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _http._tcp.svchain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _mobile._http._tcp.svchain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig svchain100.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig svchain100.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> svchain100.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 49230
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;svchain100.yourdomain.com.	IN	A

;; ANSWER SECTION:
svchain100.yourdomain.com. 60	IN	SVCB	0 svchain101.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sat Jun 01 00:46:12 +04 2024
;; MSG SIZE  rcvd: 109

```
### SVCB random N aliases (svalias)
Send multiple (3 by default) random SVCB aliases (`svalias####.yourdomain.com`). Note: This could lead to multiplication (DoS).

<table>
<tr><td>format:</td><td>svalias.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig svalias.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig svalias.1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _sip.svalias.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _sip._udp.svalias.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _http._tcp.svalias.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _mobile._http._tcp.svalias.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig svalias.5.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig svalias.5.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> svalias.5.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 3335
;; flags: qr aa; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;svalias.5.yourdomain.com.	IN	A

;; ANSWER SECTION:
svalias.5.yourdomain.com. 60	IN	SVCB	0 svalias312485.5.yourdomain.com.
svalias.5.yourdomain.com. 60	IN	SVCB	0 svalias807161.5.yourdomain.com.
svalias.5.yourdomain.com. 60	IN	SVCB	0 svalias476482.5.yourdomain.com.
svalias.5.yourdomain.com. 60	IN	SVCB	0 svalias311437.5.yourdomain.com.
svalias.5.yourdomain.com. 60	IN	SVCB	0 svalias123344.5.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sat Jun 01 00:46:12 +04 2024
;; MSG SIZE  rcvd: 392

```
### SRV alias loop (srloop)
Respond with SRV record that creates an infinite loop with any number of elements. Note that this provides the same functionality as requesting the SRV record for the `loop` feature.

<table>
<tr><td>format:</td><td>srloop.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig srloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig srloop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _sip.srloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _sip._udp.srloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _http._tcp.srloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _mobile._http._tcp.srloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig srloop.15.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig srloop.15.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> srloop.15.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 20698
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;srloop.15.yourdomain.com.	IN	A

;; ANSWER SECTION:
srloop.15.yourdomain.com. 60	IN	SRV	0 0 34304 srloop.15.1.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Mon Jun 03 14:44:44 +04 2024
;; MSG SIZE  rcvd: 112

```
### SRV alias chain (srchain)
Respond with an incrementing SRV record, creating an infinite alias chain that continues to increment indefinitely. Note that this provides the same functionality as requesting the SRV record for the `chain` feature.

<table>
<tr><td>format:</td><td>srchain&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig srchain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _sip.srchain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _sip._udp.srchain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _http._tcp.srchain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _mobile._http._tcp.srchain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig srchain100.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig srchain100.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> srchain100.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 50457
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;srchain100.yourdomain.com.	IN	A

;; ANSWER SECTION:
srchain100.yourdomain.com. 60	IN	SRV	0 0 25008 srchain101.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sat Jun 01 00:46:12 +04 2024
;; MSG SIZE  rcvd: 113

```
### SRV random N aliases (sralias)
Send multiple (3 by default) random SRV records (`sralias####.yourdomain.com`). Note: This could lead to multiplication (DoS).

<table>
<tr><td>format:</td><td>sralias.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig sralias.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig sralias.1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _sip.sralias.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _sip._udp.sralias.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _http._tcp.sralias.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _mobile._http._tcp.sralias.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig sralias.5.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig sralias.5.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> sralias.5.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 47235
;; flags: qr aa; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;sralias.5.yourdomain.com.	IN	A

;; ANSWER SECTION:
sralias.5.yourdomain.com. 60	IN	SRV	0 0 53616 sralias589536.5.yourdomain.com.
sralias.5.yourdomain.com. 60	IN	SRV	0 0 35659 sralias554721.5.yourdomain.com.
sralias.5.yourdomain.com. 60	IN	SRV	0 0 59737 sralias536404.5.yourdomain.com.
sralias.5.yourdomain.com. 60	IN	SRV	0 0 47250 sralias276839.5.yourdomain.com.
sralias.5.yourdomain.com. 60	IN	SRV	0 0 60876 sralias37220.5.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sat Jun 01 00:46:12 +04 2024
;; MSG SIZE  rcvd: 411

```
### MX alias loop (mxloop)
Respond with MX record that creates an infinite loop with any number of elements. Note that this provides the same functionality as requesting the MX record for the `loop` feature.

<table>
<tr><td>format:</td><td>mxloop.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig mxloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig mxloop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig mxloop.15.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig mxloop.15.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> mxloop.15.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 30584
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;mxloop.15.yourdomain.com.	IN	A

;; ANSWER SECTION:
mxloop.15.yourdomain.com. 60	IN	MX	0 mxloop.15.1.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Mon Jun 03 14:44:44 +04 2024
;; MSG SIZE  rcvd: 108

```
### MX alias chain (mxchain)
Respond with an incrementing MX record, creating an infinite alias chain that continues to increment indefinitely. Note that this provides the same functionality as requesting the MX record for the `chain` feature.

<table>
<tr><td>format:</td><td>mxchain&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig mxchain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig mxchain100.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig mxchain100.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> mxchain100.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 8860
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;mxchain100.yourdomain.com.	IN	A

;; ANSWER SECTION:
mxchain100.yourdomain.com. 60	IN	MX	0 mxchain101.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sat Jun 01 00:46:12 +04 2024
;; MSG SIZE  rcvd: 109

```
### MX random N aliases (mxalias)
Send multiple (3 by default) random MX records (`mxalias####.yourdomain.com`). Note: This could lead to multiplication (DoS).

<table>
<tr><td>format:</td><td>mxalias.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig mxalias.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig mxalias.1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig mxalias.5.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig mxalias.5.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> mxalias.5.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 21241
;; flags: qr aa; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;mxalias.5.yourdomain.com.	IN	A

;; ANSWER SECTION:
mxalias.5.yourdomain.com. 60	IN	MX	0 mxalias870446.5.yourdomain.com.
mxalias.5.yourdomain.com. 60	IN	MX	0 mxalias122700.5.yourdomain.com.
mxalias.5.yourdomain.com. 60	IN	MX	0 mxalias482975.5.yourdomain.com.
mxalias.5.yourdomain.com. 60	IN	MX	0 mxalias714375.5.yourdomain.com.
mxalias.5.yourdomain.com. 60	IN	MX	0 mxalias861718.5.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sat Jun 01 00:46:12 +04 2024
;; MSG SIZE  rcvd: 392

```

##
Go back to [menu](#polardns-catalogue---aliases-loops-and-chains).

