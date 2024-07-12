# PolarDNS catalogue - Aliases, loops and chains
1. [General features](general-features.md)
1. [Aliases, loops and chains](aliases-loops-and-chains.md)
	- [Generic](#generic)
		- [Random N aliases (alias)](#random-n-aliases-alias)
		- [Alias chain (chain)](#alias-chain-chain)
		- [Alias loop (loop)](#alias-loop-loop)
	- [CNAME (Canonical Name)](#cname-canonical-name)
		- [CNAME random N aliases (cnalias)](#cname-random-n-aliases-cnalias)
		- [CNAME alias chain (cnchain)](#cname-alias-chain-cnchain)
		- [CNAME alias loop (cnloop)](#cname-alias-loop-cnloop)
	- [DNAME (Delegation Name)](#dname-delegation-name)
		- [DNAME random N aliases (dnalias)](#dname-random-n-aliases-dnalias)
		- [DNAME alias chain (dnchain)](#dname-alias-chain-dnchain)
		- [DNAME alias loop (dnloop)](#dname-alias-loop-dnloop)
	- [HTTPS (HTTPS Binding)](#https-https-binding)
		- [HTTPS random N aliases (htalias)](#https-random-n-aliases-htalias)
		- [HTTPS alias chain (htchain)](#https-alias-chain-htchain)
		- [HTTPS alias loop (htloop)](#https-alias-loop-htloop)
	- [SVCB (Service Binding)](#svcb-service-binding)
		- [SVCB random N aliases (svalias)](#svcb-random-n-aliases-svalias)
		- [SVCB alias chain (svchain)](#svcb-alias-chain-svchain)
		- [SVCB alias loop (svloop)](#svcb-alias-loop-svloop)
	- [SRV (Service Locator)](#srv-service-locator)
		- [SRV random N aliases (sralias)](#srv-random-n-aliases-sralias)
		- [SRV alias chain (srchain)](#srv-alias-chain-srchain)
		- [SRV alias loop (srloop)](#srv-alias-loop-srloop)
	- [MX (Mail Exchange)](#mx-mail-exchange)
		- [MX random N aliases (mxalias)](#mx-random-n-aliases-mxalias)
		- [MX alias chain (mxchain)](#mx-alias-chain-mxchain)
		- [MX alias loop (mxloop)](#mx-alias-loop-mxloop)
	- [NS (Name Server)](#ns-name-server)
		- [NS random N aliases (nsalias)](#ns-random-n-aliases-nsalias)
		- [NS alias chain (nschain)](#ns-alias-chain-nschain)
		- [NS alias loop (nsloop)](#ns-alias-loop-nsloop)
	- [SPF (Sender Policy Framework)](#spf-sender-policy-framework)
		- [SPF (TXT) random N aliases (spfalias1)](#spf-txt-random-n-aliases-spfalias1)
		- [SPF (TXT) random N aliases (spfalias2)](#spf-txt-random-n-aliases-spfalias2)
		- [SPF (TXT) alias chain (spfchain)](#spf-txt-alias-chain-spfchain)
		- [SPF (TXT) alias loop (spfloop)](#spf-txt-alias-loop-spfloop)
	- [PTR (Pointer)](#ptr-pointer)
		- [PTR random N aliases (10.0.0.0/8)](#ptr-random-n-aliases-100008)
		- [PTR alias loop 1 (192.0.2.0/24)](#ptr-alias-loop-1-19202024)
		- [PTR alias loop 2 (198.51.100.0/24)](#ptr-alias-loop-2-19851100024)
1. [Response modifiers](response-modifiers.md)
1. [CNAME fuzzing](cname-fuzzing.md)
1. [Bad compression](bad-compression.md)
1. [Empty responses](empty-responses.md)
1. [Record injections](record-injections.md)

##
# Generic
### Random N aliases (alias)
Respond with multiple (3 by default) random aliases in the format `alias######.yourdomain.com`. This feature supports `CNAME`, `DNAME`, `HTTPS`, `SVCB`, `SRV`, `MX`, `NS` and `SPF` (`TXT`) resource types.:exclamation:**BEWARE**:exclamation:This can potentially lead to amplification effect (DoS).

<table>
<tr><td>format:</td><td>alias.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig alias.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig alias.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig CNAME alias.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig DNAME alias.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig HTTPS alias.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig SVCB alias.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig SRV alias.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig TXT alias.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig MX alias.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig NS alias.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig alias.5.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig alias.5.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> alias.5.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32197
;; flags: qr aa; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;alias.5.yourdomain.com.		IN	A

;; ANSWER SECTION:
alias.5.yourdomain.com.	60	IN	CNAME	alias323773.5.yourdomain.com.
alias.5.yourdomain.com.	60	IN	CNAME	alias323773.5.yourdomain.com.
alias.5.yourdomain.com.	60	IN	CNAME	alias323773.5.yourdomain.com.
alias.5.yourdomain.com.	60	IN	CNAME	alias323773.5.yourdomain.com.
alias.5.yourdomain.com.	60	IN	CNAME	alias323773.5.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Mon Jun 03 01:15:16 +04 2024
;; MSG SIZE  rcvd: 360

```
### Alias chain (chain)
Respond with an incremented alias record, creating an infinite alias chain that continues to increment indefinitely. This feature supports `CNAME`, `DNAME`, `HTTPS`, `SVCB`, `SRV`, `MX`, `NS` and `SPF` (`TXT`) resource types.:exclamation:**BEWARE**:exclamation:This could potentially lead to a domain lock-up (DoS).

<table>
<tr><td>format:</td><td>chain&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig chain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig CNAME chain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig DNAME chain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig HTTPS chain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig SVCB chain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig SRV chain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig TXT chain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig MX chain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig NS chain.yourdomain.com @127.0.0.1</code></td></tr>
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
### Alias loop (loop)
Respond with the exact same domain name as in the query, effectively creating a direct infinite loop. Optionally, respond with a domain name that leads to an infinite loop with an arbitrary number of elements. This feature supports `CNAME`, `DNAME`, `HTTPS`, `SVCB`, `SRV`, `MX`, `NS` and `SPF` (`TXT`) resource types.:exclamation:**BEWARE**:exclamation:This could potentially lead to a domain lock-up (DoS).

<table>
<tr><td>format:</td><td>loop.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig loop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig loop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig CNAME loop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig DNAME loop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig HTTPS loop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig SVCB loop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig SRV loop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig TXT loop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig MX loop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig NS loop.10.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig loop.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> loop.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 38888
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;loop.yourdomain.com.		IN	A

;; ANSWER SECTION:
loop.yourdomain.com.	60	IN	CNAME	loop.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Tue May 28 11:50:00 +04 2024
;; MSG SIZE  rcvd: 89

```
# CNAME (Canonical Name)
### CNAME random N aliases (cnalias)
Respond with multiple (3 by default) random `CNAME` records in the format `cnalias######.yourdomain.com`. Note that this provides the same functionality as requesting the `CNAME` record for the generic `alias` feature.:exclamation:**BEWARE**:exclamation:This can potentially lead to amplification effect (DoS).

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
### CNAME alias chain (cnchain)
Respond with an incremented `CNAME` record, creating an infinite alias chain that continues to increment indefinitely. Note that this provides the same functionality as requesting the `CNAME` record for the generic `chain` feature.:exclamation:**BEWARE**:exclamation:This could potentially lead to a domain lock-up (DoS).

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
### CNAME alias loop (cnloop)
Respond with a `CNAME` record containing the exact same domain name as in the query, effectively creating a direct infinite loop. Optionally, respond with a domain name that leads to an infinite loop with an arbitrary number of elements. Note that this provides the same functionality as requesting the `CNAME` record for the generic `loop` feature.:exclamation:**BEWARE**:exclamation:This could potentially lead to a domain lock-up (DoS).

<table>
<tr><td>format:</td><td>cnloop.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig cnloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig cnloop.5.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig cnloop.10.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig cnloop.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> cnloop.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 20548
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;cnloop.yourdomain.com.		IN	A

;; ANSWER SECTION:
cnloop.yourdomain.com.	60	IN	CNAME	cnloop.yourdomain.com.

;; Query time: 12 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sat Jun 01 00:46:11 +04 2024
;; MSG SIZE  rcvd: 95

```
# DNAME (Delegation Name)
### DNAME random N aliases (dnalias)
Respond with multiple (3 by default) random `DNAME` records in the format `dnalias######.yourdomain.com`. Note that this provides the same functionality as requesting the `DNAME` record for the generic `alias` feature.:exclamation:**BEWARE**:exclamation:This can potentially lead to amplification effect (DoS).

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
### DNAME alias chain (dnchain)
Respond with an incremented `DNAME` record, creating an infinite alias chain that continues to increment indefinitely. Note that this provides the same functionality as requesting the `DNAME` record for the generic `chain` feature.:exclamation:**BEWARE**:exclamation:This could potentially lead to a domain lock-up (DoS).

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
### DNAME alias loop (dnloop)
Respond with a `DNAME` record containing the exact same domain name as in the query, effectively creating a direct infinite loop. Optionally, respond with a domain name that leads to an infinite loop with an arbitrary number of elements. Note that this provides the same functionality as requesting the `DNAME` record for the generic `loop` feature.:exclamation:**BEWARE**:exclamation:This could potentially lead to a domain lock-up (DoS).

<table>
<tr><td>format:</td><td>dnloop.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig dnloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig dnloop.5.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig dnloop.10.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig dnloop.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> dnloop.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 61371
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;dnloop.yourdomain.com.		IN	A

;; ANSWER SECTION:
dnloop.yourdomain.com.	60	IN	DNAME	dnloop.yourdomain.com.

;; Query time: 4 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sat Jun 01 00:46:11 +04 2024
;; MSG SIZE  rcvd: 95

```
# HTTPS (HTTPS Binding)
### HTTPS random N aliases (htalias)
Respond with multiple (3 by default) random `HTTPS` records in the format `htalias######.yourdomain.com`. Note that this provides the same functionality as requesting the `HTTPS` record for the generic `alias` feature.:exclamation:**BEWARE**:exclamation:This can potentially lead to amplification effect (DoS).

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
### HTTPS alias chain (htchain)
Respond with an incremented `HTTPS` alias record (SvcPriority 0), creating an infinite alias chain that continues to increment indefinitely. Note that this provides the same functionality as requesting the `HTTPS` record for the generic `chain` feature.:exclamation:**BEWARE**:exclamation:This could potentially lead to a domain lock-up (DoS).

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
### HTTPS alias loop (htloop)
Respond with a `HTTPS` record containing the exact same domain name as in the query, effectively creating a direct infinite loop. Optionally, respond with a domain name that leads to an infinite loop with an arbitrary number of elements. Note that this provides the same functionality as requesting the `HTTPS` record for the generic `loop` feature.:exclamation:**BEWARE**:exclamation:This could potentially lead to a domain lock-up (DoS).

<table>
<tr><td>format:</td><td>htloop.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig htloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig htloop.5.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig htloop.10.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig htloop.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> htloop.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 25585
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;htloop.yourdomain.com.		IN	A

;; ANSWER SECTION:
htloop.yourdomain.com.	60	IN	HTTPS	0 htloop.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sat Jun 01 00:46:11 +04 2024
;; MSG SIZE  rcvd: 97

```
# SVCB (Service Binding)
### SVCB random N aliases (svalias)
Respond with multiple (3 by default) random `SVCB` records in the format `svalias######.yourdomain.com`. Note that this provides the same functionality as requesting the `SVCB` record for the generic `alias` feature.:exclamation:**BEWARE**:exclamation:This can potentially lead to amplification effect (DoS).

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
### SVCB alias chain (svchain)
Respond with an incremented `SVCB` alias record (SvcPriority 0), creating an infinite alias chain that continues to increment indefinitely. Note that this provides the same functionality as requesting the `SVCB` record for the generic `chain` feature.:exclamation:**BEWARE**:exclamation:This could potentially lead to a domain lock-up (DoS).

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
### SVCB alias loop (svloop)
Respond with a `SVCB` record containing the exact same domain name as in the query, effectively creating a direct infinite loop. Optionally, respond with a domain name that leads to an infinite loop with an arbitrary number of elements. Note that this provides the same functionality as requesting the `SVCB` record for the generic `loop` feature.:exclamation:**BEWARE**:exclamation:This could potentially lead to a domain lock-up (DoS).

<table>
<tr><td>format:</td><td>svloop.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig svloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig svloop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _sip.svloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _sip._udp.svloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _http._tcp.svloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _mobile._http._tcp.svloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _mobile._http._tcp.svloop.10.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig svloop.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> svloop.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 38993
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;svloop.yourdomain.com.		IN	A

;; ANSWER SECTION:
svloop.yourdomain.com.	60	IN	SVCB	0 svloop.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sat Jun 01 00:46:12 +04 2024
;; MSG SIZE  rcvd: 97

```
# SRV (Service Locator)
### SRV random N aliases (sralias)
Respond with multiple (3 by default) random `SRV` records in the format `sralias######.yourdomain.com`. Note that this provides the same functionality as requesting the `SRV` record for the generic `alias` feature.:exclamation:**BEWARE**:exclamation:This can potentially lead to amplification effect (DoS).

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
### SRV alias chain (srchain)
Respond with an incremented `SRV` record, creating an infinite alias chain that continues to increment indefinitely. Note that this provides the same functionality as requesting the `SRV` record for the generic `chain` feature.:exclamation:**BEWARE**:exclamation:This could potentially lead to a domain lock-up (DoS).

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
### SRV alias loop (srloop)
Respond with a `SRV` record containing the exact same domain name as in the query, effectively creating a direct infinite loop. Optionally, respond with a domain name that leads to an infinite loop with an arbitrary number of elements. Note that this provides the same functionality as requesting the `SRV` record for the generic `loop` feature.:exclamation:**BEWARE**:exclamation:This could potentially lead to a domain lock-up (DoS).

<table>
<tr><td>format:</td><td>srloop.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig srloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig srloop.10.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _sip.srloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _sip._udp.srloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _http._tcp.srloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _mobile._http._tcp.srloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig _mobile._http._tcp.srloop.10.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig srloop.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> srloop.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 64758
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;srloop.yourdomain.com.		IN	A

;; ANSWER SECTION:
srloop.yourdomain.com.	60	IN	SRV	0 0 38882 srloop.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sat Jun 01 00:46:12 +04 2024
;; MSG SIZE  rcvd: 101

```
# MX (Mail Exchange)
### MX random N aliases (mxalias)
Respond with multiple (3 by default) random `MX` records in the format `mxalias######.yourdomain.com`. Note that this provides the same functionality as requesting the `MX` record for the generic `alias` feature.:exclamation:**BEWARE**:exclamation:This can potentially lead to amplification effect (DoS).

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
### MX alias chain (mxchain)
Respond with an incremented `MX` record, creating an infinite alias chain that continues to increment indefinitely. Note that this provides the same functionality as requesting the `MX` record for the generic `chain` feature.:exclamation:**BEWARE**:exclamation:This could potentially lead to a domain lock-up (DoS).

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
### MX alias loop (mxloop)
Respond with a `MXx` record containing the exact same domain name as in the query, effectively creating a direct infinite loop. Optionally, respond with a domain name that leads to an infinite loop with an arbitrary number of elements. Note that this provides the same functionality as requesting the `MX` record for the generic `loop` feature.:exclamation:**BEWARE**:exclamation:This could potentially lead to a domain lock-up (DoS).

<table>
<tr><td>format:</td><td>mxloop.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig mxloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig mxloop.5.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig mxloop.10.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig mxloop.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> mxloop.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41968
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;mxloop.yourdomain.com.		IN	A

;; ANSWER SECTION:
mxloop.yourdomain.com.	60	IN	MX	0 mxloop.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Sat Jun 01 00:46:12 +04 2024
;; MSG SIZE  rcvd: 97

```
# NS (Name Server)
### NS random N aliases (nsalias)
Respond with multiple (3 by default) random `NS` records in the format `nsalias######.yourdomain.com`. Note that this provides the same functionality as requesting the `NS` record for the generic `alias` feature.:exclamation:**BEWARE**:exclamation:This can potentially lead to amplification effect (DoS).

<table>
<tr><td>format:</td><td>nsalias.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig nsalias.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig nsalias.1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig nsalias.5.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig nsalias.5.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> nsalias.5.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 5265
;; flags: qr aa; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;nsalias.5.yourdomain.com.	IN	A

;; ANSWER SECTION:
nsalias.5.yourdomain.com. 60	IN	NS	nsalias745947.5.yourdomain.com.
nsalias.5.yourdomain.com. 60	IN	NS	nsalias39277.5.yourdomain.com.
nsalias.5.yourdomain.com. 60	IN	NS	nsalias385184.5.yourdomain.com.
nsalias.5.yourdomain.com. 60	IN	NS	nsalias621059.5.yourdomain.com.
nsalias.5.yourdomain.com. 60	IN	NS	nsalias694309.5.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 11 11:53:03 +04 2024
;; MSG SIZE  rcvd: 261

```
### NS alias chain (nschain)
Respond with an incremented `NS` record, creating an infinite alias chain that continues to increment indefinitely. Note that this provides the same functionality as requesting the `NS` record for the generic `chain` feature.:exclamation:**BEWARE**:exclamation:This could potentially lead to a domain lock-up (DoS).

<table>
<tr><td>format:</td><td>nschain&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig nschain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig nschain100.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig nschain100.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> nschain100.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 47034
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;nschain100.yourdomain.com.	IN	A

;; ANSWER SECTION:
nschain100.yourdomain.com. 60	IN	NS	nschain101.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 11 11:53:03 +04 2024
;; MSG SIZE  rcvd: 82

```
### NS alias loop (nsloop)
Respond with a `NS` record containing the exact same domain name as in the query, effectively creating a direct infinite loop. Optionally, respond with a domain name that leads to an infinite loop with an arbitrary number of elements. Note that this provides the same functionality as requesting the `NS` record for the generic `loop` feature.:exclamation:**BEWARE**:exclamation:This could potentially lead to a domain lock-up (DoS).

<table>
<tr><td>format:</td><td>nsloop.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig nsloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig nsloop.5.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig nsloop.10.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig nsloop.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> nsloop.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 65006
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;nsloop.yourdomain.com.		IN	A

;; ANSWER SECTION:
nsloop.yourdomain.com.	60	IN	NS	nsloop.yourdomain.com.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 11 11:53:03 +04 2024
;; MSG SIZE  rcvd: 74

```
# SPF (Sender Policy Framework)
### SPF (TXT) random N aliases (spfalias1)
Respond with multiple (3 by default) `SPF` (Sender Policy Framework) entries, with each entry in a separate `TXT` record. Each `SPF` entry contains a single `include:` parameter with a randomly generated alias/domain name in the format `spfalias1#####.yourdomain.com`. Note that this provides the same functionality as requesting the `TXT` record for the generic `alias` feature.:exclamation:**BEWARE**:exclamation:This can potentially lead to amplification effect (DoS).

<table>
<tr><td>format:</td><td>spfalias1.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig spfalias1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig spfalias1.1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig spfalias1.5.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig spfalias1.5.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> spfalias1.5.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 60985
;; flags: qr aa; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;spfalias1.5.yourdomain.com.	IN	A

;; ANSWER SECTION:
spfalias1.5.yourdomain.com. 60	IN	TXT	"v=spf1 include:spfalias110591.5.yourdomain.com ~all"
spfalias1.5.yourdomain.com. 60	IN	TXT	"v=spf1 include:spfalias141406.5.yourdomain.com ~all"
spfalias1.5.yourdomain.com. 60	IN	TXT	"v=spf1 include:spfalias129292.5.yourdomain.com ~all"
spfalias1.5.yourdomain.com. 60	IN	TXT	"v=spf1 include:spfalias114609.5.yourdomain.com ~all"
spfalias1.5.yourdomain.com. 60	IN	TXT	"v=spf1 include:spfalias13328.5.yourdomain.com ~all"

;; Query time: 4 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Fri Jul 12 01:33:31 +04 2024
;; MSG SIZE  rcvd: 363

```
### SPF (TXT) random N aliases (spfalias2)
Respond with multiple (3 by default) `SPF` (Sender Policy Framework) entries within one or more `TXT` records. Each `SPF` record includes multiple `include:` parameters with randomly generated alias/domain names in the format `spfalias2#####.yourdomain.com`. The number of `SPF` aliases per `TXT` record is limited by the maximum `TXT` label size of 255 bytes. If the specified number of aliases cannot fit within a single `TXT` record, multiple `TXT` records will be produced to accomodate all aliases.:exclamation:**BEWARE**:exclamation:This can potentially lead to amplification effect (DoS).

<table>
<tr><td>format:</td><td>spfalias2.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig spfalias2.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig spfalias2.1.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig spfalias2.100.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig spfalias2.11.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig spfalias2.11.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> spfalias2.11.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 55061
;; flags: qr aa; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;spfalias2.11.yourdomain.com.	IN	A

;; ANSWER SECTION:
spfalias2.11.yourdomain.com. 60	IN	TXT	"v=spf1 include:spfalias297648.11.yourdomain.com include:spfalias292301.11.yourdomain.com include:spfalias271263.11.yourdomain.com include:spfalias280110.11.yourdomain.com include:spfalias248974.11.yourdomain.com ~all"
spfalias2.11.yourdomain.com. 60	IN	TXT	"v=spf1 include:spfalias247152.11.yourdomain.com include:spfalias288375.11.yourdomain.com include:spfalias295587.11.yourdomain.com include:spfalias257159.11.yourdomain.com include:spfalias235140.11.yourdomain.com ~all"
spfalias2.11.yourdomain.com. 60	IN	TXT	"v=spf1 include:spfalias224904.11.yourdomain.com ~all"

;; Query time: 4 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Fri Jul 12 10:06:38 +04 2024
;; MSG SIZE  rcvd: 568

```
### SPF (TXT) alias chain (spfchain)
Respond with a `TXT` record containing an `SPF` (Sender Policy Framework) record with an incremented index, creating an infinite alias chain that continues to increment indefinitely. Note that this provides the same functionality as requesting the `TXT` record for the generic `chain` feature.:exclamation:**BEWARE**:exclamation:This could potentially lead to a domain lock-up (DoS).

<table>
<tr><td>format:</td><td>spfchain&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig spfchain.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig spfchain100.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig spfchain100.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> spfchain100.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 24557
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;spfchain100.yourdomain.com.	IN	A

;; ANSWER SECTION:
spfchain100.yourdomain.com. 60	IN	TXT	"v=spf1 include:spfchain101.yourdomain.com ~all"

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 11 11:53:03 +04 2024
;; MSG SIZE  rcvd: 103

```
### SPF (TXT) alias loop (spfloop)
Respond with a `TXT` record with an `SPF` (Sender Policy Framework) record containing the exact same domain name as in the query, effectively creating a direct infinite loop. Optionally, respond with a domain name that leads to an infinite loop with an arbitrary number of elements. Note that this provides the same functionality as requesting the `TXT` record for the generic `loop` feature.:exclamation:**BEWARE**:exclamation:This could potentially lead to a domain lock-up (DoS).

<table>
<tr><td>format:</td><td>spfloop.&lt;NUMBER>.yourdomain.com</td></tr>
<tr><td>example:</td><td><code>dig spfloop.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig spfloop.5.yourdomain.com @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig spfloop.10.yourdomain.com @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig spfloop.yourdomain.com @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> spfloop.yourdomain.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 56063
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;spfloop.yourdomain.com.		IN	A

;; ANSWER SECTION:
spfloop.yourdomain.com.	60	IN	TXT	"v=spf1 include:spfloop.yourdomain.com ~all"

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Thu Jul 11 11:53:03 +04 2024
;; MSG SIZE  rcvd: 95

```
# PTR (Pointer)
### PTR random N aliases (10.0.0.0/8)
Requesting a reverse DNS record for any IP address within the `10.0.0.0/8` network range (e.g., a PTR record for `z.y.x.10.in-addr.arpa`). The `10.0.0.0/8` range is a private network range used exclusively for internal purposes. We will respond with `x` number of `PTR` records containing domains in the format `10.x.*.*.in-addr.arpa` (within the same range). This implies that if the client/resolver attempts to resolve any of these records, it will loop back to this process, generating even more `PTR` records from the same range.:exclamation:**BEWARE**:exclamation:This can potentially lead to amplification effect (DoS).

<table>
<tr><td>format:</td><td>&lt;0-255>.&lt;0-255>.&lt;0-255>.10.in-addr.arpa</td></tr>
<tr><td>example:</td><td><code>dig -x 10.1.0.0 @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig -x 10.5.0.0 @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig -x 10.10.123.123 @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig -x 10.15.123.123 @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig PTR 0.0.1.10.in-addr.arpa @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig PTR 0.0.5.10.in-addr.arpa @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig PTR 123.123.10.10.in-addr.arpa @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig PTR 123.123.15.10.in-addr.arpa @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig -x 10.5.0.0 @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> -x 10.5.0.0 @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 30634
;; flags: qr aa; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;0.0.5.10.in-addr.arpa.		IN	PTR

;; ANSWER SECTION:
0.0.5.10.in-addr.arpa.	60	IN	PTR	170.72.5.10.in-addr.arpa.
0.0.5.10.in-addr.arpa.	60	IN	PTR	212.179.5.10.in-addr.arpa.
0.0.5.10.in-addr.arpa.	60	IN	PTR	42.124.5.10.in-addr.arpa.
0.0.5.10.in-addr.arpa.	60	IN	PTR	8.207.5.10.in-addr.arpa.
0.0.5.10.in-addr.arpa.	60	IN	PTR	52.140.5.10.in-addr.arpa.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Fri Jul 12 10:36:31 +04 2024
;; MSG SIZE  rcvd: 229

```
### PTR alias loop 1 (192.0.2.0/24)
Requesting a reverse DNS record for any IP address within the `192.0.2.0/24` network range (e.g., a `PTR` record for `x.2.0.192.in-addr.arpa`). The `192.0.2.0/24` range, known as TEST-NET-1, is typically used for documentation and examples. We will respond with the same exact domain name, effectively creating an immediate loop.:exclamation:**BEWARE**:exclamation:This could potentially lead to a domain lock-up (DoS).

<table>
<tr><td>format:</td><td>&lt;0-255>.2.0.192.in-addr.arpa</td></tr>
<tr><td>example:</td><td><code>dig -x 192.0.2.0 @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig -x 192.0.2.100 @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig PTR 0.2.0.192.in-addr.arpa @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig PTR 255.2.0.192.in-addr.arpa @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig -x 192.0.2.200 @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig -x 192.0.2.200 @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> -x 192.0.2.200 @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 5212
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;200.2.0.192.in-addr.arpa.	IN	PTR

;; ANSWER SECTION:
200.2.0.192.in-addr.arpa. 60	IN	PTR	200.2.0.192.in-addr.arpa.

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Fri Jul 12 10:58:36 +04 2024
;; MSG SIZE  rcvd: 56

```
### PTR alias loop 2 (198.51.100.0/24)
Requesting a reverse DNS record for any IP address within the `198.51.100.0/24` network range (e.g., a `PTR` record for `x.100.51.198.in-addr.arpa`). The `198.51.100.0/24` range, known as TEST-NET-2, is typically used for documentation and examples. We will respond with incremented domain name, cycling through addresses from `198.51.100.0` to `198.51.100.255` indefinitely, effectively creating a loop.:exclamation:**BEWARE**:exclamation:This could potentially lead to a domain lock-up (DoS).

<table>
<tr><td>format:</td><td>&lt;0-255>.100.51.198.in-addr.arpa</td></tr>
<tr><td>example:</td><td><code>dig -x 198.51.100.0 @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig -x 198.51.100.10 @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig PTR 0.100.51.198.in-addr.arpa @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig PTR 255.100.51.198.in-addr.arpa @127.0.0.1</code></td></tr>
<tr><td>example:</td><td><code>dig -x 198.51.100.123 @127.0.0.1</code></td></tr>
</table>

Sample:
```
# dig -x 198.51.100.123 @127.0.0.1

; <<>> DiG 9.18.10-2-Debian <<>> -x 198.51.100.123 @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 13554
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;123.100.51.198.in-addr.arpa.	IN	PTR

;; ANSWER SECTION:
123.100.51.198.in-addr.arpa. 60	IN	PTR	124.100.51.198.in-addr.arpa.

;; Query time: 3 msec
;; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)
;; WHEN: Fri Jul 12 10:58:36 +04 2024
;; MSG SIZE  rcvd: 86

```

##
Go back to [menu](#polardns-catalogue---aliases-loops-and-chains).

