---
layout: default
title: PolarDNS
has_children: true
nav_order: 1
---

<img width="800" alt="PolarDNS logo" src="assets/polardns-logo-for-white-bg.png">

PolarDNS is a specialized authoritative DNS server written in Python 3.x, originally developed as a tool for security testing of DNS recursive resolvers from the server-side.

It allows the operator to produce custom DNS responses, making it suitable for in-depth DNS protocol testing purposes.

_

PolarDNS can be used for testing of:

- DNS resolvers (server-side)
- DNS clients
- DNS libraries
- DNS parsers and dissectors
- any software handling DNS information

It supports both UDP and TCP protocols, and it gives the operator full control over the DNS protocol layer.

PolarDNS server can produce variety of non-standard and non-compliant DNS responses, DNS responses violating the RFC specifications, including highly abnormal and malformed DNS responses.

This can be useful for:
- Functional testing
- RFC compliance
- Vulnerability research

---

| Next: [Installation](installation/installation) |
