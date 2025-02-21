---
layout: default
title: Features and Response Modifiers Explained
parent: Using PolarDNS
has_children: false
nav_order: 3
---

# Features and Response Modifiers Explained

PolarDNS has the following main functionalities:
1. **Features**: These can produce various DNS responses. Most features have parameters, meaning that it is possible to adjust their behavior to produce variety of different DNS responses.
1. **Response modifiers**: These can further modify the DNS responses coming out from the PolarDNS server. Modifiers are independent on the selected feature and can be combined freely.

There are over 70 different features and 18 response modifiers currently implemented. By using different features and combining them together with different response modifiers, it is possible to produce countless variants of given response.

See the included **[catalogue](../catalogue/catalogue.html)** of all implemented **features** and **response modifiers**.

This gives PolarDNS capacity to produce highly unusual, abnormal, and even malformed DNS responses, allowing the operator to see how the receiving side handles such situations and whether the receiving side is technically robust and mature.

Some examples of DNS responses which PolarDNS can produce contain:
-	Alias (CNAME) chains and alias loops
-	DNS header malformations (ID, Flags, number of sections)
-	Injection of unsolicited records (cache poisoning)
-	Injection of arbitrary bytes of arbitrary lengths
-	Incomplete / empty / NULL byte(s) responses
-	Compression issues (loops, invalid pointers)
-	Slowly transmitted chunked responses
-	Illegal labels or domain name lengths
-	Arbitrary number of TXT records of arbitrary size
-	Packet length manipulations (TCP)
- Etc.

These can lead to discovery of various vulnerabilities such as:
-	Sloth domain attacks
-	Phantom domain attacks
-	Domain lock-up attacks
-	Cache poisoning
-	Resource exhaustion
-	Crashes, DoS

--- 

| Previous: [Understanding the Main Concept](main-concept) | Next: [Testing of Recursive DNS Resolvers](testing-recursive-resolvers) |
