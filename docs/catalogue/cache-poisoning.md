---
layout: default
title: Cache poisoning
parent: Catalogue
has_children: true
---

# Cache Poisoning

Modules in this category were designed for cache poisoning experiments, specifically for injecting unsolicited records into DNS responses.

These modules can inject records of various resource types, including A, AAAA, CNAME, DNAME, NS, MX, and PTR.

Upon receiving a query for any supported record type, these modules return a standard (benign) answer that correctly responds to the query. Additionally, the response includes an unsolicited record, aiming for the resolver to pick up and store it in its cache.
