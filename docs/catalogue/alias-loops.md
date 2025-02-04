---
layout: default
title: Alias loops
parent: Catalogue
has_children: true
---

# Alias Loops

Modules in this category implement alias loops for various resource types, including CNAME, DNAME, PTR, NAPTR, NS, MX, HTTPS, SVCB, SRV, and SPF-TXT.


These modules typically produce alias records that form a direct loop, where the alias either points back to the same domain name as the original query or cycles through multiple elements in a loop sequence.

The concept is that if the client or resolver attempts to resolve the alias further, it will become trapped in an infinite resolution loop.
