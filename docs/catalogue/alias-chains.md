---
layout: default
title: Alias chains
parent: Catalogue
has_children: true
---

# Alias Chains

Modules in this category generate incremental alias chains for various resource types, including CNAME, DNAME, NS, MX, HTTPS, SVCB, SRV, and SPF-TXT.

These modules typically produce alias records in the format `chain###.yourdomain.com`, where `###` represents an incremented index.

The idea is that if the client or resolver continues resolving this alias, it will generate a new incremented alias each time, leading to an infinite resolution chain and potentially keeping the resolver occupied.
