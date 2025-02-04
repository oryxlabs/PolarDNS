---
layout: default
title: Aliases
parent: Catalogue
has_children: true
---

# Aliases

Modules in this category generate randomized alias records for various resource types, including CNAME, DNAME, NS, MX, HTTPS, SVCB, SRV, and SPF-TXT.

Typically, these modules create random alias records in the format `alias######.yourdomain.com`, where `######` is a randomly generated number.

The idea is that if a client or resolver chooses to resolve these aliases further, it will result in the generation of additional aliases, theoretically creating an infinite chain of random alias resolutions.
