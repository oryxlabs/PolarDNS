---
layout: default
title: Getting Started with PolarDNS
parent: Using PolarDNS
has_children: false
nav_order: 1
---

# Getting Started with PolarDNS

By default, when the PolarDNS server starts, it listens on all network interfaces via UDP and TCP on port 53 (0.0.0.0:53), ready to respond to DNS queries.

You can test it locally by asking the following sample query, which should always resolve to something.

Ask in UDP mode:
```
dig always.yourdomain.com @127.0.0.1
```

Ask in TCP mode:
```
dig always.yourdomain.com @127.0.0.1 +tcp
```

You should receive an ``A`` record with the ``2.3.4.5`` IP address, similarly like in this screenshot:

<img width="700" alt="PolarDNS example usage" src="../assets/polardns-example-usage.jpg">

This indicates that the server is working properly.

--- 

| Previous: [Using PolarDNS](using-polardns) | Next: [Understanding the Main Concept](main-concept)
