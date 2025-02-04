---
layout: default
title: Understanding the Main Concept
parent: Using PolarDNS
has_children: false
nav_order: 2
---

# Understanding the Main Concept

By asking the PolarDNS server to resolve something, you are essentially giving it instructions how it should respond to you. This means that you (the client) dictate the PolarDNS server what kind of response it should produce for you.

For instance, consider the following query:
```
dig always.ttl2000000000.slp1500.yourdomain.com @127.0.0.1
```

You should receive an ``A`` record with the ``2.3.4.5`` IP address again, but this time with a TTL value of 2,000,000,000 (63.4 years) and after a delay of 1.5 seconds:

<img width="700" alt="PolarDNS custom TTL and latency" src="../assets/polardns-custom-ttl-and-latency.jpg">

In the above example, we have used the [`always`](../catalogue/html/always.html) basic feature (which always resolves to something), and combined it with the [`ttl`](../catalogue/html/ttl.html) modifier to adjust the TTL value and the [`slp`](../catalogue/html/slp.html) modifier to wait before sending the response out.

| Previous: [Getting Started with PolarDNS](getting-started) | Next: [Features and Response Modifiers Explained](features-and-modifiers)
