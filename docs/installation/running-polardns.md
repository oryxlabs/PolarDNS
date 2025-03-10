---
layout: default
title: Running PolarDNS
parent: Installation
has_children: false
nav_order: 2
has_toc: false
---

# Running PolarDNS

PolarDNS server is configurable via the `polardns/polardns.toml` configuration file.

- For testing purposes, the default configuration should work fine for running locally.
- However, you may want to adjust the configuration by adding your domain and nameserver IP addresses.

Upon starting PolarDNS, you should see output similar to the following:

```
python polardns.py
1741599804.9039893 | PolarDNS v1.6.1 server starting up
1741599804.9039893 | Using '/path/to/your/polardns/polardns.toml' config file
1741599804.9039893 | Starting listener at tcp://0.0.0.0:53
1741599804.9039893 | Starting listener at udp://0.0.0.0:53
```

This indicates that the server is up and running.

---

| Previous: [Installation Methods](installation-methods) | Next: [Using PolarDNS](../using-polardns/using-polardns) |
