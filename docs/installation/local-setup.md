---
layout: default
title: Local Setup
parent: Installation
has_children: false
nav_order: 1
has_toc: false
---

# Local Setup

These steps explain how to install PolarDNS locally and experiment with it without requiring the purchase of a dedicated domain:

1. Install Python 3.11 or newer.
2. (Optional) Edit the `polardns.toml` configuration file and adjust the settings according to your preferences.
3. Run `python polardns.py`

As a result, you should see something like this:
```
1740073244.6643643 | PolarDNS v1.6.0 server starting up
1740073244.6653879 | Starting listener at tcp://0.0.0.0:53
1740073244.6657066 | Starting listener at udp://0.0.0.0:53
```

This indicates that the server is up and running.

---

| Previous: [Installation](installation) | Next: [Public Setup (External Domain)](public-setup) |
