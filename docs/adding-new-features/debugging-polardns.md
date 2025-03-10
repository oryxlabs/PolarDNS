---
layout: default
title: Debugging PolarDNS
parent: Adding New Features
has_children: false
nav_order: 7
---

# Debugging PolarDNS

Because of the way modularity is implemented in PolarDNS, a specific method must be used when debugging.

To debug PolarDNS, it's important to set breakpoints in the generated `polardns_real.py` file rather than the `polardns/core.py` file.

For example, once running PolarDNS in the PyCharm debugger, simply open the `polardns_real.py` file and set your breakpoints there to debug your code.

Here's a step-by-step procedure to confirm that you can debug it:
1. Click `Debug 'polardns'` in PyCharm
2. Open the `polardns_real.py` file
3. Set a breakpoint in the `process_DNS()` function
4. Send a DNS query to your PolarDNS instance, e.g. `dig always.yourdomain.com @127.0.0.1`
5. This should immediately trigger your breakpoint

---

| Previous: [Crafting DNS Responses](crafting-dns-responses) | Next: [Useful Links](useful-links) |
