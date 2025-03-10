---
layout: default
title: PolarDNS Modularity
parent: Adding New Features
has_children: false
nav_order: 3
---

# PolarDNS Modularity

Since version `v1.1`, PolarDNS has supported features defined as standalone, pluggable modules in the form of `.toml` files. You can look at the module repository [here](https://github.com/oryxlabs/PolarDNS/tree/main/polardns/modules).

Internally, the modularity of PolarDNS is implemented in such a way that, when you start PolarDNS, it first creates a copy of itself and incorporates all the modules' code. This generates the `polardns_real.py` file. It then runs this newly created file, and that's when the PolarDNS server actually begins operating.

This has specific implications for debugging the PolarDNS server, which we'll cover later.

!!! Ensure you do NOT make changes directly to the `polardns_real.py` file, as your changes might be overwritten !!!

Now let's see where we can add our code.

---

| Previous: [Process of Adding New Features](process-of-adding) | Next: [Where to Add the Code](where-to-add-code) |
