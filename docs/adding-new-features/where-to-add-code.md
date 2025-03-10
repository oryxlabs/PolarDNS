---
layout: default
title: Where to Add the Code
parent: Adding New Features
has_children: false
nav_order: 4
---

# Where to Add the Code

When adding new features to PolarDNS, it is generally recommended to work directly within the `polardns/core.py` file and implement the new feature there, rather than adding it to a `.toml` file right away.

This is because editing a `.py` file is much more convenient. It provides the advantages of syntax highlighting, code autocompletion, and all the other benefits of modern code editors like PyCharm and others.

The correct place to add the new feature code is within the `process_DNS()` function, the core function of PolarDNS. This function does all the parsing and decision making.

---

| Previous: [PolarDNS Modularity](polardns-modularity) | Next: [The process_DNS() Function](process_dns-function) |
