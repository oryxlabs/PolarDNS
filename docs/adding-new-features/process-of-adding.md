---
layout: default
title: Process of Adding New Features
parent: Adding New Features
has_children: false
nav_order: 2
---

# Process of Adding New Features

The following sections outline the process of adding new features to PolarDNS. These instructions aim to provide a guidance to follow and a recommended workflow. Some of the core concepts and technical details about the PolarDNS inner workings are mentioned here as well.

In a nutshell, the easiest way of adding a new feature to PolarDNS is to take an existing feature with a similar functionality and use it as a template for your new feature. Then, change the functionality according to your needs.

Here's a step-by-step overview of the process:

1. Edit the `polardns/core.py` file
2. Create a copy of a similar feature, such as the [`always`](../catalogue/html/always.html) feature
3. Implement the new feature:
   - 3.1. Change the initial matching rule
   - 3.2. Change the logic to build your DNS response
   - 3.3. Test the functionality locally using `dig`/`nslookup` and Wireshark
4. Run all tests (strongly recommended)
5. Optionally, move the feature into a separate module (`.toml` file)

Let's briefly discuss the modularity in PolarDNS.

---

| Previous: [Introduction](introduction) | Next: [PolarDNS Modularity](polardns-modularity) |
