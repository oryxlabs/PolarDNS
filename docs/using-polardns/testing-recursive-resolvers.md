---
layout: default
title: Testing of Recursive DNS Resolvers
parent: Using PolarDNS
has_children: false
nav_order: 4
---

# Testing of Recursive DNS Resolvers

Here's a high-level overview of what you need in order to start testing recursive DNS servers.

1. Purchase a domain for your tests e.g., example123.com
2. Get 2 Linux VPS instances with public and static IP addresses - these will be your nameservers.
3. Deploy the PolarDNS server on both of your VPS instances (nameservers)
4. Make sure to edit the ``polardns.toml`` configuration file and change your domain name and nameserver IP addresses
5. In the domain registrar, select to manage the domain using your own nameservers (you will need to specify 2 public IPs of your servers - primary and secondary NS)

Now your infrastructure should be ready for testing of any recursive DNS resolver of your choice.

---

| Previous: [Features and Response Modifiers Explained](features-and-modifiers) | Next: [Testing Process Breakdown](testing-process-breakdown)
