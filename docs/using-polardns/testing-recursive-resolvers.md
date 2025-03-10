---
layout: default
title: Testing of Recursive DNS Resolvers
parent: Using PolarDNS
has_children: false
nav_order: 4
---

# Testing of Recursive DNS Resolvers

Here's a high-level overview of what you need in order to start testing recursive DNS servers.

1. Purchase a domain for your tests e.g., `example.com` using your favorite domain registrar.
2. Get 2 Linux VPS instances with public and <u>static</u> IP addresses - these will be your nameservers.
3. Deploy the PolarDNS server on both instances.
4. Edit the ``polardns/polardns.toml`` configuration file on each instance and change your domain name and nameserver IP addresses accordingly - same configuration on both.
5. In the domain registrar, select to manage the domain using your own nameservers. You will need to specify the primary and secondary NS - provide IP addresses of your instances.

Now your infrastructure should be ready for testing of any recursive DNS resolver of your choice.

---

| Previous: [Features and Response Modifiers Explained](features-and-modifiers) | Next: [Testing Process Breakdown](testing-process-breakdown)
