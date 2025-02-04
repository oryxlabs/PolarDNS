---
layout: default
title: The process_DNS() Function
parent: Adding New Features
has_children: false
nav_order: 5
---

# The process_DNS() Function

Each time the PolarDNS server receives a network packet, it attempts to parse it by calling the `process_DNS()` function. If the parsing goes as expected and we have a proper DNS request, the function will then proceed to decide how to respond.

The function will try to determine which feature to activate based on the question found in the DNS request, typically specifically focusing on the initial part of the hostname (domain name).

This particular decision-making logic is defined in the final part of the `process_DNS()` function, within the lengthy if-elif-else code section that attempts to match the pattern of the first subdomain.

You can simply add another `elif` statement there and start working on the new feature directly.

For instance, a feature that activates upon resolving the `abcd.yourdomain.com` domain could look like this:
```
if req.first_subdomain.startswith("abcd"):
   ... add your code here ...
```
Now you just need to actually craft your DNS response and you're all set. Let's see how to do that.

---

| Previous: [Where to Add the Code](where-to-add-code) | Next: [Crafting DNS Responses](crafting-dns-responses) |
