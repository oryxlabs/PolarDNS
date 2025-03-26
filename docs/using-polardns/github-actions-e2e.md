---
layout: default
title: Automated E2E Testing with GitHub Actions
parent: Using PolarDNS
has_children: false
nav_order: 6
---

# Automated E2E Testing with GitHub Actions

PolarDNS can be integrated with a variety of DNS resolvers to run a comprehensive end-to-end (E2E) DNS server test suite.

This integration is powered by GitHub Actions, with reference templates (workflows) currently available for the following six DNS resolvers:

- BIND9 ([e2e-bind9.yaml](https://github.com/oryxlabs/PolarDNS/blob/main/.github/workflows/e2e-bind9.yaml))
- CoreDNS ([e2e-coredns.yaml](https://github.com/oryxlabs/PolarDNS/blob/main/.github/workflows/e2e-coredns.yaml))
- Dnsmasq ([e2e-dnsmasq.yaml](https://github.com/oryxlabs/PolarDNS/blob/main/.github/workflows/e2e-dnsmasq.yaml))
- Knot Resolver ([e2e-knot-v5.yaml](https://github.com/oryxlabs/PolarDNS/blob/main/.github/workflows/e2e-knot-v5.yaml), [e2e-knot-v6.yaml](https://github.com/oryxlabs/PolarDNS/blob/main/.github/workflows/e2e-knot-v6.yaml))
- PowerDNS ([e2e-powerdns.yaml](https://github.com/oryxlabs/PolarDNS/blob/main/.github/workflows/e2e-powerdns.yaml))
- Unbound ([e2e-unbound.yaml](https://github.com/oryxlabs/PolarDNS/blob/main/.github/workflows/e2e-unbound.yaml))

When a GitHub Action is triggered (e.g., on commit or manually), the workflows perform the following steps:

1. Start the selected DNS resolver in a Docker container
2. Start PolarDNS in a separate Docker container
3. Connect the selected resolver to PolarDNS
4. Run the E2E test suite against the selected DNS resolver

To add your own E2E tests, simply place them in the [test-e2e/](https://github.com/oryxlabs/PolarDNS/tree/main/test-e2e) directory.

Looking for a full-featured DNS server E2E test suite? Reach out to `ivan.jedek@oryxlabs.com`.

---

| Previous: [Testing Process Breakdown](testing-process-breakdown) | Next: [Adding New Features](../adding-new-features/adding-new-features) |
