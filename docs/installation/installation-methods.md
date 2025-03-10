---
layout: default
title: Installation Methods
parent: Installation
has_children: false
nav_order: 1
has_toc: false
---

# Installation Methods

There are three available methods to install PolarDNS.

PolarDNS requires Python 3.11 or newer and has no additional dependencies.

## Method 1: Installation via Pip

This is the easiest way to install and run PolarDNS:

```
pip install polardns
polardns
```

## Method 2: Traditional Installation

You can also clone the repository and run PolarDNS directly:

```
git clone https://github.com/oryxlabs/PolarDNS.git
cd PolarDNS
python polardns.py
```

This method is recommended if you plan to debug or modify the code, or add new features.

## Method 3: PolarDNS in Docker

You can also run PolarDNS in a Docker container:

```
docker run -p 53:53/tcp -p 53:53/udp oryxlabs/polardns
```

---

| Previous: [Installation](installation) | Next: [Running PolarDNS](running-polardns) |
