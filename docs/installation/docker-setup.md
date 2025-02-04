---
layout: default
title: Building and Running PolarDNS Docker Image
parent: Installation
has_children: false
nav_order: 3
has_toc: false
---

# Building and Running PolarDNS Docker Image

Alternatively, you can also deploy PolarDNS as a Docker image for which you can use the following steps:

1) To build the Docker image for PolarDNS:
```
docker build -t polar_dns .
```

2) To run the PolarDNS container:
```
docker run -d --name polar_dns_container -p 53:53/tcp -p 53:53/udp polar_dns
```

--- 

| Previous: [Public Setup (External Domain)](public-setup) | Next: [Using PolarDNS](../using-polardns/using-polardns) |
