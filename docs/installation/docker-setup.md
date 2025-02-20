---
layout: default
title: PolarDNS in a Docker
parent: Installation
has_children: false
nav_order: 3
has_toc: false
---

# PolarDNS in a Docker

You can also run PolarDNS in a Docker:
```
docker run -p 53:53/tcp -p 53:53/udp oryxlabs/polardns
```

As a result, you should see something like this:
```
Unable to find image 'oryxlabs/polardns:latest' locally
latest: Pulling from oryxlabs/polardns
6e771e15690e: Already exists 
f88e0568d87b: Already exists 
45ccf01a8316: Already exists 
5f200fdec155: Already exists 
b415a54f79ce: Pull complete 
7e1825c50c8e: Pull complete 
0f7a5cc51549: Pull complete 
b297b254c5f7: Pull complete 
b1de20210261: Pull complete 
Digest: sha256:8cafd2dcfab78cebb93a71730de34cbe334ffcacf0542fc3a2973bca1ef4541f
Status: Downloaded newer image for oryxlabs/polardns:latest
1740073244.6643643 | PolarDNS v1.6.0 server starting up
1740073244.6653879 | Starting listener at tcp://0.0.0.0:53
1740073244.6657066 | Starting listener at udp://0.0.0.0:53
```

This indicates that the server is up and running.

--- 

| Previous: [Public Setup (External Domain)](public-setup) | Next: [Using PolarDNS](../using-polardns/using-polardns) |
