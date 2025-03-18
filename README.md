<img width="800" alt="PolarDNS logo" src="https://raw.githubusercontent.com/oryxlabs/PolarDNS/main/docs/assets/polardns-logo-for-white-bg.png">
PolarDNS is a specialized authoritative DNS server written in Python 3.x, originally developed as a tool for security testing of DNS recursive resolvers from the server-side.
<br><br>
It allows the operator to produce custom DNS responses, making it suitable for in-depth DNS protocol testing purposes.

_

PolarDNS can be used for testing of:

- DNS resolvers (server-side)
- DNS clients
- DNS libraries
- DNS parsers and dissectors
- any software handling DNS information

It supports both UDP and TCP protocols, and it gives the operator full control over the DNS protocol layer.

PolarDNS server can produce variety of non-standard and non-compliant DNS responses, DNS responses violating the RFC specifications, including highly abnormal and malformed DNS responses.

This can be useful for:
- Functional testing
- RFC compliance
- Vulnerability research

## Installation

There are three available methods to install PolarDNS.

PolarDNS requires Python 3.11 or newer and has no additional dependencies.

### Method 1: Installation via Pip

This is the easiest way to install and run PolarDNS:
```
pip install polardns
polardns
```

### Method 2: Traditional installation

You can also clone the repository and run PolarDNS directly:
```
git clone https://github.com/oryxlabs/PolarDNS.git
cd PolarDNS
python polardns.py
```

This method is recommended if you plan to debug or modify the code, or add new features.

### Method 3: Running PolarDNS in Docker

You can also run PolarDNS in a Docker container:
```
docker run -p 53:53/tcp -p 53:53/udp oryxlabs/polardns
```

## Running PolarDNS

PolarDNS server is configurable via the `polardns/polardns.toml` configuration file.

- For testing purposes, the default configuration should work fine for running locally.
- However, you may want to adjust the configuration by adding your domain and nameserver IP addresses.

Upon starting PolarDNS, you should see output similar to the following:
```
python polardns.py
1741599804.9039893 | PolarDNS v1.6.1 server starting up
1741599804.9039893 | Using '/path/to/your/polardns/polardns.toml' config file
1741599804.9039893 | Starting listener at tcp://0.0.0.0:53
1741599804.9039893 | Starting listener at udp://0.0.0.0:53
```
This indicates that the server is up and running.

## Working with PolarDNS

By default, the server starts listening on all interfaces on UDP and TCP port 53 (0.0.0.0:53), ready to answer DNS queries.

You can test it locally by asking the following sample query, which should always resolve to something.

Ask in UDP mode:
```
dig always.yourdomain.com @127.0.0.1
```

Ask in TCP mode:
```
dig always.yourdomain.com @127.0.0.1 +tcp
```

You should receive an ``A`` record with the ``2.3.4.5`` IP address, similarly like in this screenshot:

<img width="700" alt="PolarDNS example usage" src="https://raw.githubusercontent.com/oryxlabs/PolarDNS/main/docs/assets/polardns-example-usage.jpg">

This indicates that the server is working properly.

## Main concept

By asking the PolarDNS server to resolve something, you are essentially giving it instructions how it should respond to you. This means that you (the client) dictate the PolarDNS server what kind of response it should produce for you.

For instance, consider the following query:
```
dig always.ttl2000000000.slp1500.yourdomain.com @127.0.0.1
```

You should receive an ``A`` record with the ``2.3.4.5`` IP address again, but this time with a TTL value of 2,000,000,000 (63.4 years) and after a delay of 1.5 seconds:

<img width="700" alt="PolarDNS custom TTL and latency" src="https://raw.githubusercontent.com/oryxlabs/PolarDNS/main/docs/assets/polardns-custom-ttl-and-latency.jpg">

In the above example, we have used the [`always`](https://oryxlabs.github.io/PolarDNS/catalogue/html/always.html) basic feature (which always resolves to something), and combined it with the [`ttl`](https://oryxlabs.github.io/PolarDNS/catalogue/html/ttl.html) modifier to adjust the TTL value and the [`slp`](https://oryxlabs.github.io/PolarDNS/catalogue/html/slp.html) modifier to wait before sending the response out.

## PolarDNS functionalities

PolarDNS has the following main functionalities:
1. **Features**: These can produce various DNS responses. Most features have parameters, meaning that it is possible to adjust their behavior to produce variety of different DNS responses.
1. **Response modifiers**: These can further modify the DNS responses coming out from the PolarDNS server. Modifiers are independent on the selected feature and can be combined freely.

There are over 70 different features and 19 response modifiers currently implemented. By using different features and combining them together with different response modifiers, it is possible to produce countless variants of given response.

See the included **[catalogue](https://oryxlabs.github.io/PolarDNS/catalogue/catalogue.html)** of all implemented **features** and **response modifiers**.

This gives PolarDNS capacity to produce highly unusual, abnormal, and even malformed DNS responses, allowing the operator to see how the receiving side handles such situations and whether the receiving side is technically robust and mature.

Some examples of DNS responses which PolarDNS can produce contain:
-	Alias (CNAME) chains and alias loops
-	DNS header malformations (ID, Flags, number of sections)
-	Injection of unsolicited records (cache poisoning)
-	Injection of arbitrary bytes of arbitrary lengths
-	Incomplete / empty / NULL byte(s) responses
-	Compression issues (loops, invalid pointers)
-	Slowly transmitted chunked responses
-	Illegal labels or domain name lengths
-	Arbitrary number of TXT records of arbitrary size
-	Packet length manipulations (TCP)
- Etc.

These can lead to discovery of various vulnerabilities such as:
-	Sloth domain attacks
-	Phantom domain attacks
-	Domain lock-up attacks
-	Cache poisoning
-	Resource exhaustion
-	Crashes, DoS

See the [BlackHat MEA 2023](https://github.com/oryxlabs/PolarDNS/tree/main/docs/pptx) presentations (including BONUS slides) for more details, many more examples and use-cases.

## Testing of recursive DNS resolvers

Here's a high-level overview of what you need in order to start testing recursive DNS servers.

1. Purchase a domain for your tests e.g., ``example123.com`` using your favorite domain registrar.
2. Get 2 Linux VPS instances with public and static IP addresses - these will be your nameservers.
3. Deploy the PolarDNS server on both instances.
4. Edit the ``polardns/polardns.toml`` configuration file on each instance and change your domain name and nameserver IP addresses accordingly - same configuration on both.
5. In the domain registrar, select to manage the domain using your own nameservers. You will need to specify the primary and secondary NS - provide IP addresses of your instances.

Now your infrastructure should be ready for testing of any recursive DNS resolver of your choice.

### Testing process breakdown

In order to start testing a target DNS recursive resolver, you have to target your queries to the target DNS resolver, e.g.

```
dig always.example123.com @<TARGET-RESOLVER-IP>
```
For example, to test the CloudFlare public DNS:
```
dig always.example123.com @1.1.1.1
```

During the resolution, the target DNS resolver will contact your authoritative PolarDNS nameservers (managing your example123.com testing domain) to resolve the query.

One of your PolarDNS servers will respond to the target DNS resolver. The target DNS resolver will obtain the response from PolarDNS and will parse it and process it. Afterwards, the resolver will send you (the client) the answer.

By instructing the DNS resolver to resolve various subdomains under your example123.com domain, you can effectively test the behavior of the DNS resolver and see how it handles various unexpected situations (responses).

For instance, how does it handle a situation when it obtains a malformed DNS response, a response with an injected record, or a record containing illegal characters, and what kind of answer does it ultimately send to you, the client?

## Adding new features

Adding new features to PolarDNS is essential for discovering truly novel DNS issues. And with PolarDNS, you can do just that relatively easily.

PolarDNS allows you to quickly add a new feature, try out your ideas, or develop a PoC without having to build your own DNS server. All you need is ability to understand Python code and a curiosity to experiment with the DNS protocol.

There is a detailed, step-by-step [contribution guide](https://github.com/oryxlabs/PolarDNS/blob/main/CONTRIBUTING.md) to get you started. There, you'll find not only how to add new features but also how to debug PolarDNS, submit issues, share ideas, and more.

## Links

Here are some excellent resources that are useful when playing with PolarDNS.

DNS Protocol related links:
- https://en.wikipedia.org/wiki/List_of_DNS_record_types
- https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml

DNS servers:
- https://en.wikipedia.org/wiki/Comparison_of_DNS_server_software
- https://www.lifewire.com/free-and-public-dns-servers-2626062

## Credits

Thank you to everyone who has contributed to PolarDNS! ❤️

<a href="https://github.com/oryxlabs/polardns/graphs/contributors">
  <img src="https://contrib.rocks/image?&columns=25&max=10000&&repo=oryxlabs/polardns" noZoom />
</a>

