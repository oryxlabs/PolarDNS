# Table of Contents

- [Introduction](#introduction)
- [Bug Reports](#bug-reports)
- [Pull Requests](#pull-requests)
- [Adding New Features](#adding-new-features)
	- [PolarDNS Modularity](#polardns-modularity)
	- [Where to Add the Code](#where-to-add-the-code)
	- [The process_DNS() Function](#the-process-dns-function)
	- [Crafting DNS Responses](#crafting-dns-responses)
- [Debugging PolarDNS](#debugging)
- [Other Ways to Contribute](#other-ways-to-contribute)

## <a name="introduction"></a>Introduction

This file serves as a supplement to the [README](https://github.com/oryxlabs/PolarDNS/blob/main/README.md) file. It contains information specifically about how contributors can participate in the development of PolarDNS.

## <a name="bug-reports"></a>Bug Reports

PolarDNS uses Github Issues to keep track of bug reports.

You can submit a bug report [here](https://github.com/oryxlabs/PolarDNS/issues).

Please be sure to include the version of PolarDNS that you are using, steps to reproduce the bug, and a description of what you expect to be the correct behavior.

## <a name="pull-requests"></a>Pull Requests

OryxLabs welcomes your code contribution to PolarDNS in the form of a Github Pull Request (PR).

Because not all PolarDNS committers use Github daily, it is helpful to send a notification email to [ivan.jedek@oryxlabs.com](mailto:ivan.jedek@oryxlabs.com) referencing the PR and including a short description of the functionality of the patch.

## <a name="adding-new-features"></a>Adding New Features

The following sections outline the process of adding new features to PolarDNS. These instructions aim to provide a guidance to follow and a recommended workflow. Some of the core concepts and technical details about the PolarDNS inner workings are mentioned here as well.

In a nutshell, the easiest way of adding a new feature to PolarDNS is to take an existing feature with a similar functionality and use it as a template for your new feature. Then, change the functionality according to your needs.

Here's a step-by-step overview of the process:

1. Edit the `polardns.py` file
2. Create a copy of a similar feature, such as the [always](docs/catalogue/general-features.md#always-resolve-to-ip-always) feature
3. Implement the new feature:
   - 3.1. Change the initial matching rule
   - 3.2. Change the logic to build your DNS response
   - 3.3. Test the functionality locally using `dig`/`nslookup` and Wireshark
4. Run all tests (strongly recommended)
5. Optionally, move the feature into a separate module (`.toml` file)

Let's briefly discuss the modularity in PolarDNS.

### <a name="polardns-modularity"></a>PolarDNS Modularity

Since version `v1.1`, PolarDNS has supported features defined as standalone, pluggable modules in the form of `.toml` files. You can look at the module repository [here](https://github.com/oryxlabs/PolarDNS/tree/main/modules).

Internally, the modularity of PolarDNS is implemented in such a way that, when you start PolarDNS, it first creates a copy of itself and incorporates all the modules' code. This generates the `polardns_real.py` file. It then runs this newly created file, and that's when the PolarDNS server actually begins operating.

This has specific implications for debugging the PolarDNS server, which we'll cover later.

:exclamation: Keep in mind not to make changes to the `polardns_real.py` file, as your changes might be overwritten :exclamation:

Now let's see where we can add our code.

### <a name="where-to-add-the-code"></a>Where to Add the Code

When adding new features to PolarDNS, it is generally recommended to work directly within the `polardns.py` file and implement the new feature there, rather than adding it to a `.toml` file right away.

This is because editing a `.py` file is much more convenient. It provides the advantages of syntax highlighting, code autocompletion, and all the other benefits of modern code editors like PyCharm and others.

The correct place to add the new feature code is within the `process_DNS()` function, the core function of PolarDNS. This function does all the parsing and decision making.

### <a name="the-process-dns-function"></a>The process_DNS() Function

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

### <a name="crafting-dns-responses"></a>Crafting DNS Responses

Crafting the actual DNS responses is a crucial part of the process. This is where PolarDNS provides you the flexibility to innovate and experiment freely.

If you examine a few existing features, you'll notice that they are quite similar and each of them essentially constructs some kind of DNS response.

They all share a similar structure that should be maintained for clarity. Essentially, each feature typically contains the following four code sections:

1. Steps to construct the DNS header
2. Steps to construct the QUESTION section
3. Steps to construct the ANSWER section. This is where you will probably make the most changes.
4. Steps to send the packet out and print (log) a message on the console

And that should in essence cover most of what you need for adding new features in PolarDNS.

## <a name="debugging"></a>Debugging PolarDNS

Because of the way modularity is implemented in PolarDNS, a specific method must be used when debugging.

To debug PolarDNS, it's important to set breakpoints in the generated `polardns_real.py` file rather than the `polardns.py` file.

For example, once running PolarDNS in the PyCharm debugger, simply open the `polardns_real.py` file and set your breakpoints there to debug your code.

Here's a step-by-step procedure to confirm that you can debug it:
1. Click `Debug 'polardns'` in PyCharm
2. Open the `polardns_real.py` file
3. Set a breakpoint in the `process_DNS()` function
4. Send a DNS query to your PolarDNS instance, e.g. `dig always.yourdomain.com @127.0.0.1`
5. This should immediately trigger your breakpoint

## <a name="other-ways-to-contribute"></a>Other Ways to Contribute

Don't worry if you're unable to contribute code or report bugs to PolarDNS.

You can always share ideas or suggestions to improve the project by sending an email to [ivan.jedek@oryxlabs.com](mailto:ivan.jedek@oryxlabs.com).
 
Thank you!

