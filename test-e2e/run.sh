#!/bin/bash

resolver="${1:-127.0.0.1}"
port="${2:-10053}"
domain="${3:-yourdomain.com}"

#################################

# sanity test
dig @${resolver} -p ${port} always.${domain} | grep 'IN.*A.*2.3.4.5'

#
# add your tests here
#
# or contact: ivan.jedek@oryxlabs.com
#

