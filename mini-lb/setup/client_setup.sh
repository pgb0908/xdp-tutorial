#!/bin/bash

echo "hello"

# Default route via the gateway
ip route del default
ip route add default via 10.111.220.12

tail -f /dev/null