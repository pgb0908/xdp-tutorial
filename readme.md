# XDP Tutorial Project

This project is a collection of XDP (eXpress Data Path) examples. Each sample demonstrates a specific feature or use case of XDP.

## Samples

Here is a summary of the samples in this project:

*   **sample01-basic_bpf:** A basic BPF program that uses a tracepoint to detect the execution of the `echo` command. This sample is a good introduction to BPF concepts.
*   **sample02-xdp_pass:** Demonstrates the most basic XDP actions: `XDP_PASS`, which passes the packet to the kernel's network stack, and `XDP_DROP`, which drops the packet.
*   **sample03-map-and-pinning:** Shows how to use BPF maps to store and share data between the kernel and user space. It also demonstrates map pinning, which allows maps to persist even after the BPF program is unloaded. This sample collects statistics about packets.
*   **sample04-packet_parsing:** Demonstrates how to parse various packet headers, including Ethernet, VLAN, IPv4, IPv6, ICMPv4, and ICMPv6. It filters packets based on ICMP sequence numbers.
*   **sample05-packet_redirecting:** Implements a simple router using `bpf_redirect` and `bpf_fib_lookup`. It forwards packets based on the kernel's forwarding information base (FIB).
*   **sample06-packet_control:** Shows how to dynamically control packet filtering using a BPF map. The filtering rules can be changed from user space without reloading the XDP program.
*   **sample07-lb_nat:** Implements a Layer 4 load balancer with Network Address Translation (NAT). It uses connection tracking to manage connections and rewrites packet headers to direct traffic to backend servers.
*   **sample08-RSV_pattern:** Implements a load balancer using IPIP encapsulation. It wraps incoming packets in a new IP header to route them to backend servers, avoiding the need for NAT.
