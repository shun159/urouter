#!/bin/bash
#
# A script for create a test environment

ip netns add host1
ip netns add host2
ip netns add host3
ip netns add host4

ip link add type veth peer
ip link add type veth peer
ip link add type veth peer
ip link add type veth peer

ip link set dev veth1 up
ip link set dev veth3 up
ip link set dev veth5 up
ip link set dev veth7 up

ip link set dev veth0 netns host1
ip link set dev veth2 netns host2
ip link set dev veth4 netns host3
ip link set dev veth6 netns host4

ip netns exec host1 ip link set dev veth0 up
ip netns exec host1 ip addr add 1.0.0.1/24 dev veth0
ip netns exec host2 ip link set dev veth2 up
ip netns exec host2 ip addr add 1.0.0.2/24 dev veth2

ip netns exec host3 ip link set dev veth4 up
ip netns exec host3 ip addr add 1.0.0.3/24 dev veth4
ip netns exec host4 ip link set dev veth6 up
ip netns exec host4 ip addr add 1.0.0.4/24 dev veth6

