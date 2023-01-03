#!/bin/bash
#
# A script for create a test environment

ip netns add host1
ip netns add host2

ip link add type veth peer
ip link add type veth peer

ip link set dev veth1 up
ip link set dev veth3 up

ip link set dev veth0 netns host1
ip link set dev veth2 netns host2

ip netns exec host1 ip link set dev eth0 up
ip netns exec host1 ip addr add 1.0.0.1/24 dev veth0
ip netns exec host2 ip link set dev eth2 up
ip netns exec host2 ip addr add 1.0.0.2/24 dev veth2

