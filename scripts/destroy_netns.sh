#!/bin/bash
#
# A script for teardown the test environment

ip netns del host1
ip netns del host2
ip netns del host3
ip netns del host4

