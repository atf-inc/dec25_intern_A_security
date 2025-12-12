#!/bin/bash
# IPTables rules for QuantumShield

# Create custom chain
iptables -N QUANTUMSHIELD

# Default policy
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Add rules as needed
# iptables -A INPUT -j QUANTUMSHIELD

