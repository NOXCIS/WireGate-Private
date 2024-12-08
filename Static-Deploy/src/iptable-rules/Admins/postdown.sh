#!/bin/bash
# Copyright(C) 2024 NOXCIS [https://github.com/NOXCIS]
# Under MIT License
WIREGUARD_INTERFACE=ADMINS
WIREGUARD_LAN=10.0.0.1/24
MASQUERADE_INTERFACE=eth0

CHAIN_NAME="WIREGUARD_$WIREGUARD_INTERFACE"

iptables -t nat -D POSTROUTING -o $MASQUERADE_INTERFACE -j MASQUERADE -s $WIREGUARD_LAN

# Remove and delete the WIREGUARD_wg0 chain
iptables -D FORWARD -j $CHAIN_NAME
iptables -F $CHAIN_NAME
iptables -X $CHAIN_NAME