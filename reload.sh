#!/usr/bin/env bash
set -e

make
sudo rmmod tcp_probe_fixed || true
sudo insmod tcp_probe_fixed.ko port=2083 full=1
