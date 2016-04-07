#!/usr/bin/env bash
set -e

make
rmmod tcp_probe_fixed || true
insmod tcp_probe_fixed.ko port=80 full=1
