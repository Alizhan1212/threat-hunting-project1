#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Week 06 - Benign emulation of ATT&CK T1059.004 (Unix Shell)
#
# Runs a short chain of HARMLESS commands through bash/sh, including one
# Base64-encoded command, so you can observe the telemetry they generate.
# It does NOT download, modify, persist, or delete anything.
#
# RUN ONLY in your own lab (Kali VM / WSL). Not on shared or work machines.
#
# Technique map:
#   Step 1  T1059.004 + T1033         Unix Shell + System Owner/User Discovery
#   Step 2  T1059.004 + T1082         Unix Shell + System Information Discovery
#   Step 3  T1059.004 + T1027.010 + T1140   Encoded command (Base64) decoded and run
#   Step 4  T1082                     OS release information
#   Step 5  T1087.001                 Local Account Discovery (/etc/passwd)
#   Step 6  T1016                     System Network Configuration Discovery
# ---------------------------------------------------------------------------

LOG="$(dirname "$0")/simulation_log.txt"

step() {
    local line
    line="[$(date '+%Y-%m-%d %H:%M:%S')] $1 - $2"
    echo -e "\e[36m${line}\e[0m"
    echo "${line}" >> "${LOG}"
}

echo "=== Week 06 T1059.004 simulation started on $(hostname) ===" >> "${LOG}"

# Step 1: T1059.004 - bash -c running id / whoami
step "T1059.004 / T1033" "bash -c 'id; whoami'"
bash -c 'id; whoami'

# Step 2: T1059.004 - sh -c running uname / hostname
step "T1059.004 / T1082" "sh -c 'uname -a; hostname'"
sh -c 'uname -a; hostname'

# Step 3: T1027.010 / T1140 - Base64 encoded command decoded and piped into bash
step "T1059.004 / T1027.010 / T1140" "echo <base64> | base64 -d | bash  (decodes to: whoami)"
ENC="$(echo -n 'whoami' | base64)"
bash -c "echo ${ENC} | base64 -d | bash"

# Step 4: T1082 - OS information
step "T1082" "cat /etc/os-release"
cat /etc/os-release

# Step 5: T1087.001 - Local account discovery (first 5 lines only)
step "T1087.001" "head -n 5 /etc/passwd"
head -n 5 /etc/passwd

# Step 6: T1016 - Network configuration
step "T1016" "ip addr; ip route"
ip addr
ip route

echo "=== Simulation finished ===" >> "${LOG}"
echo -e "\n\e[32mDone. Now check the audit log (see report section 5) and the timestamps in ${LOG}\e[0m"
