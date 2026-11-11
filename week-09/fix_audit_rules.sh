#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Week 09 - Install the audit rules permanently and load them
#
# Writes the two rules into /etc/audit/rules.d/week9.rules and loads them with
# augenrules, so they survive an auditd restart and a reboot.
#
#   t1059_exec         : logs every program execution by normal users
#   t1003_shadow_read  : logs every read of /etc/shadow
#
# Usage:   bash fix_audit_rules.sh
# ---------------------------------------------------------------------------

set -u

echo "=== Writing /etc/audit/rules.d/week9.rules ==="
sudo mkdir -p /etc/audit/rules.d
sudo tee /etc/audit/rules.d/week9.rules > /dev/null <<'EOF'
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k t1059_exec
-w /etc/shadow -p r -k t1003_shadow_read
EOF
cat /etc/audit/rules.d/week9.rules

echo "=== Making sure auditd is running ==="
sudo systemctl enable auditd
sudo service auditd start 2>/dev/null || true

echo "=== Loading the rules ==="
sudo augenrules --load

echo "=== Loaded rules (you should see TWO lines with t1059_exec and t1003_shadow_read) ==="
sudo auditctl -l

echo "=== Audit status (enabled should be 1) ==="
sudo auditctl -s | head -n 3

echo ">>> If the rules are listed above, take SCREENSHOT 3 now."
