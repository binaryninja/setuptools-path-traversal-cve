#!/bin/bash
set -e

echo "[VICTIM] Starting SSH server for validation..."
/usr/sbin/sshd

echo "[VICTIM] SSH server running on port 22"

# Run the attack
python tarball_client.py

echo ""
echo "============================================================"
echo "CONTAINER STAYING ALIVE FOR INVESTIGATION"
echo "============================================================"
echo ""
echo "IOC Collection Commands:"
echo "  cat /etc/cron.d/backdoor           # Check cron backdoor"
echo "  cat /root/.ssh/authorized_keys     # Check injected SSH key"
echo "  cat /home/victim/.bashrc           # Check bashrc backdoor"
echo "  bash --login                       # Trigger bashrc beacon"
echo ""
echo "From attacker container (server):"
echo "  curl http://server:8080/validate/ssh  # Validate SSH access"
echo "  curl http://server:8080/status        # Check beacon callbacks"
echo ""

# Keep container alive
sleep infinity
