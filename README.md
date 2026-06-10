# WHM Real-Time Outbound Email Spam Enforcer

An enterprise-ready systems daemon for cPanel/WHM architecture. It continuously tails live Exim transaction queues to catch high-velocity mail leaks originating from compromised mailboxes or malicious script injectors, alerts human administrators via support pipelines, and auto-freezes malicious tenants instantly.

## Architecture Controls
* **Real-time Pipeline:** Listens instantly to active sockets (`/var/log/exim_mainlog`).
* **Multi-Strike Engine:** Provides tolerance for minor spikes but clamps accounts upon an unmitigated 2nd hour limit breach.
* **WHM Integrated System Hooks:** Dispatches core `whmapi1` runtime actions to cleanly park the cPanel user environment entirely.

## Installation / Deployment Command Sheet

Execute these terminal commands on the root environment of any target WHM node to deploy the service straight from GitHub:

```bash
# 1. Pull script source down directly to systems binary bin paths
curl -sSL https://raw.githubusercontent.com/Sajibekanti/exim_realtime_blocker/main/exim_realtime_blocker.sh -o /usr/local/bin/exim_realtime_blocker.sh

# 2. Grant operations executable permissions 
chmod +x /usr/local/bin/exim_realtime_blocker.sh

# 3. Pull down the daemon system service architecture configuration properties
curl -sSL https://raw.githubusercontent.com/Sajibekanti/exim_realtime_blocker/main/exim-blocker.service -o /etc/systemd/system/exim-blocker.service

# 4. Trigger system initialization components
systemctl daemon-reload
systemctl enable exim-blocker.service
systemctl start exim-blocker.service
