# GreaseMonkey
The toolbox every developer needs. Scripts for automation, utilities for efficiency, and a collection of well-oiled solutions to keep everything running.

# Firewall WSL fix
New-NetFirewallHyperVRule -Name "WSLProBridge" -DisplayName "Allow Ubuntu Pro WSL bridge" `-Direction Inbound -VMCreatorId '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'` -Protocol TCP -LocalPorts 53618 -Action Allow
