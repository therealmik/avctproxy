avctproxy
=========

Works with many rack/blade server BMCs

Look for APCP at the start of the TCP stream - usually port 2068, but 5900 with Dell.

Cisco:
 - Visual indication that stream has been downgraded
 - MITM will be very overt and will fail
 - B200M3 blades (currently?) don't support TLS, so just don't downgrade/MITM
 
Dell:
 - iDRAC6 - runs on port 5900
 - Downgrade works, no visual indication
 - MITM works, no visual indication
 - The "encrypt" checkbox basically does nothing useful
 
Please send pull requests for specific systems, firmware version fixed in, etc.

FFS keep your management network segregated - use a VPN client on your desktop
connected to a VPN server directly plugged into BMCs.  Put this in your budget
before you buy the hardware.
