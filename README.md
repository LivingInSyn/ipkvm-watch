# ipkvm-watch
A repository for scripts to detect ip kvms

Right now this is aimed at MacOS devices but should be able to xfer to windows and *nix pretty easily

# Checks
- check ARP table for matching MAC addresses
- HTTP requests to hosts checking:
    - SSL common names
    - Page titles
- Attached USB devices (for unchanged VID/PID/Serials/Manufacturers)
- mDNS checks (still defeated by subnetting/vlans)
- (soon) heuristic checks on USB devices
    - (ex: things that look like KVMs)



## TODO:
- Add DNS (e.g. `nslookup tinypilot.local`) which may allow detection when on a different VLAN (not in ARP table)