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

# use
Normal operation:

`ipkvm-watch -i <path to indicators yaml>`

`-d` turns on debug logging
`-m` turns on MDNS discovery by subprocess only which can sometimes be stealthier on macos (avoids user notifications)

## Sample Output
```json
{
  "mdns": [
    {
      "Domain": "glkvm.local",
      "Vendor": "Comet",
      "IPv4s": [],
      "IPv6s": []
    }
  ],
  "arp": [
    {
      "MAC": "94:83:c4:ae:ac:2a",
      "Vendor": "Comet"
    }
  ],
  "usb": [
    {
      "Vendor": "Comet",
      "Manufacturer": "GLKVM",
      "Confidence": "low"
    }
  ],
  "http": [
    {
      "Vendor": "Comet",
      "Confidence": "high",
      "Type": "SSL",
      "Value": "GLKVM",
      "Hostname": "192.168.68.54"
    },
    {
      "Vendor": "Comet",
      "Confidence": "medium",
      "Type": "Title",
      "Value": "GLKVM",
      "Hostname": "192.168.68.54"
    },
    {
      "Vendor": "Comet",
      "Confidence": "high",
      "Type": "Favicon",
      "Value": "4cd10e52d0a12897ed058184e2b6136c",
      "Hostname": "192.168.68.54"
    }
  ]
}
```

# TODO:
- handle duplicates in the arp table from multiple adapters
- parallelize http queries
- use EDID & Display Fingerpriting
    - https://blog.grumpygoose.io/unemployfuscation-1a1721485312

# Credits
a LOT of the work for the IOCs comes from https://www.runzero.com/blog/oob-p1-ip-kvm/ which is written by

- HD Moore
- Tod Beardsley
- Matthew Kienow
