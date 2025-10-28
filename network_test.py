import subprocess
import logging
import yaml

logging.basicConfig(level=logging.INFO)

# first we need to know what hosts on are on the LAN
# let's check ARP first before we port sc
def get_arp_via_subprocess() -> tuple[set[str], set[str]]:
    ips = set()
    macs = set()
    # run arp -a and capture output
    result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
    output = result.stdout
    for line in output.splitlines():
        # pull IPs out via regex
        # sample output line: "? (192.168.68.56) at e6:c0:b:4b:d:26 on en0 ifscope [ethernet]"
        first_paren = line.find('(')
        closing_paren = line.find(')')
        if first_paren == -1 or closing_paren == -1:
            logging.warning("Could not find parentheses in line: %s", line)
            continue
        ip = line[first_paren + 1:closing_paren]
        start_mac = line.find(' at ') + 4
        end_mac = line.find(' on ')
        if start_mac == -1 or end_mac == -1:
            logging.warning("Could not find MAC address in line: %s", line)
            continue
        mac = line[start_mac:end_mac]
        ips.add(ip)
        macs.add(mac)
        logging.info(f"IP Address: %s, MAC Address: %s", ip, mac)

    return ips, macs

def check_macs(macs: set[str], indicators: dict) -> list[dict]:
    found = []
    for vendor, prefixes in indicators['network']['mac_addresses'].items():
        for prefix in prefixes['prefixes']:
            for mac in macs:
                if mac.lower().startswith(prefix['prefix'].lower()):
                    found.append({
                        'type:': 'mac_address',
                        'vendor': vendor,
                        'mac_address': mac,
                        'confidence': prefix['confidence']
                    })
    return found
        

if __name__ == "__main__":
    # load the indicators yaml
    with open("indicators.yaml", "r") as f:
        indicators = f.read()
        indicators = yaml.safe_load(indicators)
    # get the mac addresses and ips on the LAN
    ips, macs = get_arp_via_subprocess()
    # check the mac addresses against known vendors
    mac_indications = check_macs(macs, indicators)
    print(mac_indications)
