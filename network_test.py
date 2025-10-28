import subprocess
import logging
import yaml
import requests
import mmh3
import codecs
import urllib3
import lxml.html as phtml

logging.basicConfig(level=logging.INFO)
urllib3.disable_warnings()

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
        logging.debug(f"IP Address: %s, MAC Address: %s", ip, mac)

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

def check_http(ips: set[str], indicators: dict) -> list[dict]:
    findings = []
    # foreach IP, check for SSL certs on port 443
    for ip in ips:
        # check page titles
        title_finding = check_page_title(ip, indicators['http']['title'])
        if title_finding:
            findings.append(title_finding)
        # check SSL
        ssl_indicators = indicators['http']['ssl']
        finding = check_ssl(ip, ssl_indicators)
        if finding:
            findings.append(finding)
        # check favicon hashes
        favicon_findings = get_favicon_hash(ip, indicators['http']['favicon'])
        if len(favicon_findings) > 0:
            findings.extend(favicon_findings)
    return findings

def check_page_title(ip: str, indicators: dict) -> dict | None:
    urls = [
        f"http://{ip}",
        f"https://{ip}"
    ]
    for url in urls:
        try:
            page = urllib3.PoolManager().request('GET', url, timeout=3)
            page_data = page.data.decode('utf-8')
            p = phtml.fromstring(page_data)
            title = p.find(".//title").text
            for vendor, titles in indicators.items():
                if title in titles:
                    return {
                        'type:': 'http_title',
                        'vendor': vendor,
                        'title': title,
                        'ip': ip,
                        'confidence': 'high'
                    }
        except Exception as e:
            logging.debug(f"Could not fetch page title from {url}: {e}")
            continue
    return None

def check_ssl(ip: str, ssl_indicators: dict) -> dict | None:
    # run the following command in a subprocess and get the output:
    # openssl s_client -showcerts -connect <ip>:443
    try:
        result = subprocess.run(['openssl', 's_client', '-showcerts', '-connect', f'{ip}:443'], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=3)
    except subprocess.TimeoutExpired:
        logging.warning(f"Timeout expired when trying to connect to {ip}")
        return None
    output = result.stdout
    if result.returncode != 0:
        logging.debug(f"Could not get SSL cert from {ip}: {result.stderr}")
        return None
    # parse the output and extract the relevant information
    for vendor in ssl_indicators:
        if  ssl_indicators[vendor] in output:
            return {
                'type:': 'certificate',
                'vendor': vendor,
                'confidence': 'high'
            }
    return None

def get_favicon_hash(ip: str, indicators: dict) -> list[int]:
    # credit: Shodan https://github.com/phor3nsic/favicon_hash_shodan/tree/master
    urls = [
        f"http://{ip}/favicon.ico",
        f"https://{ip}/favicon.ico"
    ]
    hashes = []
    findings = []
    for url in urls:
        try:
            response = requests.get(url, verify=False, timeout=3)
        except requests.exceptions.RequestException as e:
            logging.debug('Request to %s failed: %s', url, e)
            continue
        try:
            favicon = codecs.encode(response.content,"base64")
            hash_favicon = mmh3.hash(favicon)
            hashes.append(hash_favicon)
        except Exception as e:
            logging.warning(f"Error fetching favicon from {url}: {e}")
    for hash in hashes:
        for vendor, fav_hashes in indicators.items():
            if hash in fav_hashes:
                findings.append({
                    'type': 'favicon',
                    'vendor': vendor,
                    'hash': hash,
                    'ip': ip
                })
                logging.debug(f"Found favicon hash match for {vendor} on {ip}")
    return findings

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
    # check the IPs for HTTP indicators
    http_indications = check_http(ips, indicators)
    print(http_indications)
