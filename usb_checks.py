import subprocess
import logging
from sys import platform
import yaml

def linux_usb_checks(indicators: dict) -> list[dict]:
    # we're going to run `lsusb -v -d vid:pid` for each known vid:pid in indicators
    findings = []
    for vendor, indicator in indicators['usb'].items():
        for indicator in indicators:
            vid = indicator['vid']
            pid = indicator['pid']
            try:
                result = subprocess.run(['lsusb', '-v', '-d', f'{vid}:{pid}'], capture_output=True, text=True, timeout=3)
            except subprocess.TimeoutExpired:
                logging.warning(f"Timeout expired when trying to query USB device {vid}:{pid}")
                continue
            output = result.stdout
            if result.returncode != 0:
                logging.debug(f"Could not get USB info for {vid}:{pid}: {result.stderr}")
                continue
            # check the output for the serial or manufacturer if provided
            # if serial or manufacturer is in indicator, it's a high confidence match
            confidence = 'low'
            if indicator['serial'] in output:
                confidence = 'medium'
            if indicator['manufacturer'] in output:
                confidence = 'high'
            findings.append({
                'type': 'usb',
                'vendor': vendor,
                'info': output,
                'confidence': confidence
            })
    return findings

def macos_usb_checks(indicators: dict) -> list[dict]:
    # Implement macOS USB checking logic here
    findings = []
    #run `ioreg -p IOUSB -l -w 0` and get the output
    try:
        result = subprocess.run(['ioreg', '-p', 'IOUSB', '-l', '-w', '0'], capture_output=True, text=True, timeout=3)
    except subprocess.TimeoutExpired:
        logging.warning(f"Timeout expired when trying to query USB devices on macOS")
        return findings
    output = result.stdout
    if result.returncode != 0:
        logging.debug(f"Could not get USB info on macOS: {result.stderr}")
        return findings
    for vendor, indicators in indicators['usb'].items():
        for indicator in indicators:
            vid = indicator['vid']
            pid = indicator['pid']
            mac_vid = int(vid, 16)
            mac_pid = int(pid, 16)
            # check the output for the vid and pid
            if f'"idVendor" = {mac_vid}' in output and f'"idProduct" = {mac_pid}' in output:
                # check the output for the serial or manufacturer if provided
                confidence = 'low'
                if indicator['serial'] in output:
                    confidence = 'medium'
                if indicator['manufacturer'] in output:
                    confidence = 'high'
                findings.append({
                    'type': 'usb',
                    'vendor': vendor,
                    'info': output,
                    'confidence': confidence
                })
    return findings

if __name__ == "__main__":
    # load the indicators yaml
    with open("indicators.yaml", "r") as f:
        indicators = f.read()
        indicators = yaml.safe_load(indicators)
    # check USB devices for known vendors
    # if on linux
    if platform == "linux":
        usb_indications = linux_usb_checks(indicators)
    # if on macOS
    elif platform == "darwin":
        usb_indications = macos_usb_checks(indicators)  
    else:
        usb_indications = []
    print(usb_indications)
