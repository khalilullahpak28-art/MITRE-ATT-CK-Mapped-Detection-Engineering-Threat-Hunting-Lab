#!/var/ossec/framework/python/bin/python3
"""
Custom Wazuh-MISP Integration
Project: MITRE ATT&CK-Mapped Detection Engineering & Threat Hunting Lab

Queries a MISP instance's restSearch API to check whether IOCs found in a
Wazuh alert (IP addresses, hostnames, file hashes) match known indicators
stored in MISP. Wazuh does not ship an official MISP integration in current
versions, so this was built from scratch, structurally modeled on Wazuh's
official Maltiverse integration script.

Installation:
  1. Place this file at /var/ossec/integrations/custom-misp.py
  2. Copy an existing wrapper script (e.g. virustotal) to
     /var/ossec/integrations/custom-misp (no extension) - it dynamically
     locates and executes this .py file based on its own name.
  3. Set permissions: chmod 750, chown root:wazuh on both files.
  4. Add to /var/ossec/etc/ossec.conf:

     <integration>
       <name>custom-misp</name>
       <api_key>YOUR_MISP_API_KEY</api_key>
       <hook_url>https://<misp-host>:<misp-port></hook_url>
       <alert_format>json</alert_format>
       <rule_id>100010,100011,100012,100013</rule_id>
     </integration>

  IMPORTANT: The integration name MUST be prefixed with "custom-" for any
  integration not natively bundled with Wazuh (only slack, pagerduty,
  virustotal, maltiverse, and shuffle are recognized without this prefix).
  Without the prefix, wazuh-integratord silently ignores the integration.

  5. Restart the manager: systemctl restart wazuh-manager
"""

import json
import os
import socket
import sys
import ipaddress

try:
    import requests
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = os.path.join(pwd, 'logs', 'integrations.log')
SOCKET_ADDR = os.path.join(pwd, 'queue', 'sockets', 'queue')
MAX_EVENT_SIZE = 65535


def debug(msg):
    if debug_enabled:
        print(msg)
    with open(LOG_FILE, 'a') as f:
        f.write(msg + '\n')


def load_alert(file_path):
    try:
        with open(file_path) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug(f"# Alert file {file_path} doesn't exist")
        sys.exit(3)
    except json.decoder.JSONDecodeError as e:
        debug(f'Failed getting json_alert: {e}')
        sys.exit(4)


def misp_search(hook_url, api_key, value):
    """Query MISP's restSearch API for a given value (IP, hash, etc.)"""
    url = f"{hook_url.rstrip('/')}/attributes/restSearch"
    headers = {
        'Authorization': api_key,
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }
    body = {"value": value}
    try:
        resp = requests.post(url, headers=headers, json=body, verify=False, timeout=10)
        debug(f'# MISP query for "{value}" -> HTTP {resp.status_code}')
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception as e:
        debug(f'# MISP request failed: {e}')
        return None


def extract_iocs(alert):
    """Pull candidate IOC values out of the Wazuh alert (IP, hostname, hashes)."""
    iocs = []
    data = alert.get('data', {})

    srcip = data.get('srcip')
    if srcip:
        try:
            ip_obj = ipaddress.ip_address(srcip)
            if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved):
                iocs.append(('ip', srcip))
        except ValueError:
            pass

    hostname = data.get('hostname')
    if hostname:
        iocs.append(('hostname', hostname))

    syscheck = alert.get('syscheck', {})
    for field in ('md5_after', 'sha1_after', 'sha256_after'):
        val = syscheck.get(field)
        if val:
            iocs.append((field, val))

    # Sysmon-style hashes field, e.g. "SHA1=xxx,MD5=xxx,SHA256=xxx,IMPHASH=xxx"
    win_hashes = alert.get('data', {}).get('win', {}).get('eventdata', {}).get('hashes')
    if win_hashes:
        for part in win_hashes.split(','):
            if '=' in part:
                htype, hval = part.split('=', 1)
                iocs.append((htype.strip().lower(), hval.strip()))

    return iocs


def build_misp_alert(alert_id, ioc_type, ioc_value, misp_response):
    attributes = misp_response.get('response', {}).get('Attribute', [])
    return {
        'integration': 'misp',
        'alert_id': alert_id,
        'misp': {
            'ioc_type': ioc_type,
            'ioc_value': ioc_value,
            'match_count': len(attributes),
            'matches': attributes,
        },
        'threat': {
            'indicator': {
                'type': ioc_type,
                'value': ioc_value,
                'sightings': len(attributes),
                'provider': 'MISP (local instance)',
            }
        },
    }


def send_event(msg, agent=None):
    if not agent or agent.get('id') == '000':
        event = f'1:misp:{json.dumps(msg)}'
    else:
        location = '[{0}] ({1}) {2}'.format(
            agent['id'], agent['name'], agent.get('ip', 'any')
        )
        location = location.replace('|', '||').replace(':', '|:')
        event = f'1:{location}->misp:{json.dumps(msg)}'

    debug(event)
    if len(event) > MAX_EVENT_SIZE:
        debug(f'# WARNING: Message exceeds max size {MAX_EVENT_SIZE}')
        return
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(event.encode())
        sock.close()
    except socket.error as e:
        if e.errno == 111:
            print('ERROR: Wazuh is not running.')
            sys.exit(6)
        elif e.errno == 90:
            print('ERROR: Message too long.')
            sys.exit(7)


def process_args(args):
    debug('# Starting MISP integration')
    alert_file_location = args[1]
    api_key = args[2]
    hook_url = args[3]

    json_alert = load_alert(alert_file_location)
    debug(f'# File location: {alert_file_location}')
    debug(f'# Hook URL: {hook_url}')
    debug(f'# Processing alert ID: {json_alert.get("id")}')

    iocs = extract_iocs(json_alert)
    debug(f'# Extracted IOCs: {iocs}')

    if not iocs:
        debug('# No IOCs found in this alert, nothing to query')
        return

    for ioc_type, ioc_value in iocs:
        result = misp_search(hook_url, api_key, ioc_value)
        if result is None:
            continue
        attributes = result.get('response', {}).get('Attribute', [])
        if attributes:
            debug(f'# MATCH FOUND for {ioc_type}={ioc_value}, {len(attributes)} hit(s)')
            msg = build_misp_alert(json_alert.get('id'), ioc_type, ioc_value, result)
            send_event(msg, json_alert.get('agent'))
        else:
            debug(f'# No match for {ioc_type}={ioc_value}')


def main(args):
    global debug_enabled
    try:
        if len(args) >= 4:
            debug_enabled = len(args) > 4 and args[4] == 'debug'
        else:
            with open(LOG_FILE, 'a') as f:
                f.write('# ERROR: Wrong arguments\n')
            sys.exit(2)
        process_args(args)
    except Exception as e:
        debug(str(e))
        raise


if __name__ == '__main__':
    main(sys.argv)
