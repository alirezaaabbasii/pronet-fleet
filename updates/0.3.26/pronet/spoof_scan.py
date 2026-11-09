"""Bounded HTTPS reachability checks against the bundled Iranian catalog."""

import concurrent.futures
import ipaddress
import re
import socket
import ssl
import time

from .common import APP, PronetError, read_json

CATALOG = APP / 'data' / 'iran-scan-seeds.json'
HOSTNAME = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+')
HTTP_STATUS = re.compile(rb'HTTP/1\.[01] ([1-5][0-9]{2})(?: |\r?\n)')
PROBE_SECONDS = 5
MAX_TARGETS = 128


def load_targets(catalog):
    """Return DNS-observed pairs, validated against the local IR registry."""
    try:
        if catalog['schema_version'] != 1 or catalog['scope']['destination_country_registry'] != 'IR':
            raise ValueError('unsupported catalog')
        prefixes = tuple(ipaddress.IPv4Network(value) for value in catalog['iran_ipv4_allowlist'])
        targets = []
        for domain in catalog['public_web_domains']:
            host = domain['hostname']
            if len(host) > 253 or not HOSTNAME.fullmatch(host):
                raise ValueError('invalid hostname')
            for record in domain['iran_ipv4']:
                address = ipaddress.IPv4Address(record['ipv4'])
                if not address.is_global or not any(address in prefix for prefix in prefixes):
                    raise ValueError('address outside the public IR registry')
                targets.append((host, str(address)))
        targets = list(dict.fromkeys(targets))
        if not 1 <= len(targets) <= MAX_TARGETS:
            raise ValueError('unexpected number of scan targets')
        return targets
    except (KeyError, ValueError, TypeError) as error:
        raise PronetError('Invalid Iran scan catalog: ' + str(error)) from error


def probe(host, address, context=None):
    """Pin the connection to the catalog IP while authenticating the hostname."""
    started = time.monotonic()
    deadline = started + PROBE_SECONDS
    result = {'hostname': host, 'ipv4': address, 'stage': 'tcp', 'http_status': None}

    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise TimeoutError('probe deadline reached')
        return seconds

    try:
        with socket.create_connection((address, 443), timeout=remaining()) as raw:
            result['stage'] = 'tls'
            raw.settimeout(remaining())
            with (context or ssl.create_default_context()).wrap_socket(raw, server_hostname=host) as connection:
                result['stage'] = 'http'
                connection.settimeout(remaining())
                request = f'HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: Pronet-Fleet-Scan\r\n\r\n'
                connection.sendall(request.encode('ascii'))
                line = bytearray()
                while b'\n' not in line and len(line) < 1024:
                    connection.settimeout(remaining())
                    part = connection.recv(1024 - len(line))
                    if not part:
                        break
                    line.extend(part)
                status = HTTP_STATUS.match(line) if b'\n' in line else None
                if status is None:
                    raise OSError('no valid HTTP status line')
                result['http_status'] = int(status.group(1))
    except OSError as error:
        result['error'] = str(error)[:200] or type(error).__name__
    result['elapsed_ms'] = round((time.monotonic() - started) * 1000)
    return result


def run_scan():
    catalog = read_json(CATALOG)
    targets = load_targets(catalog)
    context = ssl.create_default_context()
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as workers:
        results = list(workers.map(lambda target: probe(*target, context), targets))
    return {
        'schema_version': 1,
        'measured_at_unix': int(time.time()),
        'catalog_date': catalog['snapshot_date_tehran'],
        'destination_registry': 'IR',
        'protocol': 'https',
        'origin_egress': 'not_measured',
        'spoof_compatibility': 'not_measured',
        'results': results,
    }
