#!/usr/bin/env python3
"""Select an authenticated Ubuntu mirror for a private, temporary APT view.

No live APT source, service, route, or tunnel configuration is changed.
The installer owns and removes the directory passed with --directory.
"""
import argparse
import concurrent.futures
import math
import ipaddress
import secrets
import socket
import statistics
import struct
import time
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def current_dns(resolv_conf=Path('/etc/resolv.conf')):
    """Read the stub and upstream DNS addresses; never write system settings."""
    addresses = []
    try:
        addresses += re.findall(r'^nameserver\s+(\S+)', Path(resolv_conf).read_text(), re.M)
    except OSError:
        pass
    try:
        reply = subprocess.run(['resolvectl', 'dns'], text=True, capture_output=True, timeout=2)
        if reply.returncode == 0:
            for line in reply.stdout.splitlines():
                if ':' in line:
                    addresses += line.split(':', 1)[1].split()
    except (OSError, subprocess.TimeoutExpired):
        pass
    valid = []
    for address in addresses:
        try:
            address = str(ipaddress.ip_address(address))
            if address not in valid:
                valid.append(address)
        except ValueError:
            pass
    return valid


def dns_query(server, domain, port=53, timeout=.8):
    """Time a bounded UDP A query, requiring a matching question and public A answer."""
    ident = secrets.token_bytes(2)
    question = b''.join(bytes([len(label)]) + label.encode('ascii') for label in domain.split('.')) + b'\0\0\1\0\1'
    request = ident + struct.pack('!HHHHH', 0x0100, 1, 0, 0, 0) + question
    try:
        family = socket.AF_INET6 if ':' in server else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as connection:
            connection.settimeout(timeout)
            connection.connect((server, port))
            started = time.monotonic()
            connection.send(request)
            reply = connection.recv(4096)
            elapsed = (time.monotonic() - started) * 1000
        if len(reply) < 12 or reply[:2] != ident:
            return None
        flags, questions, answers, _, _ = struct.unpack('!HHHHH', reply[2:12])
        if flags & 0xFA0F != 0x8000 or questions != 1 or not answers or reply[12:12+len(question)] != question:
            return None
        cursor = 12 + len(question)
        for _ in range(min(answers, 100)):
            # Advance over a record name (compression pointers occupy two bytes).
            while reply[cursor]:
                length = reply[cursor]
                if length & 0xC0 == 0xC0:
                    cursor += 2
                    break
                if length > 63:
                    return None
                cursor += 1 + length
            else:
                cursor += 1
            kind, cls, _, size = struct.unpack('!HHIH', reply[cursor:cursor+10])
            cursor += 10
            data = reply[cursor:cursor+size]
            if len(data) != size:
                return None
            if kind == 1 and cls == 1 and size == 4 and ipaddress.ip_address(data).is_global:
                return elapsed
            cursor += size
    except (OSError, ValueError, IndexError, struct.error):
        pass
    return None


def dns_probe(server):
    samples = [dns_query(server, name) for _ in range(2)
               for name in ('raw.githubusercontent.com', 'archive.ubuntu.com', 'example.com')]
    answered = [value for value in samples if value is not None]
    return {'server': server, 'answered': len(answered), 'total': len(samples),
            'complete': len(answered) == len(samples),
            'latency': statistics.median(answered) if answered else None}


def suggest_dns():
    configured = current_dns()
    print('Current DNS (unchanged): '+(', '.join(configured) or 'not detected'), flush=True)
    print('DNS test only: 6 small queries per resolver; no DNS settings will be changed.', flush=True)
    servers = list(dict.fromkeys(configured + ['1.1.1.1', '8.8.8.8', '9.9.9.9']))[:8]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(dns_probe, servers))
    for row in results:
        latency = '%.1f ms' % row['latency'] if row['latency'] is not None else 'unavailable'
        print('DNS %s | %s | %s/%s answers' % (row['server'], latency, row['answered'], row['total']), flush=True)
    complete = [row for row in results if row['complete']]
    if complete:
        winner = min(complete, key=lambda row: row['latency'])
        print('Suggested DNS for the tested names: '+winner['server']+' (system DNS unchanged).', flush=True)
    else:
        print('No DNS suggestion: none answered all test queries. System DNS unchanged.', flush=True)
    print('DNS timing measures name resolution, not WireGuard latency or download capacity.', flush=True)


def candidates(arch):
    if arch == 'arm64':
        return ['https://ports.ubuntu.com/ubuntu-ports']
    if arch != 'amd64':
        raise ValueError('Ubuntu mirror selection supports amd64 and arm64')
    return [
        'https://ubuntu.pishgaman.net/ubuntu',
        'https://ubuntu.pars.host',
        'https://ir.ubuntu.sindad.cloud/ubuntu',
        'https://ubuntu.shatel.ir/ubuntu',
        'https://ubuntu.mobinhost.com/ubuntu',
        'https://mirror.iranserver.com/ubuntu',
        'https://mirror.arvancloud.ir/ubuntu',
        'https://ubuntu.parsvds.com/ubuntu',
        'https://archive.ubuntu.com/ubuntu',
        'https://mirror.leaseweb.com/ubuntu',
        'https://ftp.fau.de/ubuntu',
        'https://mirror.netcologne.de/ubuntu',
        'https://mirror.init7.net/ubuntu',
    ]


def probe(url, codename, keyring):
    row = {'url': url, 'speed': 0.0, 'reason': 'unavailable'}
    with tempfile.TemporaryDirectory(prefix='pronet-mirror-probe-') as temp:
        sample = Path(temp)/'InRelease'
        try:
            reply = subprocess.run([
                'curl', '--fail', '--silent', '--show-error', '--location',
                '--proto', '=https', '--proto-redir', '=https',
                '--connect-timeout', '2', '--max-time', '6', '--max-filesize', '2097152',
                '--output', str(sample), '--write-out', '%{speed_download}',
                url.rstrip('/')+'/dists/'+codename+'/InRelease',
            ], text=True, capture_output=True, timeout=8)
            if reply.returncode:
                return row
            verified = subprocess.run(['gpgv', '--keyring', str(keyring), str(sample)],
                                      capture_output=True, timeout=3)
            if verified.returncode:
                row['reason'] = 'signature rejected'
                return row
            if not re.search(r'^Codename:\s*'+re.escape(codename)+r'\s*$', sample.read_text(), re.M):
                row['reason'] = 'wrong Ubuntu release'
                return row
            speed = float(reply.stdout.strip())
            if math.isfinite(speed) and speed > 0:
                row.update(speed=speed, reason='verified')
        except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
            pass
    return row


def make_sources(apt_root, destination, mirror, codename):
    """Copy active source files and replace only Ubuntu distribution entries."""
    apt_root, destination = Path(apt_root), Path(destination)
    parts = destination/'sources.list.d'
    parts.mkdir(parents=True, exist_ok=True)
    files = [apt_root/'sources.list']
    source_parts = apt_root/'sources.list.d'
    if source_parts.is_dir():
        files += sorted(p for p in source_parts.iterdir() if p.suffix in ('.list', '.sources'))
    changed = 0
    suite = re.escape(codename)+r'(?:-(?:updates|security|backports|proposed))?'
    for source in files:
        if not source.is_file():
            continue
        text = source.read_text()
        if source.suffix == '.sources':
            stanzas = re.split(r'(\n[ \t]*\n)', text)
            for index in range(0, len(stanzas), 2):
                stanza = stanzas[index]
                suites = re.search(r'^Suites:\s*(.+)$', stanza, re.M)
                if (suites and re.search(r'\b'+suite+r'\b', suites.group(1))
                        and ('ubuntu-archive-keyring.gpg' in stanza or source.name == 'ubuntu.sources')):
                    stanza, count = re.subn(r'^URIs:[^\n]*', 'URIs: '+mirror, stanza, flags=re.M)
                    changed += count
                    stanzas[index] = stanza
            text = ''.join(stanzas)
        else:
            pattern = re.compile(r'^(\s*deb(?:-src)?\s+(?:\[[^\]]*\]\s+)?)'
                                 r'(https?://[^\s]+)(\s+'+suite+r'(?=\s)[^\n]*)$', re.M)
            def replace(match):
                nonlocal changed
                # A Docker/PPA URL ending in /linux/ubuntu is not an Ubuntu archive.
                if not re.match(r'https?://[^/]+/(?:ubuntu|ubuntu-ports)/?$', match.group(2)):
                    return match.group(0)
                changed += 1
                return match.group(1)+mirror+match.group(3)
            text = pattern.sub(replace, text)
        target = destination/'sources.list' if source == apt_root/'sources.list' else parts/source.name
        target.write_text(text)
        shutil.copymode(source, target)
    if not changed:
        raise ValueError('No supported Ubuntu source entries found; live configuration was left unchanged')
    (destination/'sources.list').touch(exist_ok=True)
    for name in ('lists/partial', 'archives/partial'):
        (destination/name).mkdir(parents=True, exist_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--packages', nargs='*', default=[])
    parser.add_argument('--dns-only', action='store_true')
    args = parser.parse_args()
    if any(not re.fullmatch('[a-z0-9][a-z0-9+.-]*', item) for item in args.packages):
        raise ValueError('Invalid prerequisite package name')
    if args.directory.exists():
        raise ValueError('--directory must be a new temporary directory; existing files were left unchanged')
    suggest_dns()
    if args.dns_only:
        return
    release = dict(re.findall(r'^([A-Z_]+)=["\']?([^\n"\']+)', Path('/etc/os-release').read_text(), re.M))
    if release.get('ID') != 'ubuntu':
        raise ValueError('Iran mirror selection is for Ubuntu only; sources were left unchanged')
    codename = release.get('VERSION_CODENAME', '')
    if not re.fullmatch('[a-z]+', codename):
        raise ValueError('Could not identify the Ubuntu release')
    keyring = Path('/usr/share/keyrings/ubuntu-archive-keyring.gpg')
    if not keyring.is_file() or any(not shutil.which(x) for x in ('curl', 'gpgv', 'apt-get', 'dpkg')):
        raise ValueError('Mirror testing requires curl, gpgv, apt-get and the Ubuntu archive keyring')
    arch = subprocess.check_output(['dpkg', '--print-architecture'], text=True).strip()
    print('Testing Ubuntu mirrors (temporary, installation only)...', flush=True)
    print('Mirror | Download Speed | Result', flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        pending = [pool.submit(probe, url, codename, keyring) for url in candidates(arch)]
        results = []
        for future in concurrent.futures.as_completed(pending):
            row = future.result(); results.append(row)
            print('%s | %.2f KB/s | %s' % (row['url'], row['speed']/1024, row['reason']), flush=True)
    ranked = sorted((r for r in results if r['speed'] > 0), key=lambda r: r['speed'], reverse=True)
    if not ranked:
        raise ValueError('No authenticated Ubuntu mirror answered; live APT sources were left unchanged')
    args.directory.mkdir(parents=True, exist_ok=True)
    row = prepare_indexes(Path('/etc/apt'), args.directory, codename, ranked, packages=args.packages)
    print('Selected verified mirror: '+row['url'], flush=True)
    print('Original APT sources are unchanged. Temporary files are removed after prerequisite installation.', flush=True)


def prepare_indexes(apt_root, directory, codename, ranked, packages=()):
    # A signed release alone does not prove that updates/security are available.
    # APT verifies all configured suites before this private view is used.
    for row in ranked:
        make_sources(apt_root, directory, row['url'], codename)
        print('Checking complete package indexes: '+row['url'], flush=True)
        try:
            checked = subprocess.run(['apt-get']+apt_options(directory)+[
                '-o', 'APT::Update::Error-Mode=any', '-o', 'Acquire::Retries=0',
                '-o', 'Acquire::http::Timeout=8', '-o', 'Acquire::https::Timeout=8', 'update'], timeout=120)
            if checked.returncode == 0:
                if not packages:
                    return row
                downloaded = subprocess.run(['apt-get']+apt_options(directory)+[
                    '-o', 'Acquire::Retries=0', '-o', 'Acquire::http::Timeout=8',
                    '-o', 'Acquire::https::Timeout=8', '--download-only', '-y', 'install']+list(packages), timeout=180)
                if downloaded.returncode == 0:
                    return row
        except subprocess.TimeoutExpired:
            pass
        print('Index or package download failed; trying the next verified mirror.', flush=True)
    else:
        raise ValueError('Package index checks failed; live APT sources were left unchanged')


def apt_options(directory):
    return ['-o', 'Dir::Etc::sourcelist='+str(directory/'sources.list'),
            '-o', 'Dir::Etc::sourceparts='+str(directory/'sources.list.d'),
            '-o', 'Dir::State::lists='+str(directory/'lists'),
            '-o', 'Dir::Cache::archives='+str(directory/'archives')]


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit('[pronet] '+str(error))
