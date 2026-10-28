#!/usr/bin/env python3
"""Refresh a public, signed address directory. No account credentials are mirrored."""
import argparse
import base64
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import directory_png

SOURCES = (
    'https://shepotvpn.com/bootstrap/portals.json',
    'https://yc-nyc1.shepot-api.cc/bootstrap/portals.json',
)
PUBLIC_KEYS = ["MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgf8h/HthQ8V6ABa2GVzJKcRsEbcE7rbnZfrJPFKaVBrt4Jh7wwv3khwo2ZcrtXhiKcIbNcprDMK7yvlR8X5Iyg==", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwwL6jhnj4GKkp/eiukEvLTUFqlxGJCrtg1WYcBH7jIoIHwOpQqjVBPGN2ysP8pUQqMDOZBDum7GdzyxynivS6Q=="]
MAX_BYTES = 32768
DIRECTORY = 'assets/route-index.json'
IMAGE = 'assets/network.png'
HOST = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$')


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def decode(raw, keys=PUBLIC_KEYS):
    if len(raw) > MAX_BYTES:
        raise ValueError('Directory exceeds the size limit')
    d = json.loads(raw.decode('utf-8'))
    if not isinstance(d, dict) or set(d) - {'version', 'portals_v', 'portals', 'portals_sig', 'link'}:
        raise ValueError('Unexpected directory fields')
    version = d.get('portals_v')
    if type(version) is not int or not 1 <= version <= 9007199254740991:
        raise ValueError('Invalid directory version')
    rows = d.get('portals')
    if not isinstance(rows, list) or not 1 <= len(rows) <= 16:
        raise ValueError('Invalid directory entries')
    names = []
    for row in rows:
        if not isinstance(row, dict) or set(row) - {'host', 'group', 'retired'}:
            raise ValueError('Unexpected entry fields')
        host, group, retired = row.get('host'), row.get('group', ''), row.get('retired', False)
        if not isinstance(host, str) or len(host) > 253 or not HOST.fullmatch(host):
            raise ValueError('Invalid host')
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError('IP literals are not directory hosts')
        if not isinstance(group, str) or not re.fullmatch('[a-z0-9-]{0,16}', group) or type(retired) is not bool:
            raise ValueError('Invalid entry metadata')
        names.append({'host': host, 'group': group, 'retired': retired})
    if len({row['host'] for row in names}) != len(names):
        raise ValueError('Duplicate host')
    signature = d.get('portals_sig')
    if not isinstance(signature, str) or not re.fullmatch('[A-Za-z0-9_-]{1,256}', signature):
        raise ValueError('Invalid signature encoding')
    signature_bytes = base64.urlsafe_b64decode(signature + '=' * (-len(signature) % 4))
    message = ('shepot-portals/1\n' + str(version) + '\n' + ''.join(
        row['host'] + '\t' + row['group'] + '\t' + str(int(row['retired'])) + '\n' for row in names)).encode()
    valid = False
    with tempfile.TemporaryDirectory() as directory:
        signature_path = Path(directory) / 'signature.der'
        signature_path.write_bytes(signature_bytes)
        for key in keys:
            public = subprocess.run(['openssl', 'pkey', '-pubin', '-inform', 'DER', '-outform', 'PEM'],
                input=base64.b64decode(key, validate=True), capture_output=True, check=True).stdout
            key_path = Path(directory) / 'public.pem'
            key_path.write_bytes(public)
            result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(key_path), '-signature', str(signature_path)],
                input=message, capture_output=True)
            valid |= result.returncode == 0
    if not valid:
        raise ValueError('Directory signature is not trusted')
    return {'version': 1, 'portals_v': version, 'portals': names, 'portals_sig': signature}


def compare(previous, incoming):
    if incoming['portals_v'] < previous['portals_v']:
        raise ValueError('Directory rollback rejected')
    if incoming['portals_v'] == previous['portals_v']:
        if incoming['portals'] != previous['portals']:
            raise ValueError('Different entries at the same version')
        return False
    return True


def request(url, *, token=None, body=None, limit=MAX_BYTES):
    headers = {'User-Agent': 'Public-Directory-Sync', 'Accept': 'application/json'}
    if token:
        if urllib.parse.urlsplit(url).netloc != 'api.github.com':
            raise ValueError('Authentication is restricted to the GitHub API')
        headers['Authorization'] = 'Bearer ' + token
        headers['X-GitHub-Api-Version'] = '2022-11-28'
    encoded = None
    if body is not None:
        encoded = json.dumps(body).encode()
        headers['Content-Type'] = 'application/json'
    opener = urllib.request.build_opener(NoRedirects(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(urllib.request.Request(url, data=encoded, headers=headers, method='PUT' if body else 'GET'), timeout=12) as response:
        if response.status not in (200, 201):
            raise ValueError('Unexpected HTTP status')
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Response exceeds the size limit')
    return data


def latest():
    candidates = []
    for index, url in enumerate(SOURCES, 1):
        try:
            candidates.append(decode(request(url)))
            print(f'Signed source {index}: verified')
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            category = f'HTTP {error.code}' if isinstance(error, urllib.error.HTTPError) else type(error).__name__
            print(f'Signed source {index}: unavailable ({category})')
    if not candidates:
        raise ValueError('No source returned a trusted directory; previous file preserved')
    best = max(candidates, key=lambda d: d['portals_v'])
    for candidate in candidates:
        if candidate['portals_v'] == best['portals_v']:
            compare(best, candidate)
    return best


def update(path, incoming, keys=PUBLIC_KEYS):
    if path.exists() and not compare(decode(path.read_bytes(), keys), incoming):
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(incoming, ensure_ascii=True, indent=2) + '\n').encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as file:
        temporary = Path(file.name)
        file.write(data)
        file.flush()
        os.fsync(file.fileno())
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return True


def github_context():
    repository = os.environ.get('GITHUB_REPOSITORY', '')
    branch = os.environ.get('GITHUB_REF_NAME', 'main')
    token = os.environ.get('GITHUB_TOKEN')
    if not re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or not token:
        raise ValueError('Repository-scoped GitHub Actions credentials are required')
    return 'https://api.github.com/repos/' + repository + '/contents/', branch, token


def remote_file(base, name, branch, token, limit=131072):
    try:
        return json.loads(request(base + name + '?ref=' + urllib.parse.quote(branch, safe=''), token=token, limit=limit))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def write_remote(base, name, branch, token, stored, data, message):
    body = {'message': message, 'branch': branch, 'content': base64.b64encode(data).decode()}
    if stored is not None:
        body['sha'] = stored['sha']
    request(base + name, token=token, limit=131072, body=body)


def publish(path):
    base, branch, token = github_context()
    stored = remote_file(base, DIRECTORY, branch, token)
    if stored is None:
        raise ValueError('Committed directory missing; refuse to replace repository state')
    incoming = decode(path.read_bytes())
    previous = decode(base64.b64decode(stored['content']))
    if not compare(previous, incoming):
        return False
    write_remote(base, DIRECTORY, branch, token, stored, path.read_bytes(), 'Refresh signed public directory')
    return True


def record_health(version):
    """One public health commit per week also keeps the scheduled workflow active."""
    base, branch, token = github_context()
    name = 'assets/sync-status.json'
    stored = remote_file(base, name, branch, token)
    current = json.loads(base64.b64decode(stored['content'])) if stored else {}
    week = datetime.now(timezone.utc).strftime('%G-W%V')
    if current.get('verified_week') == week:
        return False
    data = (json.dumps({'verified_week': week, 'portals_v': version}, indent=2) + '\n').encode()
    write_remote(base, name, branch, token, stored, data, 'Record weekly directory verification')
    return True


def refresh_image(root, document):
    data = directory_png.encode(json.dumps(document, ensure_ascii=True, separators=(',', ':')).encode())
    path = root / IMAGE
    if path.exists() and path.read_bytes() == data:
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as file:
        temporary = Path(file.name)
        file.write(data); file.flush(); os.fsync(file.fileno())
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def publish_image(path, document):
    base, branch, token = github_context()
    stored = remote_file(base, IMAGE, branch, token, limit=directory_png.MAX_IMAGE * 2)
    if stored:
        previous = base64.b64decode(stored['content'])
        compare(decode(directory_png.decode(previous)), document)
        if previous == path.read_bytes():
            return False
    write_remote(base, IMAGE, branch, token, stored, path.read_bytes(), 'Refresh signed image directory')
    return True


def verify_committed_pair(document_raw, image_raw, keys=PUBLIC_KEYS):
    document = decode(document_raw, keys)
    image = decode(directory_png.decode(image_raw), keys)
    # Two Contents API commits can be interrupted between JSON and PNG.
    # Both signatures must be valid; a later run repairs different versions.
    if image['portals_v'] == document['portals_v']:
        compare(document, image)
    return document


def self_test():
    import unittest
    class ValidationTests(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            cls.temp = tempfile.TemporaryDirectory()
            cls.private = Path(cls.temp.name) / 'temporary-test-key.pem'
            subprocess.run(['openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', str(cls.private)], check=True, capture_output=True)
            cls.private.chmod(0o600)
            public = subprocess.run(['openssl', 'pkey', '-in', str(cls.private), '-pubout', '-outform', 'DER'], check=True, capture_output=True).stdout
            cls.keys = [base64.b64encode(public).decode()]
        @classmethod
        def tearDownClass(cls):
            cls.temp.cleanup()
        def example(self, version=2, host='new.example'):
            message = f'shepot-portals/1\n{version}\n{host}\tedge\t0\n'.encode()
            sig = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(self.private)], input=message, capture_output=True, check=True).stdout
            return {'portals_v': version, 'portals': [{'host': host, 'group': 'edge', 'retired': False}],
                'portals_sig': base64.urlsafe_b64encode(sig).decode().rstrip('=')}
        def load(self, d):
            return decode(json.dumps(d).encode(), self.keys)
        def test_valid(self):
            self.assertEqual(self.load(self.example())['portals_v'], 2)
        def test_signature_and_private_field_rejection(self):
            for item in [dict(self.example(), uri='private'), dict(self.example(), portals_sig='invalid'),
                dict(self.example(), portals=[{'host': 'attacker.example'}])]:
                with self.assertRaises(ValueError): self.load(item)
        def test_rollback_conflict_and_idempotence(self):
            current = self.load(self.example())
            self.assertFalse(compare(current, self.load(self.example())))
            self.assertTrue(compare(current, self.load(self.example(3))))
            for bad in [self.load(self.example(1)), self.load(self.example(2, 'other.example'))]:
                with self.assertRaises(ValueError): compare(current, bad)
        def test_types_limits_and_duplicates(self):
            for item in [dict(self.example(), portals_v=True), dict(self.example(), portals=[]),
                dict(self.example(), portals=self.example()['portals'] * 2)]:
                with self.assertRaises(ValueError): self.load(item)
            with self.assertRaises(ValueError): decode(b' ' * (MAX_BYTES + 1), self.keys)
        def test_no_credential_redirects(self):
            with self.assertRaises(ValueError): request('https://example.com/file', token='test-only')
            self.assertIsNone(NoRedirects().redirect_request(None, None, 302, '', {}, 'https://other.example/'))
        def test_atomic_update_and_preservation(self):
            path = Path(self.temp.name) / 'test-directory.json'
            original = self.load(self.example())
            self.assertTrue(update(path, original, self.keys))
            before = path.read_bytes()
            self.assertFalse(update(path, original, self.keys))
            self.assertEqual(path.read_bytes(), before)
            with self.assertRaises(ValueError): update(path, self.load(self.example(1)), self.keys)
            self.assertEqual(path.read_bytes(), before)
            self.assertTrue(update(path, self.load(self.example(3)), self.keys))
        def test_weekly_health_is_idempotent(self):
            from unittest.mock import patch
            writes = []
            week = datetime.now(timezone.utc).strftime('%G-W%V')
            stored = {'sha': 'test', 'content': base64.b64encode(json.dumps({'verified_week': week}).encode()).decode()}
            with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'example/public', 'GITHUB_TOKEN': 'test-only'}), \
                    patch(__name__ + '.write_remote', side_effect=lambda *args: writes.append(args)), \
                    patch(__name__ + '.remote_file', return_value=stored):
                self.assertFalse(record_health(2))
                self.assertEqual(writes, [])
            with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'example/public', 'GITHUB_TOKEN': 'test-only'}), \
                    patch(__name__ + '.write_remote', side_effect=lambda *args: writes.append(args)), \
                    patch(__name__ + '.remote_file', return_value=None):
                self.assertTrue(record_health(2))
                self.assertEqual(writes[0][1], 'assets/sync-status.json')
                self.assertEqual(json.loads(writes[0][5]), {'verified_week': week, 'portals_v': 2})
        def test_interrupted_pair_can_recover_without_accepting_same_version_conflicts(self):
            current = json.dumps(self.example(2)).encode()
            older_image = directory_png.encode(json.dumps(self.example(1)).encode())
            self.assertEqual(verify_committed_pair(current, older_image, self.keys)['portals_v'], 2)
            conflicting = directory_png.encode(json.dumps(self.example(2, 'other.example')).encode())
            with self.assertRaises(ValueError): verify_committed_pair(current, conflicting, self.keys)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ValidationTests))
    if not result.wasSuccessful():
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--publish', action='store_true')
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    if args.self_test:
        self_test()
        directory_png.self_test()
        return
    root = args.root.resolve()
    path = root / DIRECTORY
    if args.check:
        d = verify_committed_pair(path.read_bytes(), (root / IMAGE).read_bytes())
        print(f"Verified public directory v{d['portals_v']} ({len(d['portals'])} hosts)")
        return
    incoming = latest()
    changed = update(path, incoming)
    document = decode(path.read_bytes())
    image = refresh_image(root, document)
    if args.publish:
        print('Comparing the mirrored directory')
        publish(path)
        print('Publishing the signed image directory')
        publish_image(image, document)
        print('Recording weekly verification')
        record_health(incoming['portals_v'])
    print(f"{'Updated' if changed else 'Verified'} public directory v{incoming['portals_v']} ({len(incoming['portals'])} hosts)")


if __name__ == '__main__':
    try:
        main()
    except urllib.error.HTTPError as error:
        raise SystemExit(f'Directory synchronization failed (HTTP {error.code}); previous public version preserved.') from None
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit('Directory synchronization failed; previous public version preserved.') from None
