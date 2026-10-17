"""Credential-free image regression: python3 -m unittest -v deploy.cloudflare.smoke.test_google_runtime."""
import hashlib
import pathlib
import subprocess
import unittest
import uuid


PROBE = r"""
import base64
import hashlib
import http.cookiejar
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

# Runs inside --network none. Never prints the generated OAuth URL/state,
# cookies, role token, HTML or SDK output.
def api(port, token, method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(f'http://127.0.0.1:{port}{path}', data=data, method=method,
        headers={'Authorization': 'Bearer '+token, 'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=2) as r:
        return json.load(r)

assert os.geteuid() != 0, 'The login must work without root'
for _ in range(100):
    try:
        status = api(8090, 'fixture-admin', 'GET', '/status')
        break
    except urllib.error.URLError:
        time.sleep(0.1)
else:
    raise RuntimeError('Packaged instance did not start')
assert status['unlocked'] is False
api(8090, 'fixture-admin', 'POST', '/create', {
    'id':'packaged-fixture', 'data_key':base64.b64encode(b'P'*32).decode(),
    'listen':'127.0.0.1:8080'})
api(8090, 'fixture-admin', 'PUT', '/consent', {
    'listen':'127.0.0.1:8081', 'public_url':'http://127.0.0.1:8081/connect',
    'api_listen':'127.0.0.1:8082',
    'api_token_sha256':hashlib.sha256(b'fixture-consent').hexdigest()})
api(8090, 'fixture-admin', 'PUT', '/roles/router', {'access':{}})
api(8090, 'fixture-admin', 'POST', '/google-drive', {})
link = api(8082, 'fixture-consent', 'POST', '/links', {'service':'drive'})
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
with opener.open(link['url'], timeout=5) as r:
    r.read()
request = urllib.request.Request(link['url'], data=b'', method='POST',
    headers={'Origin':'http://127.0.0.1:8081'})
with opener.open(request, timeout=5) as r:
    flow = r.url

class Fields(HTMLParser):
    def __init__(self):
        super().__init__()
        self.code = False
        self.google = False
    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == 'input' and attrs.get('name') == 'code':
            self.code = True
        if tag == 'a':
            address = urllib.parse.urlparse(attrs.get('href', ''))
            if address.scheme == 'https' and address.hostname == 'accounts.google.com':
                self.google = True

for _ in range(80):
    with opener.open(flow, timeout=5) as r:
        fields = Fields()
        fields.feed(r.read().decode())
    if fields.code and fields.google:
        break
    time.sleep(0.25)
else:
    raise RuntimeError('Packaged SDK never reached browser code-entry state')
"""


class GoogleRuntimeImageTest(unittest.TestCase):
    def test_google_login_with_runtime_run_mount(self):
        """A platform-mounted /run must not hide the private login directory."""
        root = pathlib.Path(__file__).resolve().parents[3]
        name = "keyring-runtime-test-" + uuid.uuid4().hex
        image = name + ":test"
        # Register cleanup before each resource can be created, including on a
        # partial startup failure. These names belong only to this test run.
        self.addCleanup(subprocess.run, ["docker", "image", "rm", image],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        built = subprocess.run(
            ["docker", "build", "--platform", "linux/amd64", "-f",
             "deploy/cloudflare/Dockerfile", "-t", image, "."],
            cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=300)
        self.assertEqual(built.returncode, 0, built.stdout[-4000:])
        self.addCleanup(subprocess.run, ["docker", "rm", "-f", name],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(
            ["docker", "run", "-d", "--name", name, "--network", "none",
             "--tmpfs", "/run:rw,nosuid,nodev,mode=755", image,
             "instance", "--container", "--admin-listen", "127.0.0.1:8090",
             "--admin-token-sha256", hashlib.sha256(b"fixture-admin").hexdigest()],
            check=True, stdout=subprocess.DEVNULL, timeout=30)
        # Use the real image binary and SDK. Only loopback is reachable; no
        # Google code is submitted, and no raw URL, cookie or SDK output is read.
        result = subprocess.run(
            ["docker", "exec", "-i", name,
             "/opt/google-cloud-sdk/platform/bundledpythonunix/bin/python3", "-"],
            input=PROBE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
