#!/usr/bin/env python3
"""
Simple validator HTTP server for wq-test.AkiACG.com

Usage:
  python server.py

Reads `dict.yml` (in the same folder) for response values. If a key is missing,
the server returns a placeholder instructing to edit `dict.yml`.

This server listens on 0.0.0.0:3502 and handles POST /api/decrypt requests.
It checks the Host header contains `wq-test.AkiACG.com` and returns JSON.
"""
import http.server
import socketserver
import json
import os
import sys
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.abspath(__file__))
DICT_FILE = os.path.join(ROOT, 'dict.yml')
HOSTNAME_EXPECT = 'wq-test.AkiACG.com'
LISTEN_PORT = 3502


def load_dict_yaml(path):
    """Very small YAML-ish loader supporting simple key: value and block | for RSA."""
    if not os.path.exists(path):
        return {}
    out = {}
    with open(path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i].rstrip('\n')
        i += 1
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if ':' not in line:
            continue
        key, rest = line.split(':', 1)
        key = key.strip()
        rest = rest.lstrip()
        if rest == '|':
            # read indented block
            block_lines = []
            while i < len(lines):
                l = lines[i]
                if not l.startswith(' ') and not l.startswith('\t') and l.strip():
                    break
                block_lines.append(l.lstrip())
                i += 1
            out[key] = ''.join(block_lines).rstrip('\n')
        else:
            # simple value
            val = rest.strip()
            # strip surrounding quotes
            if val.startswith('"') and val.endswith('"') or val.startswith("'") and val.endswith("'"):
                val = val[1:-1]
            out[key] = val
    return out


class Handler(http.server.BaseHTTPRequestHandler):
    def _send_json(self, code, obj):
        data = json.dumps(obj).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        # Host header check
        host = self.headers.get('Host', '')
        if HOSTNAME_EXPECT not in host:
            self._send_json(404, {'error': 'Host not allowed'})
            return

        parsed = urlparse(self.path)
        if parsed.path != '/api/decrypt':
            self._send_json(404, {'error': 'Not found'})
            return

        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length) if length else b''
        try:
            req = json.loads(body.decode('utf-8')) if body else {}
        except Exception:
            req = {}

        cfg = load_dict_yaml(DICT_FILE)

        # build response using dict.yml or placeholders
        resp = {}
        resp['timeStamp'] = req.get('timeStamp', int(__import__('time').time()))

        # if dict.yml supplies RSA, RSA_K, IV, use them
        if 'RSA' in cfg and cfg['RSA']:
            resp['RSA'] = cfg['RSA']
        else:
            resp['RSA'] = "REPLACE_ME_RSA_PEM\n-----\n(put PEM here)"

        if 'RSA_K' in cfg and cfg['RSA_K']:
            resp['RSA_K'] = cfg['RSA_K']
        else:
            resp['RSA_K'] = "REPLACE_ME_RSA_K_BASE64"

        if 'IV' in cfg and cfg['IV']:
            resp['IV'] = cfg['IV']
        else:
            resp['IV'] = "AAAAAAAAAAAAAAAAAAAAAA=="  # base64 for 12 zero bytes (placeholder)

        # Optionally override response per reqCode mapping in dict.yml
        # e.g., dict.yml can include: reqCode_22: '...json...' (stringified JSON)
        reqcode = str(req.get('reqCode', ''))
        mapping_key = 'reqCode_' + reqcode
        if mapping_key in cfg and cfg[mapping_key]:
            try:
                mapped = json.loads(cfg[mapping_key])
                resp.update(mapped)
            except Exception:
                # ignore if not JSON
                pass

        self._send_json(200, resp)

    def log_message(self, format, *args):
        sys.stderr.write("[App-Auth] %s - - %s\n" % (self.address_string(), format%args))


def run():
    os.chdir(ROOT)
    with socketserver.ThreadingTCPServer(('0.0.0.0', LISTEN_PORT), Handler) as httpd:
        print(f"App-Auth validator listening on 0.0.0.0:{LISTEN_PORT} (host expects {HOSTNAME_EXPECT})")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print('shutting down')
            httpd.server_close()


if __name__ == '__main__':
    run()
