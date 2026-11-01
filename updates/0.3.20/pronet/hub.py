from __future__ import annotations

import base64
import collections
import contextlib
import hmac
import html
import http.server
import json
import socket
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .common import MAX_BODY, PronetError, canonical, clean


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward a bearer token to another origin.


class Client:
    def __init__(self, url, token, ca_file=None, test_http=False):
        parsed = urllib.parse.urlsplit(url)
        if (parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/")
                or not parsed.hostname):
            raise PronetError("Hub URL must contain only scheme, host and optional port")
        if parsed.scheme != "https":
            if not test_http or parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "::1"):
                raise PronetError("HTTPS is required for the hub")
        self.url, self.token = url.rstrip("/"), token
        context = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                                  urllib.request.HTTPSHandler(context=context))

    def call(self, path, data=None, timeout=15):
        if not path.startswith("/v1/") or "\n" in path:
            raise PronetError("Invalid API path")
        request = urllib.request.Request(self.url + path, data=canonical(data) if data is not None else None,
                                         headers={"Authorization": "Bearer " + self.token,
                                                  "Content-Type": "application/json", "Accept": "application/json"})
        try:
            with self.opener.open(request, timeout=timeout) as reply:
                raw = reply.read(MAX_BODY + 1)
        except urllib.error.HTTPError as error:
            try:
                detail = json.loads(error.read(4096)).get("error", str(error.code))
            except (ValueError, AttributeError):
                detail = "HTTP " + str(error.code)
            raise PronetError(clean(detail))
        except (OSError, urllib.error.URLError) as error:
            raise PronetError("Hub connection failed: " + clean(error))
        if len(raw) > MAX_BODY:
            raise PronetError("Hub response too large")
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise PronetError("Invalid hub response")
        return result


class HubServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, address, store, tls=None, public_url=None, dashboard_token=None):
        self.store, self.tls, self.public_url = store, tls, public_url
        # The status page lives only at an unguessable path. Anything else that
        # is not the agent API gets a plain 404 with no product name or login
        # prompt, so a scanner probing this port learns nothing.
        self.dashboard_path = "/" + dashboard_token + "/" if dashboard_token else None
        self.slots = threading.BoundedSemaphore(64)
        self.rate_lock = threading.Lock()
        self.rates = {}
        super().__init__(address, Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            request.settimeout(8)
            if self.tls:
                request = self.tls.wrap_socket(request, server_side=True)
            super().process_request_thread(request, address)
        except (ssl.SSLError, OSError):
            self.shutdown_request(request)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass

    def rate(self, key, maximum, seconds):
        with self.rate_lock:
            current = time.monotonic()
            values = self.rates.setdefault(key, collections.deque())
            while values and current - values[0] > seconds:
                values.popleft()
            if len(self.rates) > 4096:
                self.rates = {k: v for k, v in self.rates.items() if v and current - v[-1] < 3600}
            if len(values) >= maximum:
                return False
            values.append(current)
            return True


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = ""
    sys_version = ""

    def send_response(self, code, message=None):
        # No Server header: do not advertise the software on this port.
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def log_message(self, *args):
        pass  # Authorization and enrollment material must not enter access logs.

    def response(self, status, value, content_type="application/json; charset=utf-8"):
        raw = canonical(value) if content_type.startswith("application/json") else value.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store, private")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    def token(self):
        value = self.headers.get("Authorization", "")
        return value[7:] if value.startswith("Bearer ") else ""

    def admin(self):
        return self.server.store.admin(self.token())

    def not_found(self):
        return self.response(404, "<html><body><h1>404 Not Found</h1></body></html>", "text/html; charset=utf-8")

    def is_dashboard(self):
        path = self.path.split("?", 1)[0]
        target = self.server.dashboard_path
        return bool(target) and (hmac.compare_digest(path, target) or hmac.compare_digest(path + "/", target))

    def body(self):
        if self.headers.get_content_type() != "application/json" or self.headers.get("Transfer-Encoding"):
            raise PronetError("JSON with an explicit content length is required")
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            raise PronetError("Invalid content length")
        if not 0 <= length <= MAX_BODY:
            raise PronetError("Request too large or missing content length")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise PronetError("Incomplete request")
        def no_constants(value):
            raise PronetError("Non-finite JSON number refused")
        value = json.loads(raw, parse_constant=no_constants)
        if not isinstance(value, dict):
            raise PronetError("JSON object required")
        return value

    def dashboard_switch(self):
        """The dashboard's one action: move new connections of a tunnel back
        to its main carrier. Knowing the secret page address is the
        authorization (the same as viewing it); requests from another site
        are refused. The result is shown on the page after a redirect."""
        origin = self.headers.get("Origin")
        if origin and origin not in ("null", self.server.public_url):
            return self.response(403, {"error": "Cross-origin request refused"})
        if not self.server.rate("switch:" + self.client_address[0], 10, 60):
            return self.redirect("busy")
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if not 0 < length <= 512 or self.headers.get("Transfer-Encoding"):
            return self.response(400, {"error": "Invalid request"})
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("ascii", "replace"))
        pair_id = (form.get("pair") or [""])[0]
        try:
            job = self.server.store.request_switch(pair_id)
        except PronetError:
            return self.redirect("fail")
        # The Iran agent is woken at once; a switch takes a probe (<3 s).
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            result = self.server.store.job_result(job)
            if result is not None:
                data = result.get("data") or {}
                if result.get("ok"):
                    return self.redirect("ok" if data.get("switched") else "same")
                error = str(result.get("error", ""))
                return self.redirect("down" if "not answering" in error else "busy" if "wait" in error else "fail")
            time.sleep(.3)
        return self.redirect("wait")

    def redirect(self, code):
        self.send_response(303)
        self.send_header("Location", self.server.dashboard_path + "?r=" + code)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store, private")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Connection", "close")
        self.end_headers()

    def do_GET(self):
        try:
            if not self.server.rate("ip:" + self.client_address[0], 1200, 60):
                return self.response(429, {"error": "Request rate exceeded"})
            if self.is_dashboard():
                query = urllib.parse.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
                notice = (query.get("r") or [None])[0]
                return self.response(200, dashboard(self.server.store.overview(), self.server.dashboard_path, notice),
                                     "text/html; charset=utf-8")
            if not self.path.startswith("/v1/"):
                return self.not_found()
            if self.path == "/v1/overview" and self.admin():
                return self.response(200, self.server.store.overview())
            node = self.server.store.authenticate(self.token())
            if not self.server.rate("node:" + node["id"], 600, 60):
                return self.response(429, {"error": "Node request rate exceeded"})
            if self.path == "/v1/overview":
                return self.response(200, self.server.store.overview(node))
            if self.path == "/v1/jobs":
                return self.response(200, {"job": self.server.store.claim(node)})
            if self.path.startswith("/v1/jobs?"):
                # Long poll: answer as soon as a job is queued (bounded wait).
                # lane=main|measure lets an agent run read-only measurements
                # next to the operations that change the host.
                query = urllib.parse.parse_qs(self.path.split("?", 1)[1], strict_parsing=True)
                if set(query) - {"wait", "lane"} or any(len(v) != 1 for v in query.values()):
                    return self.response(400, {"error": "Invalid request"})
                try:
                    wait = max(0, min(30, int(query.get("wait", ["0"])[0])))
                except ValueError:
                    return self.response(400, {"error": "Invalid request"})
                lane = query.get("lane", [None])[0]
                if lane not in (None, "main", "measure"):
                    return self.response(400, {"error": "Invalid request"})
                deadline = time.monotonic() + wait
                while True:
                    seen = self.server.store.job_signal()
                    job = self.server.store.claim(node, lane)
                    left = deadline - time.monotonic()
                    if job or left <= 0:
                        return self.response(200, {"job": job})
                    # Sleeps until a job is queued (no database polling); the
                    # 2 s re-check covers leases that expire on their own.
                    self.server.store.wait_jobs(seen, min(2.0, left))
            return self.response(404, {"error": "Unknown API endpoint"})
        except PronetError as error:
            self.response(401, {"error": clean(error)})
        except sqlite3.Error:
            self.response(503, {"error": "Hub storage busy; retry"})
        except (ValueError, TypeError, KeyError, RecursionError, OSError):
            self.response(400, {"error": "Invalid request"})

    def do_POST(self):
        try:
            if not self.server.rate("ip:" + self.client_address[0], 1200, 60):
                return self.response(429, {"error": "Request rate exceeded"})
            if self.is_dashboard():
                return self.dashboard_switch()
            origin = self.headers.get("Origin")
            if origin and origin != self.server.public_url:
                return self.response(403, {"error": "Cross-origin request refused"})
            body = self.body()
            if self.path == "/v1/enroll":
                if not self.server.rate("enroll:" + self.client_address[0], 20, 3600):
                    return self.response(429, {"error": "Enrollment rate exceeded"})
                return self.response(200, self.server.store.enroll(self.token(), body))
            node = self.server.store.authenticate(self.token())
            if not self.server.rate("node:" + node["id"], 600, 60):
                return self.response(429, {"error": "Node request rate exceeded"})
            if self.path == "/v1/heartbeat":
                result = self.server.store.heartbeat(node, body)
            elif self.path == "/v1/pair":
                result = self.server.store.create_pair(node, body)
            elif self.path == "/v1/join":
                result = self.server.store.join_pair(node, body.get("code"))
            elif self.path == "/v1/advanced":
                result = self.server.store.advanced_pair(node, body.get('pair_id'), body.get('spoof'))
            elif self.path == '/v1/memory':
                if node['role'] != 'iran' or body.get('action') not in ('status','clear'):
                    raise PronetError('Memory controls require the Iran node')
                if self.server.store.learning is None: raise PronetError('Carrier memory unavailable; ordinary full tests remain available')
                if body['action']=='clear': self.server.store.learning.clear()
                result=self.server.store.learning.summary()
            elif self.path == "/v1/stop":
                result = self.server.store.request_stop(node, body.get("pair_id"))
            elif self.path == "/v1/progress":
                if set(body) != {"job_id", "lease_proof", "progress"}:
                    raise PronetError("Invalid progress fields")
                result = self.server.store.job_progress_set(node, body["job_id"], body["lease_proof"], body["progress"])
            elif self.path == "/v1/result":
                if set(body) != {"job_id", "lease_proof", "result"}:
                    raise PronetError("Invalid result fields")
                result = self.server.store.finish(node, body["job_id"], body["lease_proof"], body["result"])
            else:
                return self.response(404, {"error": "Unknown API endpoint"})
            self.response(200, result)
        except PronetError as error:
            self.response(400, {"error": clean(error)})
        except sqlite3.Error:
            self.response(503, {"error": "Hub storage busy; retry"})
        except (ValueError, TypeError, KeyError, RecursionError, OSError):
            self.response(400, {"error": "Invalid request"})


def dashboard(data, action=None, notice=None):
    from .dashboard import render
    return render(data, action, notice)
