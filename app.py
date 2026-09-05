"""
Interceptor — a lightweight HTTP/HTTPS interception proxy with a web UI.

Captures traffic through a local proxy, lets you inspect requests/responses,
block domains, replay/edit-and-resend captured requests (Repeater), and forge
brand-new requests from scratch. Built for learning proxy/MITM mechanics and
for quick manual testing during CTFs and lab work.

Run:
    pip install -r requirements.txt
    python app.py
Then point a client/browser at the proxy port shown in the banner, or use the
web UI's Repeater/Forge tools directly without configuring a proxy at all.
"""
import json
import logging
import os
import socket
import sqlite3
import threading
import time
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, render_template, request
from flask_sock import Sock

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("interceptor")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "interceptor.db")
MAX_HISTORY = 500          # in-memory ring buffer size
MAX_BODY_PREVIEW = 20000   # chars stored per body, to keep the DB/UI sane

app = Flask(__name__)
sock = Sock(app)

# ---------------------------------------------------------------------------
# Shared state (thread-safe)
# ---------------------------------------------------------------------------
state_lock = threading.RLock()
intercepted_requests = deque(maxlen=MAX_HISTORY)
request_counter = 0
blocked_domains = set()
ws_clients = set()


def next_id():
    global request_counter
    with state_lock:
        request_counter += 1
        return request_counter


def now_iso():
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def truncate(text, limit=MAX_BODY_PREVIEW):
    if text is None:
        return ""
    if len(text) > limit:
        return text[:limit] + f"\n... [truncated, {len(text) - limit} more chars]"
    return text


# ---------------------------------------------------------------------------
# Persistence (SQLite) — history and blocked domains survive restarts
# ---------------------------------------------------------------------------
def db_connect():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db_connect()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY,
            method TEXT, url TEXT, host TEXT, headers TEXT, body TEXT,
            timestamp TEXT, source TEXT, status_code INTEGER, response TEXT,
            note TEXT DEFAULT ''
        )"""
    )
    conn.execute("CREATE TABLE IF NOT EXISTS blocked_domains (domain TEXT PRIMARY KEY)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_requests_host ON requests(host)")
    conn.commit()

    # Warm the in-memory ring buffer with the most recent rows
    rows = conn.execute(
        "SELECT * FROM requests ORDER BY id DESC LIMIT ?", (MAX_HISTORY,)
    ).fetchall()
    global request_counter
    for row in rows:
        d = dict(row)
        d["response"] = json.loads(d["response"]) if d["response"] else None
        d["headers"] = json.loads(d["headers"]) if d["headers"] else {}
        intercepted_requests.append(d)
        request_counter = max(request_counter, d["id"])
    for row in conn.execute("SELECT domain FROM blocked_domains"):
        blocked_domains.add(row["domain"])
    conn.close()
    logger.info("Loaded %d requests, %d blocked domains from %s",
                len(intercepted_requests), len(blocked_domains), DB_PATH)


def persist_request(req):
    conn = db_connect()
    conn.execute(
        """INSERT OR REPLACE INTO requests
           (id, method, url, host, headers, body, timestamp, source, status_code, response, note)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (
            req["id"], req["method"], req["url"], req.get("host", ""),
            json.dumps(req.get("headers", {})), req.get("body", ""),
            req["timestamp"], req["source"],
            (req.get("response") or {}).get("status_code"),
            json.dumps(req.get("response")) if req.get("response") is not None else None,
            req.get("note", ""),
        ),
    )
    conn.commit()
    conn.close()


def persist_blocked_domains():
    conn = db_connect()
    conn.execute("DELETE FROM blocked_domains")
    conn.executemany(
        "INSERT INTO blocked_domains (domain) VALUES (?)",
        [(d,) for d in blocked_domains],
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# WebSocket broadcast — pushes live updates to every connected UI tab
# ---------------------------------------------------------------------------
def broadcast(payload):
    dead = []
    data = json.dumps(payload)
    for client in list(ws_clients):
        try:
            client.send(data)
        except Exception:
            dead.append(client)
    for client in dead:
        ws_clients.discard(client)


def record_request(req):
    """Append to history, persist, and notify all connected UIs."""
    with state_lock:
        intercepted_requests.appendleft(req)
    persist_request(req)
    broadcast({"type": "request", "request": req})


def is_blocked(host_or_domain):
    if not host_or_domain:
        return False
    host_or_domain = host_or_domain.split(":")[0].lower()
    with state_lock:
        return any(
            host_or_domain == d or host_or_domain.endswith("." + d)
            for d in blocked_domains
        )


def find_available_port(start_port, host="127.0.0.1", max_attempts=20):
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            if s.connect_ex((host, port)) != 0:
                return port
    return None


# ---------------------------------------------------------------------------
# Proxy server — the actual man-in-the-middle for plain HTTP, plus HTTPS
# tunneling (CONNECT). TLS payloads are relayed opaquely (not decrypted) —
# that keeps the tool honest about what it can see without a client-side
# trusted CA, while HTTP traffic is fully captured and inspectable.
# ---------------------------------------------------------------------------
class ProxyServer:
    def __init__(self, host="127.0.0.1", port=None):
        self.host = host
        self.port = port
        self.server = None
        self.thread = None
        self.running = False

    def status(self):
        return {"running": self.running, "host": self.host, "port": self.port}

    def start(self):
        if self.running:
            return {"success": False, "message": "Proxy is already running"}

        self.port = self.port or find_available_port(8080)
        if not self.port:
            return {"success": False, "message": "No available port found for the proxy"}

        proxy = self

        class ProxyHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            timeout = 15

            def log_message(self, fmt, *args):
                pass  # silence default stderr access log; we log via the app logger

            def handle_one_request(self):
                # Clients (browsers especially) routinely close idle keep-alive
                # sockets without warning; the stdlib handler treats that as an
                # unhandled exception. Swallow the noise, keep real errors.
                try:
                    super().handle_one_request()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    self.close_connection = True

            def do_GET(self):
                self._forward("GET")

            def do_POST(self):
                self._forward("POST")

            def do_PUT(self):
                self._forward("PUT")

            def do_DELETE(self):
                self._forward("DELETE")

            def do_PATCH(self):
                self._forward("PATCH")

            def do_HEAD(self):
                self._forward("HEAD")

            def do_OPTIONS(self):
                self._forward("OPTIONS")

            def do_CONNECT(self):
                host, _, port_s = self.path.partition(":")
                port = int(port_s) if port_s else 443

                req = {
                    "id": next_id(),
                    "method": "CONNECT",
                    "url": f"https://{host}:{port}",
                    "host": host,
                    "headers": dict(self.headers),
                    "body": "",
                    "timestamp": now_iso(),
                    "source": "proxy",
                    "response": {"info": "TLS tunnel opened (payload not decrypted)"},
                }

                if is_blocked(host):
                    self.send_error(403, f"Domain '{host}' is blocked")
                    req["response"] = {"error": f"domain '{host}' is blocked"}
                    record_request(req)
                    return

                try:
                    remote = socket.create_connection((host, port), timeout=10)
                    self.send_response(200, "Connection Established")
                    self.end_headers()
                    record_request(req)
                    self._tunnel(self.connection, remote)
                except Exception as exc:
                    self.send_error(502, str(exc))
                    req["response"] = {"error": str(exc)}
                    record_request(req)

            def _tunnel(self, client_sock, remote_sock):
                def pump(src, dst):
                    try:
                        while True:
                            chunk = src.recv(8192)
                            if not chunk:
                                break
                            dst.sendall(chunk)
                    except OSError:
                        pass
                    finally:
                        for s in (src, dst):
                            try:
                                s.shutdown(socket.SHUT_RDWR)
                            except OSError:
                                pass

                threading.Thread(target=pump, args=(client_sock, remote_sock), daemon=True).start()
                threading.Thread(target=pump, args=(remote_sock, client_sock), daemon=True).start()

            def _forward(self, method):
                url = self.path
                host_header = self.headers.get("Host", "")
                if not url.startswith("http"):
                    url = f"http://{host_header}{url}"

                headers = {k: v for k, v in self.headers.items() if k.lower() != "proxy-connection"}
                length = int(self.headers.get("Content-Length", 0) or 0)
                body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

                domain = urlparse(url).netloc
                req = {
                    "id": next_id(),
                    "method": method,
                    "url": url,
                    "host": domain,
                    "headers": headers,
                    "body": truncate(body),
                    "timestamp": now_iso(),
                    "source": "proxy",
                    "response": None,
                }

                if is_blocked(domain):
                    self.send_response(403)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(f"Blocked by Interceptor: {domain}".encode())
                    req["response"] = {"error": f"domain '{domain}' is blocked"}
                    record_request(req)
                    return

                try:
                    upstream = requests.request(
                        method=method, url=url, headers=headers,
                        data=body.encode("utf-8") if body else None,
                        timeout=15, allow_redirects=False, stream=True,
                    )
                    self.send_response(upstream.status_code)
                    skip = {"transfer-encoding", "connection", "content-encoding"}
                    for h, v in upstream.headers.items():
                        if h.lower() not in skip:
                            self.send_header(h, v)
                    content = upstream.content
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    if method != "HEAD":
                        self.wfile.write(content)

                    body_preview = upstream.text[:MAX_BODY_PREVIEW]
                    req["response"] = {
                        "status_code": upstream.status_code,
                        "headers": dict(upstream.headers),
                        "body": body_preview,
                    }
                except Exception as exc:
                    try:
                        self.send_response(502)
                        self.send_header("Content-Type", "text/plain")
                        self.end_headers()
                        self.wfile.write(f"Interceptor error: {exc}".encode())
                    except Exception:
                        pass
                    req["response"] = {"error": str(exc)}

                record_request(req)

        try:
            self.server = HTTPServer((self.host, self.port), ProxyHandler)
            self.server.allow_reuse_address = True
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            self.running = True
            broadcast({"type": "proxy_status", "status": self.status()})
            logger.info("Proxy listening on %s:%s", self.host, self.port)
            return {"success": True, "message": f"Proxy started on {self.host}:{self.port}"}
        except OSError as exc:
            return {"success": False, "message": f"Could not start proxy: {exc}"}

    def stop(self):
        if not self.running:
            return {"success": False, "message": "Proxy is not running"}
        self.server.shutdown()
        self.server.server_close()
        self.running = False
        broadcast({"type": "proxy_status", "status": self.status()})
        return {"success": True, "message": "Proxy stopped"}


proxy = ProxyServer()


# ---------------------------------------------------------------------------
# Web UI + JSON API
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@sock.route("/ws")
def ws_endpoint(ws):
    ws_clients.add(ws)
    try:
        while True:
            ws.receive()  # block until client disconnects; we only push
    except Exception:
        pass
    finally:
        ws_clients.discard(ws)


@app.get("/api/proxy-status")
def api_proxy_status():
    return jsonify(proxy.status())


@app.post("/api/toggle-proxy")
def api_toggle_proxy():
    action = (request.json or {}).get("action")
    if action == "start":
        return jsonify(proxy.start())
    if action == "stop":
        return jsonify(proxy.stop())
    return jsonify({"success": False, "message": "action must be 'start' or 'stop'"}), 400


@app.get("/api/requests")
def api_list_requests():
    """Supports ?method=GET&q=api&limit=100 for lightweight client-side-free filtering."""
    method = request.args.get("method", "").upper()
    q = request.args.get("q", "").lower()
    limit = min(int(request.args.get("limit", 200)), MAX_HISTORY)

    with state_lock:
        items = list(intercepted_requests)

    if method:
        items = [r for r in items if r["method"] == method]
    if q:
        items = [r for r in items if q in r["url"].lower() or q in (r.get("host") or "").lower()]

    return jsonify(items[:limit])


@app.get("/api/request/<int:req_id>")
def api_get_request(req_id):
    with state_lock:
        for r in intercepted_requests:
            if r["id"] == req_id:
                return jsonify(r)
    return jsonify({"error": "not found"}), 404


@app.post("/api/request/<int:req_id>/note")
def api_set_note(req_id):
    note = (request.json or {}).get("note", "")
    with state_lock:
        for r in intercepted_requests:
            if r["id"] == req_id:
                r["note"] = note
                persist_request(r)
                return jsonify({"success": True})
    return jsonify({"error": "not found"}), 404


@app.delete("/api/requests")
def api_clear_requests():
    with state_lock:
        intercepted_requests.clear()
    conn = db_connect()
    conn.execute("DELETE FROM requests")
    conn.commit()
    conn.close()
    broadcast({"type": "cleared"})
    return jsonify({"success": True})


@app.get("/api/blocked-domains")
def api_get_blocked():
    with state_lock:
        return jsonify(sorted(blocked_domains))


@app.post("/api/block-domain")
def api_block_domain():
    domain = (request.json or {}).get("domain", "").strip().lower()
    if not domain:
        return jsonify({"success": False, "message": "domain required"}), 400
    with state_lock:
        blocked_domains.add(domain)
        persist_blocked_domains()
    broadcast({"type": "blocked_domains", "domains": sorted(blocked_domains)})
    return jsonify({"success": True})


@app.post("/api/unblock-domain")
def api_unblock_domain():
    domain = (request.json or {}).get("domain", "")
    with state_lock:
        blocked_domains.discard(domain)
        persist_blocked_domains()
    broadcast({"type": "blocked_domains", "domains": sorted(blocked_domains)})
    return jsonify({"success": True})


def _send(method, url, headers, body, source):
    req = {
        "id": next_id(),
        "method": method,
        "url": url,
        "host": urlparse(url).netloc,
        "headers": headers,
        "body": body,
        "timestamp": now_iso(),
        "source": source,
        "response": None,
    }

    domain = urlparse(url).netloc
    if is_blocked(domain):
        req["response"] = {"error": f"domain '{domain}' is blocked"}
        record_request(req)
        return req

    try:
        started = time.perf_counter()
        resp = requests.request(
            method=method, url=url, headers=headers,
            data=body.encode("utf-8") if body else None, timeout=15,
        )
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        try:
            body_out = resp.json()
            is_json = True
        except ValueError:
            body_out = resp.text[:MAX_BODY_PREVIEW]
            is_json = False
        req["response"] = {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": body_out,
            "is_json": is_json,
            "elapsed_ms": elapsed_ms,
        }
    except Exception as exc:
        req["response"] = {"error": str(exc)}

    record_request(req)
    return req


@app.post("/api/forge-request")
def api_forge_request():
    data = request.json or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    method = data.get("method", "GET").upper()
    headers = data.get("headers") or {}
    body = data.get("body", "")

    req = _send(method, url, headers, body, source="forged")
    return jsonify(req)


@app.post("/api/request/<int:req_id>/repeat")
def api_repeat_request(req_id):
    """Repeater: resend a captured/forged request, optionally with edits."""
    overrides = request.json or {}
    with state_lock:
        original = next((r for r in intercepted_requests if r["id"] == req_id), None)
    if not original:
        return jsonify({"error": "not found"}), 404

    method = overrides.get("method", original["method"]).upper()
    url = overrides.get("url", original["url"])
    headers = overrides.get("headers", original.get("headers", {}))
    body = overrides.get("body", original.get("body", ""))

    if method == "CONNECT":
        return jsonify({"error": "CONNECT tunnels can't be replayed; repeat the underlying request instead"}), 400

    req = _send(method, url, headers, body, source="repeated")
    return jsonify(req)


def _to_curl(req):
    parts = ["curl", "-i", "-X", req["method"], f"'{req['url']}'"]
    for k, v in (req.get("headers") or {}).items():
        if k.lower() in ("host", "content-length"):
            continue
        v_escaped = str(v).replace("'", "'\\''")
        parts.append(f"-H '{k}: {v_escaped}'")
    if req.get("body"):
        body_escaped = req["body"].replace("'", "'\\''")
        parts.append(f"--data-raw '{body_escaped}'")
    return " \\\n  ".join(parts)


@app.get("/api/request/<int:req_id>/curl")
def api_request_curl(req_id):
    with state_lock:
        req = next((r for r in intercepted_requests if r["id"] == req_id), None)
    if not req:
        return jsonify({"error": "not found"}), 404
    return jsonify({"curl": _to_curl(req)})


if __name__ == "__main__":
    init_db()
    flask_port = find_available_port(5000)
    banner = f"""
  Interceptor — running at http://127.0.0.1:{flask_port}
  Proxy is OFF by default — start it from the UI (or POST /api/toggle-proxy).
"""
    print(banner)
    app.run(host="127.0.0.1", port=flask_port, debug=False)
