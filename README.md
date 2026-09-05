# Interceptor

A lightweight HTTP/HTTPS interception proxy with a web UI — built for
learning how MITM proxies, request tampering, and replay tooling actually
work under the hood. Think "a tiny Burp Suite" you fully understand because
you can read every line of it.

## Features

- **Proxy capture** — a local HTTP proxy that logs every request/response
  that passes through it (method, URL, headers, body, status, timing).
- **HTTPS tunneling** — `CONNECT` requests are tunneled (not decrypted — no
  fake CA is installed on your system), so HTTPS traffic keeps working
  through the proxy even though only the connection metadata is visible.
- **Repeater** — pick any captured request, tweak the method/URL/headers/
  body, and resend it. The core "poke at an endpoint" workflow.
- **Forge** — build and send a request from scratch, no proxy needed.
- **Block rules** — block requests to a domain (and its subdomains) at the
  proxy level; blocked attempts still show up in the traffic list.
- **Export as curl** — copy any captured request as a ready-to-paste `curl`
  command, handy for writeups and reports.
- **Persistent history** — traffic and block rules are stored in a local
  SQLite file (`interceptor.db`) and reloaded on restart.
- **Live UI** — all panes update over a WebSocket as traffic arrives; no
  polling, no manual refresh.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

The app prints the URL it's serving on (auto-picks a free port starting at
5000). Open it in a browser.

## Using the proxy

1. Click **Start** next to the proxy indicator in the top bar. It picks a
   free port starting at 8080 and shows you the address.
2. Point a client at it — e.g. `curl -x http://127.0.0.1:8080 http://example.com`,
   or set it as your browser's/`http_proxy` env var for HTTP testing.
3. Watch requests land in the **Traffic** pane in real time.

You don't need the proxy running at all to use **Forge** or **Repeater** —
those send requests directly from the server, independent of the proxy.

## Notes on scope

- HTTPS payloads are **tunneled, not decrypted**. Decrypting TLS would
  require generating and trusting a local CA on the client — out of scope
  for a learning tool you run against your own lab targets. Use HTTP
  targets (most intentionally-vulnerable lab apps run over HTTP) or point
  it at the plaintext side of a TLS-terminating reverse proxy in a lab.
- This is a manual-testing aid, not a scanner — it doesn't fuzz, brute
  force, or crawl on its own. Repeater/Forge are the building blocks for
  doing that by hand or scripting on top of the same API endpoints it
  exposes (`/api/forge-request`, `/api/request/<id>/repeat`, etc).
- Intended for your own lab/CTF environments and systems you're authorized
  to test.

## Project layout

```
app.py                  Flask app: proxy server, API, WebSocket broadcast
templates/index.html    Single-page UI shell
static/css/style.css    Styling
static/js/app.js        Frontend logic (fetch + WebSocket wiring)
requirements.txt
```
