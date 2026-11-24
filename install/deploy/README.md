# Deploying Hashview behind a TLS-terminating reverse proxy

The built-in Werkzeug server terminates TLS inline on a single accept thread, so
one stalled client can freeze every new connection (`hashview/utils/tls.py`). The
supported production shape is to **terminate TLS in a reverse proxy** and run the
app as plain HTTP on localhost.

**App side** — in `hashview/config.conf`, under `[SERVER]`:

```ini
behind_proxy = true
# bind_host = 127.0.0.1   # defaults; the app binds here under --no-ssl
# bind_port = 5000
```

Keep `SERVER_NAME` on the public `host:port` the proxy listens on (e.g.
`FQDN:8443`), then run the app with:

```
venv/bin/python hashview.py --no-ssl        # serves plain HTTP on 127.0.0.1:5000
```

**Proxy side** — pick one, edit the host + cert paths, then reload:

| File | Proxy | Install target | Reload |
|------|-------|----------------|--------|
| `nginx-hashview.conf.example` | nginx (recommended) | `/etc/nginx/conf.d/hashview.conf` (RHEL) or `sites-available/` + symlink (Debian) | `nginx -t && systemctl reload nginx` |
| `Caddyfile.example` | Caddy | `/etc/caddy/Caddyfile` | `caddy validate ... && systemctl reload caddy` |

`hashview.service.example` is an optional systemd unit for the app itself (there
is no process supervision today) — **run exactly one instance** (the app starts
the scheduler).

Both proxy configs listen on **8443** and reuse the existing self-signed cert at
`<repo>/hashview/ssl/cert.pem|key.pem`, so agents, browsers, and SSO need no
change. Swap in a CA-signed cert at the proxy to drop browser warnings (agents
use `verify=False`, so nothing else changes). Open **8443** at the firewall and
keep **5000** closed. See the comments in each file for the full rationale,
large-upload streaming directives, and timeouts.
