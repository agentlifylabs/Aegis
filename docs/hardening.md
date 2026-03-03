# Aegis Hardening Guide

This guide covers TLS, mTLS, reverse-proxy deployment, and production security
recommendations for `aegisd`.

---

## 1. TLS — aegisd behind a reverse proxy (recommended)

The simplest and most operationally maintainable approach is to terminate TLS
at a reverse proxy (Caddy, nginx, Traefik) and let aegisd listen on plain HTTP
on `127.0.0.1`.

### Caddy (automatic HTTPS)

```
# /etc/caddy/Caddyfile
aegis.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy auto-provisions a Let's Encrypt certificate. No manual cert management.

### nginx

```nginx
# /etc/nginx/sites-available/aegis
server {
    listen 443 ssl http2;
    server_name aegis.example.com;

    ssl_certificate     /etc/letsencrypt/live/aegis.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/aegis.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
```

---

## 2. Direct TLS — aegisd serves HTTPS

When a reverse proxy is not available, configure `aegis.yaml`:

```yaml
tls:
  enabled: true
  cert_file: /etc/aegis/tls/cert.pem
  key_file:  /etc/aegis/tls/key.pem
```

Generate a self-signed certificate for internal/dev use:

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout /etc/aegis/tls/key.pem \
  -out    /etc/aegis/tls/cert.pem \
  -subj "/CN=aegisd" \
  -addext "subjectAltName=DNS:aegisd,IP:127.0.0.1"
```

For production, use a certificate from your internal CA or Let's Encrypt.

---

## 3. mTLS — mutual client authentication

mTLS ensures only authorised agent frameworks can connect to aegisd.

```yaml
tls:
  enabled:   true
  cert_file: /etc/aegis/tls/server-cert.pem
  key_file:  /etc/aegis/tls/server-key.pem
  ca_file:   /etc/aegis/tls/client-ca.pem   # verifies client certs
```

Issue client certificates from your internal CA and distribute them to agent
processes. Revoke compromised client certs by updating `client-ca.pem` and
reloading aegisd.

**nginx mTLS termination** (alternative — keeps aegisd config simple):

```nginx
ssl_client_certificate /etc/aegis/tls/client-ca.pem;
ssl_verify_client      on;
```

---

## 4. Network isolation

- **Docker / Compose:** bind aegisd to `127.0.0.1:8080`; only the reverse
  proxy container should reach it. In Compose, use an internal network:

  ```yaml
  networks:
    internal:
      internal: true   # no external internet access
  ```

- **Firewall:** allow inbound 443 only; block direct access to port 8080.

- **MCP proxy** (`--mcp-addr`): if enabled, apply the same isolation. The MCP
  proxy should never be internet-facing.

---

## 5. Secrets management

Never commit credentials. Recommended patterns (in order of preference):

1. **Docker secrets** (`deploy/docker-compose.prod.yml` already uses this).
2. **Environment file** (`/etc/aegis/aegisd.env`, mode 0600, owned by `aegis`).
3. **Vault / cloud secret manager** — inject via env at container startup.

For the Postgres DSN, use the `PGPASSWORD` environment variable or a `.pgpass`
file rather than embedding the password in the DSN string.

---

## 6. OS hardening (systemd)

The `deploy/aegisd.service` unit already sets:

| Option | Effect |
|---|---|
| `NoNewPrivileges=true` | Prevents privilege escalation |
| `PrivateTmp=true` | Isolated `/tmp` |
| `ProtectSystem=strict` | Read-only filesystem except `ReadWritePaths` |
| `ProtectHome=true` | No access to `/home` or `/root` |
| `CapabilityBoundingSet=` | Drop all Linux capabilities |

Additional recommendations:

```ini
# Add to [Service] for further hardening
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
```

---

## 7. trust_mode: prod checklist

When `trust_mode: prod`:

- [ ] Manifest is loaded from a verified path (`--manifest`)
- [ ] Manifest signature verification is enabled (Epic 13+)
- [ ] Database is Postgres with TLS (`sslmode=require`)
- [ ] Telemetry path is writable and monitored
- [ ] Log format is `json` (for structured log ingestion)
- [ ] Rate limiting is configured (`rate_limit: 120` or lower)
- [ ] aegisd is behind TLS (reverse proxy or direct)
- [ ] Postgres password is managed via secrets (not embedded in DSN)
- [ ] systemd unit is installed and enabled

---

## 8. Log forwarding

With `log.format: json`, pipe to your SIEM:

```bash
# journald → stdout → vector/fluentd
journalctl -u aegisd -f -o json | vector --config /etc/vector/vector.toml
```

Or use the Docker logging driver:

```yaml
# in docker-compose.prod.yml
logging:
  driver: "json-file"
  options:
    max-size: "100m"
    max-file: "5"
```
