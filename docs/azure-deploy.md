# Azure Deployment Guide

Single Azure VM running nginx + oauth2-proxy (Entra ID SSO) in front of multiple internal Python tools. Each tool gets its own subdomain; a shared oauth2-proxy on the root domain issues one cookie that covers all subdomains.

```
internet → nginx (443)
            ├─ security.mycorpdomain.com        → oauth2 endpoints + portal redirect
            ├─ skillgate.security.mycorpdomain.com  → uvicorn :8000  (SkillGate)
            └─ dashboard.security.mycorpdomain.com  → gunicorn :8001 (vuln-ratio-report)
```

All subdomains share one Entra ID app registration and one oauth2-proxy process. Users sign in once; the auth cookie is valid for `*.security.mycorpdomain.com`.

Replace `security.mycorpdomain.com` and `mycorpdomain.com` throughout.

---

## 1. Provision the VM

- **Image:** Ubuntu 24.04 LTS
- **Size:** Standard_B2s (2 vCPU, 4 GB) — adequate for several light services
- **Public IP:** Static
- **NSG inbound rules:**

| Priority | Port | Source | Purpose |
|----------|------|--------|---------|
| 100 | 443 | Any | HTTPS (gated by Entra ID) |
| 110 | 80 | Any | HTTP → redirect to HTTPS only |
| 120 | 22 | Your office IP(s) | SSH — restrict this |

```bash
az vm create \
  --resource-group rg-security-tools \
  --name vm-security-tools \
  --image Ubuntu2404 \
  --size Standard_B2s \
  --admin-username azureuser \
  --ssh-key-values ~/.ssh/id_rsa.pub \
  --public-ip-sku Standard \
  --public-ip-address-allocation Static
```

---

## 2. DNS

Add A records for all three names pointing to the VM's public IP:

```
security.mycorpdomain.com           A  <VM public IP>
skillgate.security.mycorpdomain.com A  <VM public IP>
dashboard.security.mycorpdomain.com A  <VM public IP>
```

Verify propagation before running certbot:
```bash
dig +short security.mycorpdomain.com
dig +short skillgate.security.mycorpdomain.com
dig +short dashboard.security.mycorpdomain.com
```

---

## 3. Entra ID App Registration

In Azure portal → **Entra ID → App registrations → New registration**:

- **Name:** Security Tools Platform
- **Supported account types:** Accounts in this organizational directory only
- **Redirect URI:** `https://security.mycorpdomain.com/oauth2/callback`

After creating, note:
- **Application (client) ID** → `CLIENT_ID`
- **Directory (tenant) ID** → `TENANT_ID`

**Certificates & secrets → New client secret** → note the value → `CLIENT_SECRET`

**Restrict access** (recommended):
- Enterprise application → Properties → **Assignment required: Yes**
- Users and groups → add your security team

No additional API permissions are needed beyond the defaults (openid, profile, email).

---

## 4. Initial Server Setup

```bash
ssh azureuser@security.mycorpdomain.com

sudo apt update && sudo apt upgrade -y
sudo apt install -y nginx certbot python3-certbot-nginx \
    python3-pip python3-venv git ufw

# Firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 'Nginx Full'
sudo ufw allow OpenSSH
sudo ufw enable

# Service accounts — one per app, no login shell
sudo useradd -r -m -d /opt/skillgate  -s /usr/sbin/nologin skillgate
sudo useradd -r -m -d /opt/dashboard  -s /usr/sbin/nologin dashboard
```

---

## 5. TLS Certificate

Obtain a single certificate covering all three subdomains:

```bash
# Temporarily allow nginx to serve the HTTP challenge
sudo tee /etc/nginx/sites-available/certbot-bootstrap > /dev/null << 'EOF'
server {
    listen 80;
    server_name security.mycorpdomain.com
                skillgate.security.mycorpdomain.com
                dashboard.security.mycorpdomain.com;
    root /var/www/html;
}
EOF
sudo ln -s /etc/nginx/sites-available/certbot-bootstrap /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl start nginx

sudo certbot certonly --nginx \
  -d security.mycorpdomain.com \
  -d skillgate.security.mycorpdomain.com \
  -d dashboard.security.mycorpdomain.com \
  --non-interactive --agree-tos -m you@mycorpdomain.com

# Auto-renewal
sudo certbot renew --dry-run
```

---

## 6. Install oauth2-proxy

```bash
OAUTH2_PROXY_VERSION=7.8.2
curl -L "https://github.com/oauth2-proxy/oauth2-proxy/releases/download/v${OAUTH2_PROXY_VERSION}/oauth2-proxy-v${OAUTH2_PROXY_VERSION}.linux-amd64.tar.gz" \
  | sudo tar -xz -C /usr/local/bin --strip-components=1 \
    "oauth2-proxy-v${OAUTH2_PROXY_VERSION}.linux-amd64/oauth2-proxy"
sudo chmod +x /usr/local/bin/oauth2-proxy
```

Generate a random cookie secret:
```bash
python3 -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

```bash
sudo mkdir -p /etc/oauth2-proxy
sudo tee /etc/oauth2-proxy/oauth2-proxy.cfg > /dev/null << 'EOF'
provider           = "oidc"
oidc-issuer-url    = "https://login.microsoftonline.com/TENANT_ID/v2.0"
client-id          = "CLIENT_ID"
client-secret      = "CLIENT_SECRET"

redirect-url       = "https://security.mycorpdomain.com/oauth2/callback"
email-domain       = "mycorpdomain.com"

http-address       = "127.0.0.1:4180"
upstream           = "file:///dev/null"     # nginx handles routing; proxy does auth only

cookie-secret      = "GENERATED_SECRET"
cookie-secure      = true
cookie-domain      = ".security.mycorpdomain.com"   # covers all subdomains
cookie-samesite    = "lax"

set-xauthrequest   = true    # passes X-Auth-Request-User/Email headers to upstreams
scope              = "openid email profile"
EOF
sudo chmod 640 /etc/oauth2-proxy/oauth2-proxy.cfg
```

Replace `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`, and `GENERATED_SECRET`.

```bash
sudo tee /etc/systemd/system/oauth2-proxy.service > /dev/null << 'EOF'
[Unit]
Description=oauth2-proxy
After=network.target

[Service]
User=nobody
ExecStart=/usr/local/bin/oauth2-proxy --config=/etc/oauth2-proxy/oauth2-proxy.cfg
Restart=on-failure
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now oauth2-proxy
```

---

## 7. Deploy SkillGate

```bash
sudo git clone https://github.com/tc-mgriff/skillgate.git /opt/skillgate
sudo chown -R skillgate:skillgate /opt/skillgate

sudo -u skillgate python3 -m venv /opt/skillgate/.venv
sudo -u skillgate /opt/skillgate/.venv/bin/pip install -r /opt/skillgate/requirements.txt
```

```bash
sudo tee /etc/skillgate.env > /dev/null << 'EOF'
JIRA_BASE_URL=https://your-org.atlassian.net
JIRA_EMAIL=you@mycorpdomain.com
JIRA_API_TOKEN=your-atlassian-api-token
JIRA_PROJECT=SKILL
SKILLGATE_LLM_ENDPOINT=https://<res>.services.ai.azure.com/anthropic
SKILLGATE_LLM_API_KEY=your-foundry-key
SKILLGATE_LLM_MODEL=your-claude-deployment-name
EOF
sudo chmod 640 /etc/skillgate.env
sudo chown root:skillgate /etc/skillgate.env
```

```bash
sudo tee /etc/systemd/system/skillgate.service > /dev/null << 'EOF'
[Unit]
Description=SkillGate
After=network.target

[Service]
User=skillgate
WorkingDirectory=/opt/skillgate
EnvironmentFile=/etc/skillgate.env
ExecStart=/opt/skillgate/.venv/bin/uvicorn app.main:app \
    --host 127.0.0.1 --port 8000
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now skillgate
```

---

## 8. Deploy vuln-ratio-report (Dashboard)

```bash
# The repo path on this machine — adjust if cloned elsewhere
DASHBOARD_REPO="/Users/matt/Library/Mobile Documents/com~apple~CloudDocs/Projects/vuln-ratio-report"

sudo rsync -a --chown=dashboard:dashboard "$DASHBOARD_REPO/" /opt/dashboard/
# or clone directly if the repo is on GitHub:
# sudo git clone https://github.com/your-org/vuln-ratio-report.git /opt/dashboard
# sudo chown -R dashboard:dashboard /opt/dashboard
```

Install from pyproject.toml (no requirements.txt — the package uses modern packaging):

```bash
sudo -u dashboard python3 -m venv /opt/dashboard/.venv
sudo -u dashboard /opt/dashboard/.venv/bin/pip install -e /opt/dashboard
```

Create the config file (copy and fill in from the example):

```bash
sudo -u dashboard mkdir -p /opt/dashboard/config
sudo cp /opt/dashboard/config/config.example.yaml /opt/dashboard/config/config.yaml
sudo -u dashboard nano /opt/dashboard/config/config.yaml   # fill in sections/filters
```

Create the environment file:

```bash
sudo tee /etc/dashboard.env > /dev/null << 'EOF'
# CrowdStrike
CS_CLIENT_ID=your-cs-client-id
CS_CLIENT_SECRET=your-cs-client-secret
CS_BASE_URL=https://api.crowdstrike.com

# Rapid7 data warehouse (PostgreSQL)
PGHOST=pg-rapid7.postgres.database.azure.com
PGPORT=5432
PGDATABASE=postgres
PGUSER=rapid7export
PGPASSWORD=your-rapid7-password

# History database — SQLite is fine for VM deployment
VULN_RATIO_DATABASE_URL=sqlite:////opt/dashboard/data/vuln_ratio_history.db

# Config file location
VULN_RATIO_CONFIG=/opt/dashboard/config/config.yaml

# DO NOT set VULN_RATIO_AUTH_BYPASS in production
EOF
sudo chmod 640 /etc/dashboard.env
sudo chown root:dashboard /etc/dashboard.env

# Data directory for SQLite
sudo -u dashboard mkdir -p /opt/dashboard/data
```

Run the database migration before starting the service:

```bash
sudo -u dashboard bash -c "
  set -a; source /etc/dashboard.env; set +a
  cd /opt/dashboard
  .venv/bin/alembic upgrade head
"
```

App service (Gunicorn):

```bash
sudo tee /etc/systemd/system/dashboard.service > /dev/null << 'EOF'
[Unit]
Description=vuln-ratio-report dashboard
After=network.target

[Service]
User=dashboard
WorkingDirectory=/opt/dashboard
EnvironmentFile=/etc/dashboard.env
ExecStart=/opt/dashboard/.venv/bin/gunicorn \
    --workers 3 --timeout 60 \
    --bind 127.0.0.1:8001 \
    vuln_ratio.web.app:app
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
```

Scheduled data sync — daily at 05:15 UTC via systemd timer (matches the Helm CronJob schedule):

```bash
sudo tee /etc/systemd/system/dashboard-sync.service > /dev/null << 'EOF'
[Unit]
Description=vuln-ratio data sync (one-shot)
After=network.target

[Service]
User=dashboard
WorkingDirectory=/opt/dashboard
EnvironmentFile=/etc/dashboard.env
ExecStart=/opt/dashboard/.venv/bin/vuln-ratio generate --multi
Type=oneshot
StandardOutput=journal
StandardError=journal
EOF

sudo tee /etc/systemd/system/dashboard-sync.timer > /dev/null << 'EOF'
[Unit]
Description=vuln-ratio daily data sync

[Timer]
OnCalendar=*-*-* 05:15:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now dashboard.service dashboard-sync.timer
```

Check the timer: `systemctl list-timers dashboard-sync.timer`

Trigger a manual sync to verify credentials and connectivity:

```bash
sudo systemctl start dashboard-sync.service
sudo journalctl -u dashboard-sync.service -f
```

---

## 9. nginx Configuration

Remove the bootstrap config and replace with the full configuration:

```bash
sudo rm /etc/nginx/sites-enabled/certbot-bootstrap

sudo tee /etc/nginx/sites-available/security-tools > /dev/null << 'EOF'
# ── Redirect all HTTP → HTTPS ──────────────────────────────────────────────
server {
    listen 80;
    server_name security.mycorpdomain.com
                skillgate.security.mycorpdomain.com
                dashboard.security.mycorpdomain.com;
    return 301 https://$host$request_uri;
}

# ── Shared SSL config (included by each vhost) ─────────────────────────────
# Note: certbot issued one cert covering all three names
ssl_certificate     /etc/letsencrypt/live/security.mycorpdomain.com/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/security.mycorpdomain.com/privkey.pem;
ssl_protocols       TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;

# ── Root domain — oauth2-proxy endpoints + portal redirect ─────────────────
server {
    listen 443 ssl;
    server_name security.mycorpdomain.com;

    # oauth2-proxy sign-in / callback — no auth required on these
    location /oauth2/ {
        proxy_pass       http://127.0.0.1:4180;
        proxy_set_header Host                    $host;
        proxy_set_header X-Real-IP               $remote_addr;
        proxy_set_header X-Scheme                $scheme;
        proxy_set_header X-Auth-Request-Redirect $request_uri;
    }

    # Internal auth sub-request endpoint used by other vhosts
    location = /oauth2/auth {
        proxy_pass             http://127.0.0.1:4180;
        proxy_pass_request_body off;
        proxy_set_header        Content-Length "";
        proxy_set_header        X-Original-URI $request_uri;
        proxy_cache_bypass      $cookie__oauth2_proxy;
    }

    location / {
        return 302 https://dashboard.security.mycorpdomain.com/;
    }
}

# ── SkillGate ───────────────────────────────────────────────────────────────
server {
    listen 443 ssl;
    server_name skillgate.security.mycorpdomain.com;

    location = /oauth2/auth {
        proxy_pass             http://127.0.0.1:4180;
        proxy_pass_request_body off;
        proxy_set_header        Content-Length "";
        proxy_set_header        X-Original-URI $request_uri;
        proxy_cache_bypass      $cookie__oauth2_proxy;
    }

    location / {
        auth_request /oauth2/auth;
        error_page 401 = @signin;

        auth_request_set $auth_cookie $upstream_http_set_cookie;
        add_header       Set-Cookie $auth_cookie;
        auth_request_set $user  $upstream_http_x_auth_request_user;
        auth_request_set $email $upstream_http_x_auth_request_email;
        proxy_set_header X-User  $user;
        proxy_set_header X-Email $email;

        proxy_pass       http://127.0.0.1:8000;
        proxy_set_header Host      $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location @signin {
        return 302 https://security.mycorpdomain.com/oauth2/sign_in?rd=$scheme://$host$request_uri;
    }
}

# ── Dashboard (vuln-ratio-report) ──────────────────────────────────────────
server {
    listen 443 ssl;
    server_name dashboard.security.mycorpdomain.com;

    location = /oauth2/auth {
        proxy_pass             http://127.0.0.1:4180;
        proxy_pass_request_body off;
        proxy_set_header        Content-Length "";
        proxy_set_header        X-Original-URI $request_uri;
        proxy_cache_bypass      $cookie__oauth2_proxy;
    }

    location / {
        auth_request /oauth2/auth;
        error_page 401 = @signin;

        auth_request_set $auth_cookie $upstream_http_set_cookie;
        add_header       Set-Cookie $auth_cookie;
        auth_request_set $user  $upstream_http_x_auth_request_user;
        auth_request_set $email $upstream_http_x_auth_request_email;
        proxy_set_header X-User        $user;
        proxy_set_header X-Email       $email;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        proxy_pass       http://127.0.0.1:8001;
        proxy_set_header Host      $host;
        proxy_set_header X-Real-IP $remote_addr;

        # Dashboard SSE / long-poll timeout
        proxy_read_timeout 120s;
    }

    location @signin {
        return 302 https://security.mycorpdomain.com/oauth2/sign_in?rd=$scheme://$host$request_uri;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/security-tools /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

---

## 10. Smoke Test

```bash
# All services running?
sudo systemctl status oauth2-proxy skillgate dashboard nginx

# Live logs
sudo journalctl -u skillgate   -f &
sudo journalctl -u dashboard   -f &
sudo journalctl -u oauth2-proxy -f &

# Unauthenticated request should redirect to Entra ID login
curl -I https://skillgate.security.mycorpdomain.com/
curl -I https://dashboard.security.mycorpdomain.com/
# Both expect: 302 → https://security.mycorpdomain.com/oauth2/sign_in?rd=...

# Health checks (bypass auth for monitoring)
curl http://127.0.0.1:8000/healthz    # SkillGate
curl http://127.0.0.1:8001/healthz    # Dashboard
```

After signing in with an `@mycorpdomain.com` account you should be able to navigate between both tools without re-authenticating.

---

## 11. Adding a New Tool

1. Create a service account, clone to `/opt/newtool`, venv, env file — same pattern.
2. Add a systemd unit binding to `127.0.0.1:800N`.
3. Add a new server block to `/etc/nginx/sites-available/security-tools` (copy either existing block).
4. Add a new DNS A record: `newtool.security.mycorpdomain.com → <same VM IP>`.
5. Expand the cert: `sudo certbot certonly --nginx -d security.mycorpdomain.com -d skillgate.security.mycorpdomain.com -d dashboard.security.mycorpdomain.com -d newtool.security.mycorpdomain.com`
6. `sudo nginx -t && sudo systemctl reload nginx`

No oauth2-proxy changes needed — it already sets `cookie-domain = .security.mycorpdomain.com`.

---

## 12. Deploying Updates

**SkillGate:**
```bash
cd /opt/skillgate
sudo -u skillgate git pull
sudo systemctl restart skillgate
```

**Dashboard:**
```bash
cd /opt/dashboard
sudo -u dashboard git pull          # or rsync from local
sudo -u dashboard bash -c "
  set -a; source /etc/dashboard.env; set +a
  cd /opt/dashboard && .venv/bin/alembic upgrade head
"
sudo systemctl restart dashboard
```

---

## 13. Security Notes

- SSH restricted to corp IPs via NSG.
- Each service runs as its own non-root system user with `NoNewPrivileges=true` and `PrivateTmp=true`.
- All env files are `640 root:<service-user>` — not world-readable.
- oauth2-proxy's `email-domain` ensures only `@mycorpdomain.com` addresses authenticate even if the Entra app registration is misconfigured.
- `VULN_RATIO_AUTH_BYPASS` must never be set in production (disables all authentication in the dashboard).
- SkillGate deletes all uploaded artifacts after scanning — nothing is retained on disk.
