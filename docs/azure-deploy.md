# Azure Deployment Guide

Single Azure VM running nginx + oauth2-proxy in front of multiple internal Python tools, all protected by Entra ID SSO.

```
internet → nginx (443, TLS) → auth_request → oauth2-proxy (Entra ID OIDC)
                            ↓ authed
                       /skillgate/  → uvicorn :8000  (SkillGate)
                       /dashboard/  → uvicorn :8001  (Dashboard + sync timer)
                       /newtool/    → uvicorn :800N  (future tools)
```

Replace `security.mycorpdomain.com` and `mycorpdomain.com` throughout.

---

## 1. Provision the VM

In the Azure portal (or CLI):

- **Image:** Ubuntu 24.04 LTS
- **Size:** Standard_B2s (2 vCPU, 4 GB) — adequate for several light services
- **Public IP:** Static
- **NSG inbound rules:**

| Priority | Port | Source | Purpose |
|----------|------|--------|---------|
| 100 | 443 | Any | HTTPS (public, gated by Entra) |
| 110 | 80 | Any | HTTP → redirect to HTTPS only |
| 120 | 22 | Your office IP(s) | SSH — lock this down |

```bash
# Create via CLI if preferred
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

Note the public IP — you need it for DNS before certbot will work.

---

## 2. DNS

Add an A record at your DNS provider:

```
security.mycorpdomain.com  A  <VM public IP>  TTL 300
```

Verify before continuing:
```bash
dig +short security.mycorpdomain.com
```

---

## 3. Entra ID App Registration

In the Azure portal → **Entra ID → App registrations → New registration**:

- **Name:** Security Tools Platform
- **Supported account types:** Accounts in this organizational directory only
- **Redirect URI:** `https://security.mycorpdomain.com/oauth2/callback`

After creating, note:
- **Application (client) ID** → `CLIENT_ID`
- **Directory (tenant) ID** → `TENANT_ID`

Then **Certificates & secrets → New client secret** → note the value → `CLIENT_SECRET`

**Restrict access to specific users/groups** (recommended):
- App registrations → your app → **Enterprise application** link → Properties → **Assignment required: Yes**
- Users and groups → Add your security team

**API permissions** — the defaults (openid, profile, email via Microsoft Graph) are sufficient. No additional permissions needed.

---

## 4. Initial Server Setup

```bash
ssh azureuser@security.mycorpdomain.com

sudo apt update && sudo apt upgrade -y
sudo apt install -y nginx certbot python3-certbot-nginx python3-pip python3-venv git ufw

# Firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 'Nginx Full'
sudo ufw allow OpenSSH
sudo ufw enable

# Service accounts — one per app, no login shell
sudo useradd -r -m -d /opt/skillgate -s /usr/sbin/nologin skillgate
sudo useradd -r -m -d /opt/dashboard -s /usr/sbin/nologin dashboard
```

---

## 5. Install oauth2-proxy

oauth2-proxy handles the Entra ID OIDC flow. nginx delegates auth decisions to it via `auth_request`.

```bash
# Check https://github.com/oauth2-proxy/oauth2-proxy/releases for latest version
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

Create the config file:
```bash
sudo mkdir -p /etc/oauth2-proxy
sudo tee /etc/oauth2-proxy/oauth2-proxy.cfg > /dev/null << 'EOF'
provider = "oidc"
oidc-issuer-url = "https://login.microsoftonline.com/TENANT_ID/v2.0"
client-id = "CLIENT_ID"
client-secret = "CLIENT_SECRET"

redirect-url = "https://security.mycorpdomain.com/oauth2/callback"
email-domain = "mycorpdomain.com"

http-address = "127.0.0.1:4180"
upstream = "file:///dev/null"   # nginx handles routing; proxy just does auth

cookie-secret = "GENERATED_SECRET"
cookie-secure = true
cookie-domain = "security.mycorpdomain.com"
cookie-samesite = "lax"

set-xauthrequest = true         # passes X-Auth-Request-User/Email to upstreams

scope = "openid email profile"
EOF
sudo chmod 640 /etc/oauth2-proxy/oauth2-proxy.cfg
```

Replace `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`, and `GENERATED_SECRET`.

Systemd unit:
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
sudo systemctl status oauth2-proxy
```

---

## 6. Deploy SkillGate

```bash
sudo git clone https://github.com/tc-mgriff/skillgate.git /opt/skillgate
sudo chown -R skillgate:skillgate /opt/skillgate

sudo -u skillgate python3 -m venv /opt/skillgate/.venv
sudo -u skillgate /opt/skillgate/.venv/bin/pip install -r /opt/skillgate/requirements.txt
```

Create the environment file (never commit this):
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
```

Systemd unit:
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
    --host 127.0.0.1 --port 8000 \
    --root-path /skillgate
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now skillgate
sudo systemctl status skillgate
```

> **Note:** `--root-path /skillgate` tells FastAPI its mounted prefix so internal URL generation is correct. You also need to change the `fetch` call in `app/templates/index.html` from `'/upload'` to `'upload'` (relative URL) so the browser resolves it against the subpath correctly.

---

## 7. Deploy the Dashboard

Same pattern. Adjust port and paths for your dashboard repo.

```bash
sudo git clone https://github.com/your-org/dashboard.git /opt/dashboard
sudo chown -R dashboard:dashboard /opt/dashboard

sudo -u dashboard python3 -m venv /opt/dashboard/.venv
sudo -u dashboard /opt/dashboard/.venv/bin/pip install -r /opt/dashboard/requirements.txt
```

```bash
sudo tee /etc/dashboard.env > /dev/null << 'EOF'
# dashboard-specific env vars
DATABASE_URL=...
EOF
sudo chmod 640 /etc/dashboard.env
```

App service:
```bash
sudo tee /etc/systemd/system/dashboard.service > /dev/null << 'EOF'
[Unit]
Description=Dashboard
After=network.target

[Service]
User=dashboard
WorkingDirectory=/opt/dashboard
EnvironmentFile=/etc/dashboard.env
ExecStart=/opt/dashboard/.venv/bin/uvicorn app.main:app \
    --host 127.0.0.1 --port 8001 \
    --root-path /dashboard
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
```

Scheduled data sync as a systemd timer (replaces cron):
```bash
sudo tee /etc/systemd/system/dashboard-sync.service > /dev/null << 'EOF'
[Unit]
Description=Dashboard data sync (one-shot)
After=network.target

[Service]
User=dashboard
WorkingDirectory=/opt/dashboard
EnvironmentFile=/etc/dashboard.env
ExecStart=/opt/dashboard/.venv/bin/python -m app.sync
Type=oneshot
EOF

sudo tee /etc/systemd/system/dashboard-sync.timer > /dev/null << 'EOF'
[Unit]
Description=Dashboard data sync schedule

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now dashboard.service dashboard-sync.timer
```

Check timer schedule: `systemctl list-timers dashboard-sync.timer`

---

## 8. nginx Configuration

```bash
sudo tee /etc/nginx/sites-available/security-tools > /dev/null << 'EOF'
# Redirect HTTP → HTTPS
server {
    listen 80;
    server_name security.mycorpdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name security.mycorpdomain.com;

    ssl_certificate     /etc/letsencrypt/live/security.mycorpdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/security.mycorpdomain.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    # oauth2-proxy sign-in / callback endpoints — must be reachable without auth
    location /oauth2/ {
        proxy_pass       http://127.0.0.1:4180;
        proxy_set_header Host                    $host;
        proxy_set_header X-Real-IP               $remote_addr;
        proxy_set_header X-Scheme                $scheme;
        proxy_set_header X-Auth-Request-Redirect $request_uri;
    }

    # Internal auth check sub-request used by auth_request below
    location = /oauth2/auth {
        proxy_pass             http://127.0.0.1:4180;
        proxy_pass_request_body off;
        proxy_set_header        Content-Length  "";
        proxy_set_header        X-Original-URI  $request_uri;
        proxy_cache_bypass      $cookie__oauth2_proxy;
    }

    # Redirect root to a default tool
    location = / {
        return 302 /dashboard/;
    }

    # ---- SkillGate ----
    location /skillgate/ {
        auth_request /oauth2/auth;
        error_page 401 = @signin;

        auth_request_set $auth_cookie $upstream_http_set_cookie;
        add_header       Set-Cookie $auth_cookie;
        auth_request_set $user  $upstream_http_x_auth_request_user;
        auth_request_set $email $upstream_http_x_auth_request_email;
        proxy_set_header X-User  $user;
        proxy_set_header X-Email $email;

        proxy_pass       http://127.0.0.1:8000/;
        proxy_set_header Host      $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # ---- Dashboard ----
    location /dashboard/ {
        auth_request /oauth2/auth;
        error_page 401 = @signin;

        auth_request_set $auth_cookie $upstream_http_set_cookie;
        add_header       Set-Cookie $auth_cookie;
        auth_request_set $user  $upstream_http_x_auth_request_user;
        auth_request_set $email $upstream_http_x_auth_request_email;
        proxy_set_header X-User  $user;
        proxy_set_header X-Email $email;

        proxy_pass       http://127.0.0.1:8001/;
        proxy_set_header Host      $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # ---- Add new tools here following the same block pattern ----

    location @signin {
        return 302 /oauth2/sign_in?rd=$scheme://$host$request_uri;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/security-tools /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
```

Don't reload nginx yet — the SSL cert doesn't exist. Do that after certbot.

---

## 9. TLS Certificate (Let's Encrypt)

```bash
# Obtain cert using the nginx plugin (handles HTTP challenge automatically)
sudo certbot --nginx -d security.mycorpdomain.com \
    --non-interactive --agree-tos -m you@mycorpdomain.com

# Verify auto-renewal works
sudo certbot renew --dry-run

# Now reload nginx
sudo systemctl enable --now nginx
sudo nginx -t && sudo systemctl reload nginx
```

---

## 10. Smoke Test

```bash
# All services healthy?
sudo systemctl status oauth2-proxy skillgate dashboard nginx

# Logs
sudo journalctl -u skillgate -f
sudo journalctl -u oauth2-proxy -f

# Hit the site — should redirect to Entra ID login
curl -I https://security.mycorpdomain.com/skillgate/
# Expect: 302 to login.microsoftonline.com
```

After logging in with your org account you should land on the dashboard, and `/skillgate/` should load the upload UI.

---

## 11. Adding a New Tool

1. Clone the repo to `/opt/newtool`, create a service account, venv, env file — same pattern as above.
2. Add a systemd unit at port `800N` with `--root-path /newtool`.
3. Add a `location /newtool/` block to `/etc/nginx/sites-available/security-tools` (copy any existing block, change the port).
4. `sudo nginx -t && sudo systemctl reload nginx`
5. `sudo systemctl enable --now newtool`

No oauth2-proxy changes needed — auth is handled by nginx's `auth_request` directive and the shared cookie covers all paths under the domain.

---

## 12. Deploying Updates

```bash
# SkillGate update
cd /opt/skillgate
sudo -u skillgate git pull
sudo -u skillgate .venv/bin/pip install -r requirements.txt
sudo systemctl restart skillgate
```

For zero-downtime on a single VM, you can run two uvicorn workers behind the same port with `--workers 2` and use `systemctl reload` (sends SIGHUP) instead of restart, but for internal tooling a brief restart is usually fine.

---

## Security Notes

- SSH is locked to corp IPs via NSG — don't remove that rule.
- Each service runs as its own non-root system user with `PrivateTmp=true` and `NoNewPrivileges=true`.
- All env files (`/etc/*.env`) are `640 root:<service-user>` — not world-readable.
- oauth2-proxy's `email-domain` restriction ensures only `@mycorpdomain.com` addresses can authenticate, even if the Entra app registration is somehow misconfigured.
- SkillGate's scan worker deletes all uploaded artifacts after scanning — nothing is retained on disk.
- The docker socket is **not** bind-mounted in this deployment (subprocess scan mode). If you switch to container mode, see the security note in the SkillGate README.
