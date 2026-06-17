# Deployment Guide

You provide HTTPS via your existing Nginx. This guide shows how to add the
`/keychain/` reverse-proxy location and run the `vault-server` binary as a
systemd service.

## 1. Build

```bash
cargo build --release
sudo install -m755 target/release/vault-server /usr/local/bin/
sudo install -m755 target/release/vault-cli /usr/local/bin/
```

## 2. System user + directories

```bash
sudo useradd -r -s /usr/sbin/nologin vault
sudo mkdir -p /var/lib/vault /etc/vault
sudo chown vault:vault /var/lib/vault /etc/vault
sudo chmod 700 /var/lib/vault /etc/vault
```

## 3. Generate API token

```bash
echo "AUTH_TOKEN=$(openssl rand -base64 48)" | sudo tee /etc/vault/env
sudo chmod 600 /etc/vault/env
```

## 4. Install systemd unit

```bash
sudo cp systemd/vault-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vault-server
sudo systemctl status vault-server
```

## 5. Wire into existing Nginx

In your existing Nginx config's `http { ... }` block, add (or merge):
```nginx
limit_req_zone $binary_remote_addr zone=vault_api:10m rate=5r/s;
```

In your site's `server { ... }` block, paste the contents of
`nginx/vault.conf.snippet`. Then:

```bash
sudo nginx -t
sudo nginx -s reload
```

## 6. First-time init from local machine

```bash
vault-cli init --password "your 6+ diceware words" \
    --token "$(sudo cat /etc/vault/env | cut -d= -f2)" \
    --api "https://vault.example.com/keychain/vault" \
    --csv ~/sample.csv
```

## 7. Backup

```bash
sudo cp /var/lib/vault/vault.db /backup/vault-$(date +%F).db
```

The DB is already encrypted; **the master password is the only thing that
matters for recovery**.

## Rollback

```bash
sudo systemctl disable --now vault-server
sudo rm /etc/systemd/system/vault-server.service
# Remove the /keychain/ block from Nginx config
```
