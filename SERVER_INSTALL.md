# Veil server installation

This release has two installation paths:

1. **Serve the wallet UI** — copy the already-built `dist-ui/` directory to a
   static web server. This is the simplest option and does not require Node.js.
2. **Replay and rebuild the protocol** — install Node.js and run the circuit,
   contract, and transaction tests from source.

> Veil is an unaudited bounty prototype. The UI creates and verifies real
> Groth16 proofs against local demo state, but it does not broadcast
> transactions or hold real funds.

## Option A: publish the prebuilt UI with Nginx

The following commands target Ubuntu or Debian. Replace the archive name if a
different version was supplied.

```bash
unzip veil-bsv-server-0.2.1.zip
cd veil-bsv-server-0.2.1
sha256sum -c MANIFEST.sha256
```

Install Nginx and copy the site:

```bash
sudo apt-get update
sudo apt-get install -y nginx
sudo mkdir -p /var/www/veil
sudo cp -R dist-ui/. /var/www/veil/
```

Create `/etc/nginx/sites-available/veil` with this configuration:

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name veil.example.com;

    root /var/www/veil;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location = /zk/shielded_pool.wasm {
        default_type application/wasm;
        add_header Cache-Control "public, max-age=31536000, immutable";
    }

    location = /zk/shielded_pool_final.zkey {
        default_type application/octet-stream;
        add_header Cache-Control "public, max-age=31536000, immutable";
    }

    location /zk/ {
        try_files $uri =404;
        add_header Cache-Control "public, max-age=3600";
    }
}
```

Change `veil.example.com` to the server's real domain. Then enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/veil /etc/nginx/sites-enabled/veil
sudo nginx -t
sudo systemctl reload nginx
```

Open `http://veil.example.com`. For a public deployment, add HTTPS before
sharing the URL. On Ubuntu, the common route is Certbot's Nginx integration:

```bash
sudo apt-get install -y certbot python3-certbot-nginx
sudo certbot --nginx -d veil.example.com
```

### Quick server check

```bash
curl -I https://veil.example.com/
curl -I https://veil.example.com/zk/shielded_pool.wasm
curl -I https://veil.example.com/zk/shielded_pool_final.zkey
```

All three requests should return `200`. The proving key is approximately 10 MB,
so the first proof takes longer while the browser downloads and caches it.

## Option B: replay and rebuild from source

Use Node.js 20 or newer. A clean Ubuntu host can install it with the deployment
method approved by its administrator. Confirm the versions before continuing:

```bash
node --version
npm --version
```

From the extracted release directory:

```bash
npm ci
npm run build:circuit
npm test
npm run build:contract
npm run test:onchain
npm run build:ui
```

Expected security checks include:

```text
✓ tampered statement rejected
✓ sCrypt verifier accepted the Groth16 proof
✓ Bitcoin Script accepted the unshield proof
✓ Bitcoin Script rejected a tampered proof
```

After `npm run build:ui`, deploy the regenerated `dist-ui/` directory using
Option A. The circuit build creates a single-contributor development setup and
must not be treated as a production trusted ceremony.

## Updating an existing installation

Verify the new release first, then replace the static files:

```bash
cd veil-bsv-server-0.2.1
sha256sum -c MANIFEST.sha256
sudo cp -R dist-ui/. /var/www/veil/
sudo nginx -t
sudo systemctl reload nginx
```

The site has no database, backend process, secrets, or environment variables.
Rollback consists of restoring the previous `dist-ui/` directory.

## Operational notes

- Serve the files over HTTPS so proof assets cannot be altered in transit.
- Do not add private keys, wallet seeds, or server secrets to this directory.
- The browser stores demo wallet state locally; clearing browser storage resets
  it.
- Read `SECURITY.md` before modifying the protocol or attempting a real-funds
  deployment.
- A production release requires an independent audit, a secure multi-party
  setup or transparent proving system, encrypted note delivery, and miner
  policy/fee confirmation for the large covenant.
