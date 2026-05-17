# Recon Automation

Automated bug bounty recon pipeline.

**Pipeline:** subfinder → alterx → shuffledns → dnsx → naabu → httpx → katana → waybackurls → gau → jshunter

## Requirements

Python 3.10+ and the following Go tools:

```bash
# Install via PDTM (recommended)
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
pdtm -ia -igp

# Or individually
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/cc1a2b/jshunter/cmd/jshunter@latest
```

Make sure Go bin is in your PATH:
```bash
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc
```

## Setup

```bash
git clone https://github.com/sandimfz/alen
cd alen
pip install -r requirements.txt
```

Place your `resolvers.txt` in the project root, or pass it via `--resolvers`.

## Usage

```bash
python3 main.py -d target.com
python3 main.py -d target.com --cookie "session=abc123"
python3 main.py -d target.com --skip-ports --skip-crawl
python3 main.py -d target.com --proxy 127.0.0.1:8080
python3 main.py -d target.com --skip-js
python3 main.py -d target.com --tools-check-only
```

## Flags

| Flag | Description |
|------|-------------|
| `-d`, `--domain` | Target domain (required) |
| `--cookie` | Session cookie for Katana authenticated crawl |
| `--proxy` | HTTP/SOCKS5 proxy for JSHunter (e.g., `127.0.0.1:8080`) |
| `--resolvers` | Path to custom resolvers.txt |
| `--skip-alterx` | Skip alterx mutation step |
| `--skip-ports` | Skip naabu port scanning |
| `--skip-crawl` | Skip katana crawling |
| `--skip-passive` | Skip waybackurls and gau |
| `--skip-js` | Skip JSHunter JavaScript analysis |
| `--skip-tls` | Skip TLS certificate verification in JSHunter |
| `--tools-check-only` | Only verify tools, do not run recon |

## Output

Results are saved to `recon/recon_<domain>_<timestamp>/`:

```
recon/recon_example.com_20260517_xxxxxx/
├── subdomains/
│   ├── subdomains.txt
│   ├── alterx_mutations.txt
│   └── shuffledns_resolved.txt
├── dns/
│   └── alive_domains.txt
├── ports/
│   └── open_ports.txt
├── http/
│   ├── httpx_results.txt
│   ├── httpx_results.json
│   └── httpx_live.txt
├── crawl/
│   ├── katana_endpoints.txt
│   └── httpx_urls.txt
├── passive/
│   ├── waybackurls.txt
│   └── gau_urls.txt
├── js/
│   ├── js_urls.txt
│   └── jshunter_results.json
└── SUMMARY.json
```

## Running Tests

```bash
pytest tests/
```

## Telegram Notification

After recon completes, a summary is automatically sent to Telegram.

**Setup:**
```bash
cp .env.example .env
```

Edit `.env` and fill in your credentials:
```
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here
```

- Get your bot token from [@BotFather](https://t.me/BotFather)
- Get your chat ID by messaging [@userinfobot](https://t.me/userinfobot)

If `.env` is not configured, the notification is silently skipped and recon still completes normally.
