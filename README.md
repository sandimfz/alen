# Recon Automation

Automated bug bounty recon pipeline.

**Pipeline:** subfinder → alterx → shuffledns → dnsx → naabu → httpx → katana → waybackurls → gau

## Requirements

Python 3.10+ and the following Go tools:

```bash
# Install via PDTM (recommended)
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
pdtm -ia -igp

# Or individually
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
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
python3 main.py -d target.com --tools-check-only
```

## Flags

| Flag | Description |
|------|-------------|
| `-d`, `--domain` | Target domain (required) |
| `--cookie` | Session cookie for Katana authenticated crawl |
| `--resolvers` | Path to custom resolvers.txt |
| `--skip-alterx` | Skip alterx mutation step |
| `--skip-ports` | Skip naabu port scanning |
| `--skip-crawl` | Skip katana crawling |
| `--skip-passive` | Skip waybackurls and gau |
| `--tools-check-only` | Only verify tools, do not run recon |

## Output

Results are saved to `recon/recon_<domain>_<timestamp>/`:

```
recon/recon_target.com_20260517_xxxxxx/
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
└── SUMMARY.json
```

## Running Tests

```bash
pytest tests/
```
