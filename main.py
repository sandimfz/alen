#!/usr/bin/env python3
"""
Recon Automation Script
Pipeline: subfinder → alterx → shuffledns → dnsx → naabu → httpx → katana
Modern bug bounty recon workflow.

Usage:
    python3 recon_automation.py -d target.com
    python3 recon_automation.py -d target.com --cookie "session=abc123" --skip-ports
"""

import argparse
import subprocess
import os
import sys
import shutil
import json
import logging
from datetime import datetime
from pathlib import Path

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────
REQUIRED_TOOLS = ["subfinder", "alterx", "shuffledns", "dnsx", "naabu", "httpx", "katana"]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("recon")


# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────
def banner():
    print(r"""

       _____  .__                 
  /  _  \ |  |   ____   ____  
 /  /_\  \|  | _/ __ \ /    \ 
/    |    \  |_\  ___/|   |  \
\____|__  /____/\___  >___|  /
        \/          \/     \/ 
                                                        
  Recon  |  github: @sndimf
""")


def run(cmd: list[str], output_file: str | None = None) -> bool:
    """Run a shell command, optionally writing stdout to a file."""
    cmd_str = " ".join(cmd)
    log.info(f">> {cmd_str}")
    try:
        if output_file:
            with open(output_file, "w") as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            stderr = result.stderr.strip() if result.stderr else ""
            log.warning(f"   Exit code {result.returncode}" + (f": {stderr[:200]}" if stderr else ""))
        return result.returncode == 0
    except FileNotFoundError:
        log.error(f"   Tool not found: {cmd[0]}")
        return False
    except Exception as e:
        log.error(f"   Error: {e}")
        return False


def count_lines(filepath: str) -> int:
    try:
        with open(filepath) as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


def check_tools(tools: list[str]) -> bool:
    missing = [t for t in tools if not shutil.which(t)]
    if missing:
        log.error("The following tools were not found in PATH:")
        for t in missing:
            log.error(f"   [x] {t}")
        log.error("\nInstall via PDTM:")
        log.error("   go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest")
        log.error("   pdtm -ia -igp")
        log.error("\nMake sure Go bin is exported:")
        log.error("   echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc")
        return False
    log.info(f"[+] All tools available: {', '.join(tools)}")
    return True


def find_local_file(filename: str) -> str | None:
    """Look for a file in the same directory as this script."""
    script_dir = Path(__file__).parent.resolve()
    candidate  = script_dir / filename
    if candidate.exists() and candidate.stat().st_size > 0:
        return str(candidate)
    return None


def setup_output_dir(domain: str) -> str:
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    base    = Path(__file__).parent.resolve() / "recon" / f"{domain}_{ts}"
    base.mkdir(parents=True, exist_ok=True)
    log.info(f"Output directory: {base}/")
    return str(base)


# ──────────────────────────────────────────────
# RECON STEPS
# ──────────────────────────────────────────────
def step_subfinder(domain: str, out_dir: str) -> str:
    log.info("\n--- [1/7] SUBFINDER - Subdomain Enumeration ---")
    output = f"{out_dir}/01_subdomains.txt"
    run(["subfinder", "-d", domain, "-all", "-silent", "-o", output])
    n = count_lines(output)
    log.info(f"   [+] Found {n} subdomains -> {output}")
    return output


def step_alterx(subdomains_file: str, out_dir: str) -> str:
    log.info("\n--- [2/7] ALTERX - Permutation & Mutation ---")
    output = f"{out_dir}/02_alterx_mutations.txt"
    with open(output, "w") as f:
        result = subprocess.run(
            ["alterx", "-silent"],
            stdin=open(subdomains_file),
            stdout=f,
            stderr=subprocess.PIPE,
            text=True,
        )
    n = count_lines(output)
    log.info(f"   [+] Generated {n} mutation candidates -> {output}")
    return output


def step_shuffledns(mutations_file: str, resolvers_file: str, out_dir: str) -> str:
    log.info("\n--- [3/7] SHUFFLEDNS - DNS Resolution ---")
    output = f"{out_dir}/03_shuffledns_resolved.txt"

    # Ensure resolver file exists and is not empty
    if not os.path.exists(resolvers_file) or os.path.getsize(resolvers_file) == 0:
        log.warning("   Resolver file is empty or missing, writing fallback resolvers...")
        with open(resolvers_file, "w") as f:
            f.write(FALLBACK_RESOLVERS + "\n")

    # Touch output file so next steps don't crash if shuffledns produces nothing
    Path(output).touch()

    ok = run(
        ["shuffledns", "-list", mutations_file, "-r", resolvers_file,
         "-silent", "-o", output],
    )

    n = count_lines(output)
    if not ok or n == 0:
        log.warning("   shuffledns found no results. Falling back to original subdomains.")
        # Copy original subdomains so the pipeline can continue
        subdomains_file = mutations_file.replace("02_alterx_mutations", "01_subdomains")
        if os.path.exists(subdomains_file) and count_lines(subdomains_file) > 0:
            import shutil as _sh
            _sh.copy(subdomains_file, output)
            n = count_lines(output)
            log.info(f"   [+] Fallback: using {n} subdomains from step 1 -> {output}")
        else:
            log.error("   [x] No data available to continue to the next step.")
    else:
        log.info(f"   [+] {n} domains resolved -> {output}")
    return output


def step_dnsx(resolved_file: str, out_dir: str) -> str:
    log.info("\n--- [4/7] DNSX - Active DNS Verification ---")
    output = f"{out_dir}/04_alive_domains.txt"

    if not os.path.exists(resolved_file) or count_lines(resolved_file) == 0:
        log.warning(f"   Input file is empty or missing: {resolved_file}")
        Path(output).touch()
        return output

    with open(output, "w") as f:
        subprocess.run(
            ["dnsx", "-silent"],
            stdin=open(resolved_file),
            stdout=f,
            stderr=subprocess.PIPE,
            text=True,
        )
    n = count_lines(output)
    log.info(f"   [+] {n} live domains (valid DNS) -> {output}")
    return output


def step_naabu(alive_file: str, out_dir: str) -> str:
    log.info("\n--- [5/7] NAABU - Port Scanning ---")
    output = f"{out_dir}/05_open_ports.txt"

    if not os.path.exists(alive_file) or count_lines(alive_file) == 0:
        log.warning(f"   Input file is empty or missing: {alive_file}")
        Path(output).touch()
        return output

    with open(output, "w") as f:
        subprocess.run(
            ["naabu", "-silent", "-top-ports", "1000"],
            stdin=open(alive_file),
            stdout=f,
            stderr=subprocess.PIPE,
            text=True,
        )
    n = count_lines(output)
    log.info(f"   [+] {n} open ports found -> {output}")
    return output


def step_httpx(ports_file: str, out_dir: str) -> str:
    log.info("\n--- [6/7] HTTPX - Web Service Analysis ---")
    output      = f"{out_dir}/06_httpx_results.txt"
    output_json = f"{out_dir}/06_httpx_results.json"
    output_live = f"{out_dir}/06_httpx_live.txt"

    if not os.path.exists(ports_file) or count_lines(ports_file) == 0:
        log.warning(f"   Input file is empty or missing: {ports_file}")
        Path(output).touch()
        Path(output_json).touch()
        Path(output_live).touch()
        return output

    with open(output, "w") as f:
        subprocess.run(
            ["httpx", "-silent", "-title", "-sc", "-td", "-ip"],
            stdin=open(ports_file),
            stdout=f,
            stderr=subprocess.PIPE,
            text=True,
        )
    with open(output_json, "w") as f:
        subprocess.run(
            ["httpx", "-silent", "-title", "-sc", "-td", "-ip", "-json"],
            stdin=open(ports_file),
            stdout=f,
            stderr=subprocess.PIPE,
            text=True,
        )

    # Extract only live URLs (2xx/3xx) from results into a clean URL-only file
    with open(output_live, "w") as f:
        subprocess.run(
            ["httpx", "-silent", "-mc", "200,201,204,301,302,303,307,308,403"],
            stdin=open(ports_file),
            stdout=f,
            stderr=subprocess.PIPE,
            text=True,
        )

    n      = count_lines(output)
    n_live = count_lines(output_live)
    log.info(f"   [+] {n} active web services -> {output}")
    log.info(f"   [+] {n_live} live URLs (2xx/3xx/403) -> {output_live}")
    return output


def step_katana(httpx_file: str, out_dir: str, cookie: str | None = None) -> str:
    log.info("\n--- [7/7] KATANA - Deep Crawling ---")
    output = f"{out_dir}/07_katana_endpoints.txt"

    # Extract URLs from httpx output (first column)
    urls = []
    try:
        with open(httpx_file) as f:
            for line in f:
                parts = line.strip().split()
                if parts and parts[0].startswith("http"):
                    urls.append(parts[0])
    except Exception:
        pass

    if not urls:
        log.warning("   No URLs to crawl.")
        return output

    # Write URL list for katana
    url_list = f"{out_dir}/httpx_urls.txt"
    with open(url_list, "w") as f:
        f.write("\n".join(urls))

    cmd = ["katana", "-list", url_list, "-jc", "-jsl", "-silent", "-o", output]
    if cookie:
        cmd += ["-H", f"Cookie: {cookie}"]

    run(cmd)
    n = count_lines(output)
    log.info(f"   ✓ {n} endpoints/URLs discovered → {output}")
    return output


# ──────────────────────────────────────────────
# SUMMARY REPORT
# ──────────────────────────────────────────────
def generate_summary(domain: str, out_dir: str, files: dict):
    log.info("\n━━━ GENERATING SUMMARY REPORT ━━━")
    summary = {
        "domain"    : domain,
        "timestamp" : datetime.now().isoformat(),
        "output_dir": out_dir,
        "results"   : {},
    }
    for step, filepath in files.items():
        if filepath and os.path.exists(filepath):
            summary["results"][step] = {
                "file" : filepath,
                "count": count_lines(filepath),
            }

    summary_file = f"{out_dir}/SUMMARY.json"
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)

    # Print summary to terminal
    print("\n" + "═" * 55)
    print(f"  RECON SUMMARY — {domain}")
    print("═" * 55)
    for step, data in summary["results"].items():
        print(f"  {step:<30} {data['count']:>6} items")
    print("═" * 55)
    print(f"  Output dir : {out_dir}/")
    print(f"  Summary    : {summary_file}")
    print("═" * 55 + "\n")

    return summary_file


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Automated Bug Bounty Recon Pipeline",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-d", "--domain",      required=True,  help="Target domain (e.g. example.com)")
    parser.add_argument("--cookie",            default=None,   help="Session cookie for authenticated crawling in Katana")
    parser.add_argument("--resolvers",         default=None,   help="Path to custom resolvers.txt (default: resolvers.txt in script folder)")
    parser.add_argument("--skip-alterx",       action="store_true", help="Skip the alterx mutation step")
    parser.add_argument("--skip-ports",        action="store_true", help="Skip the naabu port scanning step")
    parser.add_argument("--skip-crawl",        action="store_true", help="Skip the katana crawling step")
    parser.add_argument("--tools-check-only",  action="store_true", help="Only check tools availability, do not run recon")
    args = parser.parse_args()

    domain = args.domain.strip().lower().removeprefix("http://").removeprefix("https://").rstrip("/")

    # ── Cek tools ──
    tools_needed = ["subfinder", "dnsx", "httpx"]
    if not args.skip_alterx:   tools_needed += ["alterx", "shuffledns"]
    if not args.skip_ports:    tools_needed.append("naabu")
    if not args.skip_crawl:    tools_needed.append("katana")

    if not check_tools(tools_needed):
        sys.exit(1)

    if args.tools_check_only:
        log.info("Tools check complete. Exiting.")
        sys.exit(0)

    # ── Setup ──
    out_dir = setup_output_dir(domain)

    # ── Resolvers: use argument, or find local file, or error ──
    resolvers_file = args.resolvers
    if not resolvers_file:
        resolvers_file = find_local_file("resolvers.txt")
        if resolvers_file:
            log.info(f"Using local resolvers: {resolvers_file}")
        else:
            log.error("resolvers.txt not found in script folder!")
            log.error("Place resolvers.txt in the same folder as main.py,")
            log.error("or use: --resolvers /path/to/resolvers.txt")
            sys.exit(1)

    # ── Pipeline ──
    files = {}

    files["01_subdomains"]      = step_subfinder(domain, out_dir)

    if not args.skip_alterx:
        files["02_mutations"]   = step_alterx(files["01_subdomains"], out_dir)
        files["03_shuffledns"]  = step_shuffledns(files["02_mutations"], resolvers_file, out_dir)
        dns_input               = files["03_shuffledns"]
    else:
        log.info("\n[SKIP] alterx & shuffledns")
        dns_input               = files["01_subdomains"]

    files["04_alive_domains"]   = step_dnsx(dns_input, out_dir)

    if not args.skip_ports:
        files["05_open_ports"]  = step_naabu(files["04_alive_domains"], out_dir)
        httpx_input             = files["05_open_ports"]
    else:
        log.info("\n[SKIP] naabu port scanning")
        httpx_input             = files["04_alive_domains"]

    files["06_httpx"]           = step_httpx(httpx_input, out_dir)
    files["06_httpx_live"]      = files["06_httpx"].replace("06_httpx_results.txt", "06_httpx_live.txt")

    if not args.skip_crawl:
        files["07_katana"]      = step_katana(files["06_httpx"], out_dir, cookie=args.cookie)
    else:
        log.info("\n[SKIP] katana crawling")

    # ── Summary ──
    generate_summary(domain, out_dir, files)
    log.info("Recon complete! Happy hacking")


if __name__ == "__main__":
    main()