"""
steps.py - Individual recon pipeline step functions.
"""

import logging
import os
import subprocess
from pathlib import Path

from .utils import run, count_lines

log = logging.getLogger("recon")


def step_subfinder(domain: str, out_dir: str) -> str:
    log.info("\n--- [1/9] SUBFINDER - Subdomain Enumeration ---")
    output = f"{out_dir}/subdomains/subdomains.txt"
    run(["subfinder", "-d", domain, "-all", "-silent", "-o", output])
    n = count_lines(output)
    log.info(f"   [+] Found {n} subdomains -> {output}")
    return output


def step_alterx(subdomains_file: str, out_dir: str) -> str:
    log.info("\n--- [2/9] ALTERX - Permutation & Mutation ---")
    output = f"{out_dir}/subdomains/alterx_mutations.txt"
    with open(output, "w") as f:
        subprocess.run(
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
    log.info("\n--- [3/9] SHUFFLEDNS - DNS Resolution ---")
    output = f"{out_dir}/subdomains/shuffledns_resolved.txt"

    # Touch output file so next steps don't crash if shuffledns produces nothing
    Path(output).touch()

    ok = run(
        ["shuffledns", "-list", mutations_file, "-r", resolvers_file,
         "-mode", "resolve", "-silent", "-o", output],
    )

    n = count_lines(output)
    if not ok or n == 0:
        log.warning("   shuffledns found no results. Falling back to original subdomains.")
        subdomains_file = f"{out_dir}/subdomains/subdomains.txt"
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
    log.info("\n--- [4/9] DNSX - Active DNS Verification ---")
    output = f"{out_dir}/dns/alive_domains.txt"

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
    log.info("\n--- [5/9] NAABU - Port Scanning ---")
    output = f"{out_dir}/ports/open_ports.txt"

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
    log.info("\n--- [6/9] HTTPX - Web Service Analysis ---")
    output      = f"{out_dir}/http/httpx_results.txt"
    output_json = f"{out_dir}/http/httpx_results.json"
    output_live = f"{out_dir}/http/httpx_live.txt"

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
    log.info("\n--- [7/9] KATANA - Deep Crawling ---")
    output = f"{out_dir}/crawl/katana_endpoints.txt"

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

    url_list = f"{out_dir}/crawl/httpx_urls.txt"
    with open(url_list, "w") as f:
        f.write("\n".join(urls))

    cmd = ["katana", "-list", url_list, "-jc", "-jsl", "-silent", "-o", output]
    if cookie:
        cmd += ["-H", f"Cookie: {cookie}"]

    run(cmd)
    n = count_lines(output)
    log.info(f"   [+] {n} endpoints/URLs discovered -> {output}")
    return output


def step_waybackurls(domain: str, out_dir: str) -> str:
    log.info("\n--- [8/9] WAYBACKURLS - Wayback Machine URL Fetch ---")
    output = f"{out_dir}/passive/waybackurls.txt"

    with open(output, "w") as f:
        subprocess.run(
            ["waybackurls", domain],
            stdout=f,
            stderr=subprocess.PIPE,
            text=True,
        )

    n = count_lines(output)
    log.info(f"   [+] {n} URLs fetched from Wayback Machine -> {output}")
    return output


def step_gau(domain: str, out_dir: str) -> str:
    log.info("\n--- [9/9] GAU - Get All URLs (OTX, Wayback, CommonCrawl, URLScan) ---")
    output = f"{out_dir}/passive/gau_urls.txt"

    with open(output, "w") as f:
        subprocess.run(
            ["gau", "--subs", "--threads", "5", "--o", output, domain],
            stdout=f,
            stderr=subprocess.PIPE,
            text=True,
        )

    n = count_lines(output)
    log.info(f"   [+] {n} URLs fetched from all sources -> {output}")
    return output
