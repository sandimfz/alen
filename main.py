#!/usr/bin/env python3
"""
main.py - Entry point for the recon automation pipeline.

Pipeline: subfinder -> alterx -> shuffledns -> dnsx -> naabu -> httpx -> katana -> waybackurls -> gau

Usage:
    python3 main.py -d target.com
    python3 main.py -d target.com --cookie "session=abc123" --skip-ports
"""

import argparse
import logging
import sys

from src.utils import banner, check_tools, find_local_file, setup_output_dir
from src.steps import (
    step_subfinder,
    step_alterx,
    step_shuffledns,
    step_dnsx,
    step_naabu,
    step_httpx,
    step_katana,
    step_waybackurls,
    step_gau,
)
from src.report import generate_summary

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("recon")


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Automated Bug Bounty Recon Pipeline",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-d", "--domain",         required=True,       help="Target domain (e.g. example.com)")
    parser.add_argument("--cookie",               default=None,        help="Session cookie for authenticated crawling in Katana")
    parser.add_argument("--resolvers",            default=None,        help="Path to custom resolvers.txt (default: resolvers.txt in project root)")
    parser.add_argument("--skip-alterx",          action="store_true", help="Skip the alterx mutation step")
    parser.add_argument("--skip-ports",           action="store_true", help="Skip the naabu port scanning step")
    parser.add_argument("--skip-crawl",           action="store_true", help="Skip the katana crawling step")
    parser.add_argument("--skip-passive",         action="store_true", help="Skip waybackurls and gau passive URL collection")
    parser.add_argument("--tools-check-only",     action="store_true", help="Only check tools availability, do not run recon")
    args = parser.parse_args()

    domain = args.domain.strip().lower().removeprefix("http://").removeprefix("https://").rstrip("/")

    # -- Tool check --
    tools_needed = ["subfinder", "dnsx", "httpx"]
    if not args.skip_alterx:  tools_needed += ["alterx", "shuffledns"]
    if not args.skip_ports:   tools_needed.append("naabu")
    if not args.skip_crawl:   tools_needed.append("katana")
    if not args.skip_passive: tools_needed += ["waybackurls", "gau"]

    if not check_tools(tools_needed):
        sys.exit(1)

    if args.tools_check_only:
        log.info("Tools check complete. Exiting.")
        sys.exit(0)

    # -- Setup --
    out_dir = setup_output_dir(domain)

    # -- Resolvers --
    resolvers_file = args.resolvers
    if not resolvers_file:
        resolvers_file = find_local_file("resolvers.txt")
        if resolvers_file:
            log.info(f"Using local resolvers: {resolvers_file}")
        else:
            log.error("resolvers.txt not found in project root!")
            log.error("Place resolvers.txt in the project root folder,")
            log.error("or use: --resolvers /path/to/resolvers.txt")
            sys.exit(1)

    # -- Pipeline --
    files = {}

    files["01_subdomains"]  = step_subfinder(domain, out_dir)

    if not args.skip_alterx:
        files["02_mutations"]  = step_alterx(files["01_subdomains"], out_dir)
        files["03_shuffledns"] = step_shuffledns(files["02_mutations"], resolvers_file, out_dir)
        dns_input              = files["03_shuffledns"]
    else:
        log.info("\n[SKIP] alterx & shuffledns")
        dns_input              = files["01_subdomains"]

    files["04_alive_domains"] = step_dnsx(dns_input, out_dir)

    if not args.skip_ports:
        files["05_open_ports"] = step_naabu(files["04_alive_domains"], out_dir)
        httpx_input            = files["05_open_ports"]
    else:
        log.info("\n[SKIP] naabu port scanning")
        httpx_input            = files["04_alive_domains"]

    files["06_httpx"]      = step_httpx(httpx_input, out_dir)
    files["06_httpx_live"] = files["06_httpx"].replace("httpx_results.txt", "httpx_live.txt")

    if not args.skip_crawl:
        files["07_katana"] = step_katana(files["06_httpx"], out_dir, cookie=args.cookie)
    else:
        log.info("\n[SKIP] katana crawling")

    if not args.skip_passive:
        files["08_waybackurls"] = step_waybackurls(domain, out_dir)
        files["09_gau"]         = step_gau(domain, out_dir)
    else:
        log.info("\n[SKIP] waybackurls & gau")

    # -- Summary --
    generate_summary(domain, out_dir, files)
    log.info("Recon complete! Happy hacking")


if __name__ == "__main__":
    main()
