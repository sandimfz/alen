"""
utils.py - Helper functions for the recon pipeline.
"""

import logging
import os
import shutil
import subprocess
from pathlib import Path
from datetime import datetime

log = logging.getLogger("recon")


def run(cmd: list[str], output_file: str | None = None, timeout: int | None = None) -> bool:
    """Run a shell command, optionally writing stdout to a file."""
    cmd_str = " ".join(cmd)
    log.info(f">> {cmd_str}")
    try:
        if output_file:
            with open(output_file, "w") as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True, timeout=timeout)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        if result.returncode != 0:
            stderr = result.stderr.strip() if result.stderr else ""
            log.warning(f"   Exit code {result.returncode}" + (f": {stderr[:200]}" if stderr else ""))
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        log.error(f"   Timeout after {timeout}s: {cmd[0]}")
        return False
    except FileNotFoundError:
        log.error(f"   Tool not found: {cmd[0]}")
        return False
    except Exception as e:
        log.error(f"   Error: {e}")
        return False


def count_lines(filepath: str) -> int:
    """Count non-empty lines in a file."""
    try:
        with open(filepath) as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


def check_tools(tools: list[str]) -> bool:
    """Verify all required tools are available in PATH."""
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
    """Look for a file in the src/ directory or its parent (project root)."""
    for base in [Path(__file__).parent, Path(__file__).parent.parent]:
        candidate = base / filename
        if candidate.exists() and candidate.stat().st_size > 0:
            return str(candidate)
    return None


def setup_output_dir(domain: str) -> str:
    """Create a timestamped output directory with subdirectories under <project_root>/recon/."""
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = Path(__file__).parent.parent / "recon" / f"recon_{domain}_{ts}"

    for subdir in ["subdomains", "dns", "ports", "http", "crawl", "passive", "js"]:
        (base / subdir).mkdir(parents=True, exist_ok=True)

    log.info(f"Output directory: {base}/")
    return str(base)


def banner():
    print(r"""
   _____  .__                 
  /  _  \ |  |   ____   ____  
 /  /_\  \|  | _/ __ \ /    \ 
/    |    \  |_\  ___/|   |  \
\____|__  /____/\___  >___|  /
        \/          \/     \/ 

  Recon  |  github: @sandimfz
""")
