"""
report.py - Summary report generation.
"""

import json
import logging
import os
from datetime import datetime

from .utils import count_lines

log = logging.getLogger("recon")


def generate_summary(domain: str, out_dir: str, files: dict) -> str:
    log.info("\n--- GENERATING SUMMARY REPORT ---")
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

    print("\n" + "=" * 55)
    print(f"  RECON SUMMARY -- {domain}")
    print("=" * 55)
    for step, data in summary["results"].items():
        print(f"  {step:<30} {data['count']:>6} items")
    print("=" * 55)
    print(f"  Output dir : {out_dir}/")
    print(f"  Summary    : {summary_file}")
    print("=" * 55 + "\n")

    return summary_file
