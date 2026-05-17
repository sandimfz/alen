"""
notify.py - Telegram notification after recon completes.
"""

import logging
import os
import urllib.request
import urllib.parse
import json

log = logging.getLogger("recon")

TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"


def _load_config() -> tuple[str | None, str | None]:
    """Load TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID from environment or .env file."""
    env_file = os.path.join(os.path.dirname(__file__), "..", ".env")
    if os.path.exists(env_file):
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    os.environ.setdefault(key.strip(), value.strip())

    token   = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    return token, chat_id


def send_telegram(domain: str, out_dir: str, summary: dict) -> bool:
    """
    Send a Telegram notification with the recon summary.
    Called only after all steps and SUMMARY.json are complete.
    Returns True if message was sent successfully.
    """
    token, chat_id = _load_config()

    if not token or not chat_id:
        log.warning("Telegram notification skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set.")
        log.warning("Add them to .env or export as environment variables.")
        return False

    # Build message
    lines = [
        f"*Recon Complete*",
        f"Domain: `{domain}`",
        f"",
        f"*Results:*",
    ]
    for step, data in summary.get("results", {}).items():
        lines.append(f"  `{step}`: {data['count']} items")

    lines += [
        f"",
        f"Output: `{out_dir}`",
        f"Timestamp: {summary.get('timestamp', '-')}",
    ]

    message = "\n".join(lines)

    url  = TELEGRAM_API.format(token=token)
    data = urllib.parse.urlencode({
        "chat_id"    : chat_id,
        "text"       : message,
        "parse_mode" : "Markdown",
    }).encode()

    try:
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
            if body.get("ok"):
                log.info("[+] Telegram notification sent.")
                return True
            else:
                log.warning(f"Telegram API error: {body}")
                return False
    except Exception as e:
        log.warning(f"Failed to send Telegram notification: {e}")
        return False
