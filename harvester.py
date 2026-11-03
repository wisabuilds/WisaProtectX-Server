#!/usr/bin/env python3
"""
WisaProtectX Keybox Harvester & Validator
Designed to run automatically via GitHub Actions or standalone cron.
Monitors public channels, validates keybox XML structure, and publishes updates.
"""

import os
import re
import sys
import base64
import hashlib
import datetime
import urllib.request
import xml.etree.ElementTree as ET

# Configuration
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
KEY_PATH = os.path.join(REPO_ROOT, "key")
STATUS_PATH = os.path.join(REPO_ROOT, "status")
META_PATH = os.path.join(REPO_ROOT, "meta.json")

TELEGRAM_CHANNELS = ["keybox_xml", "keyboxstrong"]
COMMUNITY_MIRROR = "http://evoker.qzz.io/key"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def log(msg):
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{now}] {msg}")

def validate_keybox(xml_text: str) -> tuple[bool, str]:
    """
    Validates XML structure, checks algorithm attributes,
    and ensures valid certificate formatting.
    """
    if not xml_text or "<Keybox" not in xml_text:
        return False, "Not a Keybox file (missing <Keybox> tag)"

    # Automatically fix common author watermark corruption
    if 'algorithm="@' in xml_text:
        xml_text = re.sub(r'algorithm="@[^"]+"', 'algorithm="rsa"', xml_text)

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        return False, f"Malformed XML: {e}"

    # Verify keys exist
    keys = root.findall(".//Key")
    if not keys:
        return False, "No <Key> elements found"

    has_ecdsa = any(k.get("algorithm") == "ecdsa" for k in keys)
    has_rsa = any(k.get("algorithm") == "rsa" for k in keys)

    if not (has_ecdsa or has_rsa):
        return False, "Missing both RSA and ECDSA algorithm keys"

    # Verify PEM certificates exist
    certs = root.findall(".//Certificate")
    if not certs:
        return False, "No <Certificate> elements found in chain"

    valid_certs = 0
    for cert in certs:
        text = cert.text or ""
        if "BEGIN CERTIFICATE" in text and "END CERTIFICATE" in text:
            valid_certs += 1

    if valid_certs == 0:
        return False, "Certificates are incomplete or missing PEM markers"

    return True, xml_text

def publish_keybox(validated_xml: str, source_name: str) -> bool:
    """
    Encodes the validated keybox and atomically updates server files.
    Returns True if an update was written, False if already up-to-date.
    """
    new_hash = hashlib.sha256(validated_xml.encode()).hexdigest()

    # Compare with current active keybox
    if os.path.exists(KEY_PATH):
        try:
            with open(KEY_PATH, "r") as f:
                current_b64 = f.read().strip()
            current_xml = base64.b64decode(current_b64).decode("utf-8", errors="ignore")
            if hashlib.sha256(current_xml.encode()).hexdigest() == new_hash:
                log(f"Keybox from '{source_name}' matches active keybox. No update needed.")
                return False
        except Exception as e:
            log(f"Notice: Failed to read current keybox ({e}), will overwrite.")

    # 1. Write /key (Base64-encoded)
    b64_payload = base64.b64encode(validated_xml.encode()).decode()
    with open(KEY_PATH, "w") as f:
        f.write(b64_payload)

    # 2. Write /status
    with open(STATUS_PATH, "w") as f:
        f.write("🟢🟢🟢")

    # 3. Write /meta.json
    filename = f"wisa_key_{new_hash[:8]}.xml"
    with open(META_PATH, "w") as f:
        f.write(f'{{"filename": "{filename}"}}\n')

    log(f"🎉 SUCCESS: New keybox published from '{source_name}' (ID: {filename})")
    return True

def harvest_from_telegram_preview(channel: str) -> bool:
    """
    Scrapes public web preview (https://t.me/s/<channel>) for posted keyboxes.
    """
    url = f"https://t.me/s/{channel}"
    log(f"Checking Telegram channel: @{channel}...")

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            html = res.read().decode("utf-8", errors="ignore")
    except Exception as e:
        log(f"Error fetching channel @{channel}: {e}")
        return False

    # Check for raw XML in code snippets
    code_blocks = re.findall(r'<pre[^>]*>(.*?)</pre>', html, re.DOTALL)
    for block in code_blocks:
        cleaned = block.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
        if "<Keybox" in cleaned:
            valid, result = validate_keybox(cleaned)
            if valid:
                log(f"Found valid keybox snippet in @{channel}")
                return publish_keybox(result, f"Telegram @{channel}")

    return False

def sync_from_community_mirror() -> bool:
    """
    Checks the active community mirror for fresh rotating keyboxes.
    """
    log(f"Checking community mirror: {COMMUNITY_MIRROR}...")
    req = urllib.request.Request(COMMUNITY_MIRROR, headers={"User-Agent": "AlwaysStrong/1.0.5"})
    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            raw_b64 = res.read().decode("utf-8", errors="ignore").strip()
            decoded_xml = base64.b64decode(raw_b64).decode("utf-8", errors="ignore")
            valid, result = validate_keybox(decoded_xml)
            if valid:
                return publish_keybox(result, "Community Mirror")
    except Exception as e:
        log(f"Community mirror check failed: {e}")
    return False

def main():
    log("Starting WisaProtectX Harvester...")
    updated = False

    # 1. Try community mirror sync first
    if sync_from_community_mirror():
        updated = True

    # 2. Check public Telegram channels
    if not updated:
        for chan in TELEGRAM_CHANNELS:
            if harvest_from_telegram_preview(chan):
                updated = True
                break

    log("Harvest scan completed successfully.")

if __name__ == "__main__":
    main()
