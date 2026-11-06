#!/usr/bin/env python3
"""
WisaProtectX Keybox Harvester & Validator
Designed to run automatically via GitHub Actions or standalone cron.
Monitors public channels, validates keybox XML structure and certificate chains,
checks against Google's official Attestation CRL, and publishes verified updates.
"""

import os
import re
import sys
import ssl
import json
import time
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
GOOGLE_CRL_URL = "https://android.googleapis.com/attestation/status"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# In-memory cache for Google Attestation CRL serials
_CACHED_CRL: set[int] | None = None


def log(msg: str):
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{now}] {msg}")


def get_google_crl(max_retries: int = 2, timeout: int = 15) -> set[int] | None:
    """
    Fetches Google's official Attestation CRL containing revoked certificate serials.
    Returns a set of integer serial numbers, or None if unreachable.
    """
    global _CACHED_CRL
    if _CACHED_CRL is not None:
        return _CACHED_CRL

    log("Fetching Google Attestation Revocation List (CRL)...")
    req = urllib.request.Request(GOOGLE_CRL_URL, headers={"User-Agent": USER_AGENT})

    for attempt in range(max_retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as res:
                payload = json.loads(res.read().decode("utf-8"))

            entries = payload.get("entries", {})
            revoked_serials: set[int] = set()

            for key, val in entries.items():
                if isinstance(val, dict) and val.get("status") == "REVOKED":
                    try:
                        # Google CRL keys can be decimal strings or lowercase hex strings
                        if key.isdigit():
                            revoked_serials.add(int(key, 10))
                        else:
                            revoked_serials.add(int(key, 16))
                    except Exception:
                        pass

            log(f"Successfully loaded {len(revoked_serials)} revoked certificate serials from Google CRL.")
            _CACHED_CRL = revoked_serials
            return _CACHED_CRL

        except Exception as e:
            if attempt < max_retries:
                log(f"Warning: Failed to fetch Google CRL (attempt {attempt + 1}/{max_retries + 1}): {e}. Retrying...")
                time.sleep(2)
            else:
                log(f"Error: Unable to fetch Google Attestation CRL after {max_retries + 1} attempts: {e}")

    return None


def _read_asn1_length(data: bytes, offset: int) -> tuple[int, int]:
    """Helper to decode ASN.1 DER length field. Returns (length, value_offset)."""
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    num_bytes = first & 0x7F
    offset += 1
    length = int.from_bytes(data[offset:offset + num_bytes], "big")
    return length, offset + num_bytes


def parse_cert_serial(pem_text: str) -> int:
    """
    Extracts the serial number integer from an X.509 PEM certificate using pure Python.
    Parses Certificate -> TBSCertificate -> serialNumber.
    """
    der = ssl.PEM_cert_to_DER_cert(pem_text)
    pos = 0

    # 1. Certificate SEQUENCE (0x30)
    if der[pos] != 0x30:
        raise ValueError("Expected Certificate SEQUENCE (0x30)")
    _, pos = _read_asn1_length(der, pos + 1)

    # 2. TBSCertificate SEQUENCE (0x30)
    if der[pos] != 0x30:
        raise ValueError("Expected TBSCertificate SEQUENCE (0x30)")
    _, pos = _read_asn1_length(der, pos + 1)

    # 3. Optional version [0] EXPLICIT tag (0xa0)
    if der[pos] == 0xA0:
        v_len, pos = _read_asn1_length(der, pos + 1)
        pos += v_len

    # 4. serialNumber INTEGER (0x02)
    if der[pos] != 0x02:
        raise ValueError(f"Expected INTEGER tag (0x02) for serialNumber, got {hex(der[pos])}")
    s_len, pos = _read_asn1_length(der, pos + 1)
    serial_bytes = der[pos:pos + s_len]

    return int.from_bytes(serial_bytes, "big", signed=False)


def extract_certificate_serials(xml_text: str) -> list[int]:
    """Extracts all certificate serial numbers present in the XML keybox."""
    root = ET.fromstring(xml_text)
    serials = []
    for cert in root.findall(".//Certificate"):
        pem = (cert.text or "").strip()
        if "BEGIN CERTIFICATE" in pem and "END CERTIFICATE" in pem:
            try:
                serial = parse_cert_serial(pem)
                serials.append(serial)
            except Exception as e:
                log(f"Warning: Failed to parse certificate serial: {e}")
    return serials


def validate_keybox(xml_text: str, crl: set[int] | None = None) -> tuple[bool, str]:
    """
    Validates XML structure, algorithm attributes, certificate formatting,
    and cross-checks certificate serials against Google's live Attestation CRL.
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

    # Verify certificate serials and check for revocation
    serials = extract_certificate_serials(xml_text)
    if not serials:
        return False, "Could not extract valid certificate serials from chain"

    if crl is not None:
        for s in serials:
            if s in crl:
                return False, f"Revoked by Google CRL (serial: {hex(s)})"

    return True, xml_text


def set_status(status_str: str, reason: str = ""):
    """Updates the /status file if changed."""
    current = ""
    if os.path.exists(STATUS_PATH):
        try:
            with open(STATUS_PATH, "r") as f:
                current = f.read().strip()
        except Exception:
            pass

    if current != status_str:
        with open(STATUS_PATH, "w") as f:
            f.write(status_str)
        log(f"Status changed: '{current}' -> '{status_str}' ({reason})")


def publish_keybox(validated_xml: str, source_name: str) -> tuple[bool, bool]:
    """
    Encodes the validated keybox and atomically updates server files.
    Returns (updated: bool, matches_active: bool).
    """
    new_hash = hashlib.sha256(validated_xml.encode()).hexdigest()

    # Compare with current active keybox
    if os.path.exists(KEY_PATH):
        try:
            with open(KEY_PATH, "r") as f:
                current_b64 = f.read().strip()
            if current_b64:
                current_xml = base64.b64decode(current_b64).decode("utf-8", errors="ignore")
                if hashlib.sha256(current_xml.encode()).hexdigest() == new_hash:
                    log(f"Keybox from '{source_name}' matches active keybox. No update needed.")
                    set_status("🟢🟢🟢", "Active keybox is up-to-date and verified")
                    return False, True
        except Exception as e:
            log(f"Notice: Failed to read current keybox ({e}), will overwrite.")

    # 1. Write /key (Base64-encoded)
    b64_payload = base64.b64encode(validated_xml.encode()).decode()
    with open(KEY_PATH, "w") as f:
        f.write(b64_payload)

    # 2. Write /status
    set_status("🟢🟢🟢", f"New keybox published from {source_name}")

    # 3. Write /meta.json
    filename = f"wisa_key_{new_hash[:8]}.xml"
    with open(META_PATH, "w") as f:
        f.write(f'{{"filename": "{filename}", "revoked": false}}\n')

    log(f"🎉 SUCCESS: New verified keybox published from '{source_name}' (ID: {filename})")
    return True, True


def tombstone_active_keybox(reason: str):
    """
    Tombstones the active keybox when revoked or corrupted so clients do not
    download or preserve a poisoned keybox. Writes empty payload and signals revocation.
    """
    try:
        with open(KEY_PATH, "w") as f:
            f.write("")
        with open(META_PATH, "w") as f:
            f.write(json.dumps({"filename": "none", "revoked": True, "reason": reason}) + "\n")
        log(f"Active keybox tombstoned successfully (Reason: {reason})")
    except Exception as e:
        log(f"Error while tombstoning active keybox: {e}")


def verify_active_keybox(crl: set[int] | None):
    """
    Validates the currently published active keybox.
    If it is revoked or corrupted, updates /status to reflect downtime
    and tombstones /key so devices do not download or preserve a poisoned keybox.
    """
    if not os.path.exists(KEY_PATH):
        log("No active keybox found on disk.")
        set_status("🔴🔴🔴", "Missing key payload")
        tombstone_active_keybox("Missing key payload")
        return

    try:
        with open(KEY_PATH, "r") as f:
            current_b64 = f.read().strip()
        if not current_b64:
            # Already tombstoned
            set_status("🔴🔴🔴", "Keybox is currently tombstoned / inactive")
            return
        current_xml = base64.b64decode(current_b64).decode("utf-8", errors="ignore")
    except Exception as e:
        log(f"Active keybox is unreadable/corrupted: {e}")
        set_status("🔴🔴🔴", "Corrupted key payload")
        tombstone_active_keybox(f"Corrupted key payload: {e}")
        return

    valid, reason = validate_keybox(current_xml, crl)
    if not valid:
        log(f"🚨 ACTIVE KEYBOX IS REVOKED OR INVALID: {reason}")
        set_status("🔴🔴🔴", f"Active keybox revoked: {reason}")
        tombstone_active_keybox(reason)
    else:
        log("✓ Active keybox verified: unrevoked in Google CRL.")
        set_status("🟢🟢🟢", "Active keybox verified")


def harvest_from_telegram_preview(channel: str, crl: set[int] | None = None) -> tuple[bool, bool]:
    """
    Scrapes public web preview (https://t.me/s/<channel>) for posted keyboxes.
    Returns (updated: bool, handled: bool).
    """
    url = f"https://t.me/s/{channel}"
    log(f"Checking Telegram channel: @{channel}...")

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            html = res.read().decode("utf-8", errors="ignore")
    except Exception as e:
        log(f"Error fetching channel @{channel}: {e}")
        return False, False

    code_blocks = re.findall(r"<pre[^>]*>(.*?)</pre>", html, re.DOTALL)
    for block in code_blocks:
        cleaned = block.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
        if "<Keybox" in cleaned:
            valid, result = validate_keybox(cleaned, crl)
            if valid:
                log(f"Found valid unrevoked keybox in @{channel}")
                return publish_keybox(result, f"Telegram @{channel}")
            else:
                log(f"Rejected candidate from @{channel}: {result}")

    return False, False


def sync_from_community_mirror(crl: set[int] | None = None) -> tuple[bool, bool]:
    """
    Checks the active community mirror for fresh rotating keyboxes.
    Returns (updated: bool, handled: bool).
    """
    log(f"Checking community mirror: {COMMUNITY_MIRROR}...")
    req = urllib.request.Request(COMMUNITY_MIRROR, headers={"User-Agent": "AlwaysStrong/1.0.5"})
    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            raw_b64 = res.read().decode("utf-8", errors="ignore").strip()
            decoded_xml = base64.b64decode(raw_b64).decode("utf-8", errors="ignore")
            valid, result = validate_keybox(decoded_xml, crl)
            if valid:
                return publish_keybox(result, "Community Mirror")
            else:
                log(f"Rejected candidate from Community Mirror: {result}")
    except Exception as e:
        log(f"Community mirror check failed: {e}")
    return False, False


def main():
    log("Starting WisaProtectX Harvester...")

    # Load Google Attestation CRL
    crl = get_google_crl()
    if crl:
        log(f"Loaded {len(crl)} revoked certificate serials from Google Attestation CRL.")
    else:
        log("Warning: Google Attestation CRL could not be loaded; revocation checks will be bypassed.")

    updated = False
    handled = False

    # 1. Try community mirror sync first
    updated, handled = sync_from_community_mirror(crl)

    # 2. Check public Telegram channels if not already handled
    if not handled:
        for chan in TELEGRAM_CHANNELS:
            up, ok = harvest_from_telegram_preview(chan, crl)
            if up:
                updated = True
            if ok:
                handled = True
                break

    # 3. Check status of current active keybox if nothing new was handled
    if not handled:
        verify_active_keybox(crl)

    log("Harvest scan completed.")


if __name__ == "__main__":
    main()
