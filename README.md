# 🛡️ WisaProtectX Keybox Server & Automated Harvester

This repository serves as the private, secure, and automated keybox distribution backend for the **[WisaProtectX](https://github.com/wisabuilds/WisaProtectX)** Play Integrity module.

---

## 📡 Live Endpoints

All endpoints are hosted via GitHub's Cloudflare-backed CDN over encrypted HTTPS:

| Endpoint | Path | Format | Description |
| :--- | :--- | :--- | :--- |
| **`/key`** | `https://raw.githubusercontent.com/wisabuilds/WisaProtectX-Server/main/key` | Plain Text (Base64) | Active hardware attestation keybox |
| **`/status`** | `https://raw.githubusercontent.com/wisabuilds/WisaProtectX-Server/main/status` | Plain Text | Real-time health indicator (`🟢🟢🟢`) |
| **`/meta.json`** | `https://raw.githubusercontent.com/wisabuilds/WisaProtectX-Server/main/meta.json` | JSON | Active key identifier for WebUI |

---

## 🤖 Automated Sync Workflow

* A GitHub Actions workflow (`.github/workflows/auto_harvest.yml`) runs **every 6 hours**.
* It validates keybox XML structures and PEM certificate chains.
* It automatically repairs syntax or watermark defects before publishing.
* When a newer keybox is found, it atomically commits and pushes updates to this repository.

---

## 🛠️ Manual Trigger

You can trigger a manual check anytime from the GitHub web UI:
1. Navigate to **Actions** -> **WisaProtectX Keybox Sync & Harvest**
2. Click **Run workflow** -> **Branch: main** -> **Run workflow**
