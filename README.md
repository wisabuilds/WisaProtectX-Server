# WisaProtectX-Server

Keybox distribution and automated sync backend for WisaProtectX.

## Endpoints

Served via raw HTTPS:

- `/key`: Base64-encoded active hardware attestation keybox (`keybox.xml`)
- `/status`: Health check string (`🟢🟢🟢`)
- `/meta.json`: Active key payload identifier

## Automation

A GitHub Actions workflow (`.github/workflows/auto_harvest.yml`) runs on a 6-hour cron:

1. Runs `harvester.py` to check upstream channels and mirrors for new hardware keyboxes.
2. Validates XML structure, certificate chains, and repairs corrupted algorithm tags.
3. Automatically commits and pushes changes when an update is found.

To trigger a sync manually, dispatch the workflow from the Actions tab or run:

```bash
python3 harvester.py
```
