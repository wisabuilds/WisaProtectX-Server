# WisaProtectX-Server

Sync backend and asset host for WisaProtectX.

## Endpoints

- `/key`: Payload data
- `/status`: Health check
- `/meta.json`: Asset manifest

## Automation

Runs via GitHub Actions (`auto_harvest.yml`) on a scheduled workflow.

Run locally:

```bash
python3 harvester.py
```
