#!/usr/bin/env bash
# Launch the Homelab Control Panel (localhost only).
cd "$(dirname "$0")"
exec ../venv/bin/python app.py
