#!/bin/bash
# APK QA Tool — Setup Script
set -e

echo "=== Installing Python packages ==="
# Note: --ignore-installed blinker handles a Debian/Ubuntu package conflict
pip install anthropic flask requests streamlit --break-system-packages --ignore-installed blinker

echo "=== Installing system tools ==="
apt-get install -y apktool aapt 2>/dev/null || echo "Warning: apt-get failed (may need sudo or tools may already be installed)"

echo "=== Setup complete ==="
echo "Usage: ANTHROPIC_API_KEY=sk-... python3 apk_qa_agent.py /path/to/app.apk"
echo "Web UI: ANTHROPIC_API_KEY=sk-... python3 web/server.py"
