#!/bin/bash
# ============================================================
# Honeypot Lab — One-Command Installer (Kali/Linux)
# ============================================================
set -e

echo "🍯 Honeypot Lab — Linux Installer"
echo "==================================="

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found. Installing..."
    sudo apt-get update && sudo apt-get install -y python3 python3-pip python3-venv
fi

# Create venv
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install deps
echo "📥 Installing Python packages..."
pip install -r requirements.txt
# Native C builds work on Linux
pip install conpot heralding 2>/dev/null || echo "⚠️  conpot/heralding optional"

echo ""
echo "✅ Install complete!"
echo ""
echo "🚀 Start:  python3 start_all.py"
echo "📊 Dashboard: python3 dashboard.py  -> http://localhost:5000"
echo "🎯 Test: python3 tools/test_scanner.py"
echo "🛑 Stop: python3 stop_all.py"
