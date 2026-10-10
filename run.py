"""
Root Application Launcher
Explainable Multi-Source Threat Correlation Framework for Adaptive Cyber Incident Response
"""

import sys
import os
import webbrowser
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from backend.app import app, seed_database_if_empty

if __name__ == "__main__":
    print("=" * 75)
    print("  EXPLAINABLE MULTI-SOURCE THREAT CORRELATION FRAMEWORK")
    print("  Adaptive Cyber Incident Response SOC Platform")
    print("=" * 75)
    print("[1/3] Initializing SQLite database & multi-source schemas...")
    seed_database_if_empty()

    port = 5000
    host = "127.0.0.1"
    url = f"http://{host}:{port}"

    print(f"[2/3] AI/ML Engine initialized (XGBoost + SHAP TreeExplainer).")
    print(f"[3/3] Starting CyberSOC Web Server at {url}")
    print("=" * 75)
    print(f"  Access Dashboard: {url}")
    print(f"  REST API Base:   {url}/api/dashboard/summary")
    print("=" * 75)
    print("Press CTRL+C to terminate.")

    app.run(host=host, port=port, debug=False)
