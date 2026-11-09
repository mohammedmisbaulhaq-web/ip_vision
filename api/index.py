"""
ipVision — Vercel Serverless Function Entry Point

This file is the ONLY Python file Vercel runs.
It routes all /api/* requests to the ScannerHandler in server.py.
Static files (HTML, CSS, JS, assets) are served by Vercel CDN automatically.
"""
import sys
from pathlib import Path

# Make server.py importable
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from server import ScannerHandler  # noqa: E402

# Vercel requires a class named 'handler' that extends BaseHTTPRequestHandler
handler = ScannerHandler
