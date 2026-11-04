"""Vercel Serverless Function Entry Point for ipVision"""
import os
import sys
from pathlib import Path

# Add project root to sys.path so server.py can be imported
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from server import ScannerHandler

# Vercel looks for 'handler' class inheriting from BaseHTTPRequestHandler
handler = ScannerHandler
