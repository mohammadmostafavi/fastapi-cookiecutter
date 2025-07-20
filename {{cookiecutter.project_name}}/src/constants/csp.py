import os

"""
Content Security Policy (CSP) configuration constants.

This module contains constants related to Content Security Policy (CSP) configuration.
"""

CSP_ENABLED = os.getenv("CSP_ENABLED", "True").lower() == "true"
CSP_DEFAULT_SRC = os.getenv("CSP_DEFAULT_SRC", "'self'").split()
CSP_SCRIPT_SRC = os.getenv("CSP_SCRIPT_SRC", "'self'").split()
CSP_STYLE_SRC = os.getenv("CSP_STYLE_SRC", "'self' 'unsafe-inline'").split()
CSP_IMG_SRC = os.getenv("CSP_IMG_SRC", "'self' data:").split()
CSP_CONNECT_SRC = os.getenv("CSP_CONNECT_SRC", "'self'").split()
CSP_FONT_SRC = os.getenv("CSP_FONT_SRC", "'self'").split()
CSP_OBJECT_SRC = os.getenv("CSP_OBJECT_SRC", "'none'").split()
CSP_MEDIA_SRC = os.getenv("CSP_MEDIA_SRC", "'self'").split()
CSP_FRAME_SRC = os.getenv("CSP_FRAME_SRC", "'none'").split()
CSP_REPORT_URI = os.getenv("CSP_REPORT_URI", "")
