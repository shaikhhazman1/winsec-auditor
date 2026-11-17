"""Lets the module be tested on its own with:  python -m modules.scanner"""
from .port_scanner import _standalone

raise SystemExit(_standalone())
