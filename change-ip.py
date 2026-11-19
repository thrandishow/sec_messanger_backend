#!/usr/bin/env python3
"""Compatibility entry point for installations previously managed with change-ip.py."""
import os
from pathlib import Path
import sys

cli = Path(__file__).resolve().with_name("shifrctl")
os.execv(cli, [str(cli), "set-ip", *sys.argv[1:]])
