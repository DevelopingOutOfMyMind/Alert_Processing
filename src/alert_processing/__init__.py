"""
Alert Processing System

An AI Ops alert processing system built with LangGraph and Presidio
for collecting, analyzing, categorizing, and enriching alerts for SRE automation.
"""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("alert-processing")
except PackageNotFoundError:
    __version__ = "unknown"

__all__ = ["__version__"]