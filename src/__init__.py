"""NIDS — Network Intrusion Detection System (from-scratch ML)."""

__version__ = "1.0.0"
__author__ = "NIDS Project"

from . import capture, data, inference, models, monitoring, training, utils

__all__ = ["capture", "data", "models", "training", "inference", "utils", "monitoring"]
