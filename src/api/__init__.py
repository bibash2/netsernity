"""REST API for NetSentry."""

from .app import VERSION, create_app

__all__ = ["create_app", "VERSION"]
