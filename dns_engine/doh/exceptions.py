"""
DNS-over-HTTPS Exceptions

Responsibilities:
- Define DoH-specific exceptions
- Allow precise error handling
- Prevent generic exception usage
"""

from __future__ import annotations


class DoHError(Exception):
    """
    Base class for all DoH exceptions.
    """


class DoHConfigurationError(DoHError):
    """
    Invalid DoH configuration.
    """


class DoHConnectionError(DoHError):
    """
    Unable to connect to DoH server.
    """


class DoHTimeoutError(DoHError):
    """
    DoH request timed out.
    """


class DoHProtocolError(DoHError):
    """
    Invalid HTTP response from DoH server.
    """


class DoHResponseError(DoHError):
    """
    Invalid DNS response received from DoH server.
    """


class DoHValidationError(DoHError):
    """
    DNS response validation failed.
    """


class DoHProviderError(DoHError):
    """
    Unknown or unsupported DoH provider.
    """