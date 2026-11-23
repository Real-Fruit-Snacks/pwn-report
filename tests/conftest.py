"""Suite-wide proof that fixture and report work never requires a network."""

from __future__ import annotations

import http.client
import socket
import urllib.request

import pytest


@pytest.fixture(autouse=True)
def _block_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("network access is forbidden by the pwn-report test contract")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(http.client, "HTTPConnection", blocked)
    monkeypatch.setattr(http.client, "HTTPSConnection", blocked)
    monkeypatch.setattr(urllib.request, "urlopen", blocked)
