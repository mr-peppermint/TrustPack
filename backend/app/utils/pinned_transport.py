"""DNS-rebinding-proof connection setup.

`validate_outbound_url` resolves a hostname and rejects private/reserved
addresses, but if the HTTP client then resolves the same name AGAIN when it
connects, an attacker-controlled DNS server can answer differently the
second time (classic DNS rebinding / TOCTOU). This network backend closes
that gap: the address that gets validated is the address that gets connected
to. Resolution happens once per connection attempt, every resolved address
is checked, and the TCP socket is opened to the validated IP literal.

TLS is unaffected: httpcore still passes the original hostname as the SNI /
certificate-verification name, so the certificate must be valid for the
allow-listed host, not for the IP.
"""
import asyncio
from typing import Iterable, Optional

import httpcore

from app.utils.errors import UnsupportedHostError
from app.utils.security import resolve_safe_addresses


class SSRFSafeBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, inner: Optional[httpcore.AsyncNetworkBackend] = None) -> None:
        self._inner = inner or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Optional[Iterable] = None,
    ) -> httpcore.AsyncNetworkStream:
        loop = asyncio.get_running_loop()
        addresses = await loop.run_in_executor(None, resolve_safe_addresses, host)
        last_exc: Optional[Exception] = None
        for address in addresses:
            try:
                return await self._inner.connect_tcp(
                    address, port, timeout=timeout, local_address=local_address, socket_options=socket_options
                )
            except httpcore.ConnectError as exc:
                last_exc = exc
        assert last_exc is not None  # resolve_safe_addresses never returns an empty list
        raise last_exc

    async def connect_unix_socket(self, path: str, timeout=None, socket_options=None):
        raise UnsupportedHostError("Unix domain sockets are not permitted for outbound requests")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)
