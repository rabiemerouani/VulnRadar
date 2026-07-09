# src/scanner.py
import asyncio
import logging

logger = logging.getLogger("VulnRadar.scanner")

async def scan_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    Attempts to establish an asynchronous TCP connection to a specific target port.
    Returns True if open, False if closed or filtered.
    """
    try:
        # Attempt to open a TCP stream connection with a hard timeout limit
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        
        # CRITICAL: Always clean up and close your sockets if connection succeeds
        writer.close()
        await writer.wait_closed()
        return True
        
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        # All network errors, rejections, or timeouts mean the port is inaccessible
        return False
    except Exception as e:
        logger.error(f"Unexpected error while scanning {ip}:{port} -> {e}")
        return False