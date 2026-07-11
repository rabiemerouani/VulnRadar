# src/scanner.py
import asyncio
import logging

logger = logging.getLogger("VulnRadar.scanner")

# Standard industry mappings to identify common services quickly
COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    80: "http",
    110: "pop3",
    135: "msrpc",
    161: "snmp",
    443: "https",
    445: "microsoft-ds",
    3306: "mysql",
    3389: "ms-wbt-server",
    8080: "http-alt",
    8443: "https-alt"
}

async def scan_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    Attempts to establish an asynchronous TCP connection to a specific target port.
    Returns True if open, False if closed or filtered.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False
    except Exception as e:
        logger.error(f"Unexpected error while scanning {ip}:{port} -> {e}")
        return False

async def grab_banner(ip: str, port: int, timeout: float = 0.5) -> str:
    """
    Connects to a confirmed open port to intercept its service version banner.
    Returns an empty string "" if the service remains silent or errors out.
    """
    try:
        # Keep timeout short (0.5s) as talkative services respond instantly
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        
        # Interrogate standard web interfaces with a clean HTTP probe
        if port in [80, 8080]:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
            
        data = await reader.read(1024)
        writer.close()
        await writer.wait_closed()
        
        if data:
            banner = data.decode("utf-8", errors="ignore").strip()
            
            # Isolate the definitive software version string from HTTP server responses
            if "Server:" in banner:
                for line in banner.split("\n"):
                    if line.strip().startswith("Server:"):
                        return line.replace("Server:", "").strip()
            return banner
            
    except Exception:
        # Fail silently with an empty string if service banner extraction drops
        return ""
    return ""