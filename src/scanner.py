
import asyncio
import logging

logger = logging.getLogger("VulnRadar.scanner")

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
    Protects against silent hanging protocols using an explicit read timeout block.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        
        if port in [80, 8080]:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
            
        # FIX: Explicitly wrapped read operation inside its own timeout loop
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        
        writer.close()
        await writer.wait_closed()
        
        if data:
            banner = data.decode("utf-8", errors="ignore").strip()
            if "Server:" in banner:
                for line in banner.split("\n"):
                    if line.strip().startswith("Server:"):
                        return line.replace("Server:", "").strip()
            return banner
            
    except Exception:
        return ""
    return ""

async def scan_host(ip: str, ports_list: list, timeout: float = 1.0) -> dict:
    """
    Scans a comprehensive list of ports on a single host concurrently using asyncio.gather.
    Returns a structured metadata summary of the live target state.
    """
    # 1. Fire off all port connectivity checks concurrently
    tasks = [scan_port(ip, port, timeout) for port in ports_list]
    scan_results = await asyncio.gather(*tasks)
    
    # Map the port numbers alongside their Boolean results
    open_ports = [ports_list[i] for i, is_open in enumerate(scan_results) if is_open]
    
    # If no ports are accessible, evaluate the entire host as down immediately
    if not open_ports:
        return {"ip": ip, "status": "down", "ports": []}
        
    logger.info(f"[+] Active host discovered at {ip}. Extracting profile metrics...")
    
    # 2. For all discovered open ports, collect signatures in parallel
    banner_tasks = [grab_banner(ip, port, timeout) for port in open_ports]
    banners = await asyncio.gather(*banner_tasks)
    
    # 3. Assemble our clean structured portfolio schema
    detected_ports = []
    for i, port in enumerate(open_ports):
        service_name = COMMON_SERVICES.get(port, "unknown")
        detected_ports.append({
            "port": port,
            "protocol": "tcp",
            "state": "open",
            "service": service_name,
            "banner": banners[i]
        })
        
    return {
        "ip": ip,
        "status": "up",
        "ports": detected_ports
    }