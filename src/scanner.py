# src/scanner.py
import asyncio
import ipaddress
import logging

# Set up the logger aligned with the global system architecture
logger = logging.getLogger("VulnRadar.scanner")

# Industry standard port-to-service mapping for rapid profiling
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
        # Immediate cleanup and closure upon discovery success
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
    Connects to an open port to grab its service application banner (version identification).
    Secured with an explicit read timeout block to prevent hanging on silent services.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        
        # Inject a basic HTTP probe if the target port is web-oriented
        if port in [80, 8080]:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
            
        # CRITICAL FIX: Explicit timeout on raw reading to combat silent protocols (like Telnet)
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        
        writer.close()
        await writer.wait_closed()
        
        if data:
            banner = data.decode("utf-8", errors="ignore").strip()
            # Targeted extraction if the return payload contains a web server signature
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
    Returns a structured dictionary summary of the live target state.
    """
    # 1. Fire off all TCP connectivity checks concurrently
    tasks = [scan_port(ip, port, timeout) for port in ports_list]
    scan_results = await asyncio.gather(*tasks)
    
    # Filter to isolate discovered open ports only
    open_ports = [ports_list[i] for i, is_open in enumerate(scan_results) if is_open]
    
    # If no ports respond, evaluate the host as down/unreachable
    if not open_ports:
        return {"ip": ip, "status": "down", "ports": []}
        
    logger.info(f"[+] Active host discovered at {ip}. Extracting profile metrics...")
    
    # 2. Collect banners in parallel across all detected open ports
    banner_tasks = [grab_banner(ip, port, timeout) for port in open_ports]
    banners = await asyncio.gather(*banner_tasks)
    
    # 3. Assemble the structured results payload for this specific host
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

async def scan_subnet(target: str, ports_list: list, timeout: float = 1.0, max_concurrent_hosts: int = 50) -> list:
    """
    The main engine entry point. Parses a single target IP or complete CIDR block
    (e.g., 192.168.1.0/24) and manages global concurrency thresholds using a Semaphore.
    """
    try:
        # If the target string contains a slash, parse it as a network range, else a single IP
        if "/" in target:
            hosts = [str(ip) for ip in ipaddress.ip_network(target, strict=False).hosts()]
        else:
            hosts = [target]
    except Exception as e:
        logger.error(f"Invalid target signature format specified ({target}): {e}")
        return []

    logger.info(f"[*] Initializing async network engine scan on: {target} ({len(hosts)} total hosts)")

    # Establish the Semaphore to regulate simultaneous active connections safely
    semaphore = asyncio.Semaphore(max_concurrent_hosts)

    async def scan_host_with_limit(ip: str):
        async with semaphore:
            return await scan_host(ip, ports_list, timeout)

    # Launch scanning concurrently across the entire parsed target host list
    subnet_tasks = [scan_host_with_limit(host) for host in hosts]
    all_results = await asyncio.gather(*subnet_tasks)

    # Filter out dead hosts, keeping only active maps for the main dashboard data feed
    active_network_map = [result for result in all_results if result["status"] == "up"]
    
    logger.info(f"[*] Scan complete. {len(active_network_map)} active host(s) identified.")
    return active_network_map