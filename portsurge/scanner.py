"""
PortSurge — Async port scanner engine.
Resolves subdomains, scans ports via asyncio, and streams results.
"""

import asyncio
import socket
import time
import sys
from dataclasses import dataclass, field
from typing import Optional

# Well-known service banners / port mappings
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios", 143: "imap", 443: "https", 445: "smb",
    465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    2083: "cpanel-ssl", 2087: "whm-ssl", 3000: "dev-server",
    3306: "mysql", 3389: "rdp", 4443: "https-alt", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 6443: "k8s-api", 8000: "http-alt",
    8008: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    8888: "http-alt", 9090: "prometheus", 9200: "elasticsearch",
    9443: "https-alt", 27017: "mongodb", 11211: "memcached",
}

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 179, 443, 445,
    465, 514, 515, 587, 631, 636, 993, 995, 1080, 1433, 1521, 1723,
    2049, 2083, 2087, 3000, 3306, 3389, 4443, 5432, 5900, 5985, 6379,
    6443, 6667, 8000, 8008, 8080, 8443, 8888, 9090, 9200, 9443,
    10000, 11211, 27017,
]

TOP_1000_PORTS = sorted(set(TOP_100_PORTS + [
    1, 7, 9, 11, 13, 15, 17, 19, 20, 26, 37, 49, 70, 79, 81, 82, 83,
    84, 85, 88, 89, 90, 99, 100, 106, 113, 119, 125, 144, 146, 161,
    163, 175, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301,
    311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 444, 458, 464,
    481, 497, 500, 512, 513, 524, 541, 543, 544, 545, 548, 554, 555,
    563, 616, 617, 625, 646, 648, 666, 667, 668, 683, 687, 691, 700,
    705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801,
    808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981,
    987, 990, 992, 999, 1000, 1001, 1010, 1023, 1024, 1025, 1026,
    1027, 1028, 1029, 1030, 1099, 1100, 1110, 1111, 1222, 1234,
    1241, 1248, 1270, 1311, 1334, 1352, 1414, 1443, 1494, 1500,
    1503, 1515, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641,
    1658, 1666, 1687, 1700, 1717, 1718, 1719, 1720, 1721, 1761,
    1782, 1783, 1801, 1805, 1812, 1839, 1862, 1863, 1864, 1875,
    1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998, 1999,
    2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
    2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038,
    2040, 2043, 2045, 2048, 2065, 2068, 2099, 2100, 2103, 2105,
    2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161,
    2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288,
    2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401,
    2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607,
    2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809,
    2811, 2869, 2875, 2909, 2910, 2920, 2967, 2998, 3001, 3003,
    3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052, 3071,
    3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283,
    3300, 3301, 3323, 3325, 3333, 3351, 3367, 3369, 3370, 3371,
    3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527, 3546, 3551,
    3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801,
    3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880,
    3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998,
    4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125,
    4129, 4224, 4242, 4279, 4321, 4343, 4444, 4445, 4446, 4449,
    4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002,
    5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061,
    5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221,
    5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431,
    5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633,
    5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811,
    5815, 5822, 5825, 5850, 5859, 5862, 5877, 5901, 5902, 5903,
    5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952,
    5959, 5960, 5961, 5962, 5987, 5988, 5989, 5998, 5999, 6000,
    6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059,
    6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502,
    6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666, 6669,
    6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901,
    6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100,
    7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625,
    7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937,
    7938, 7999, 8001, 8002, 8007, 8009, 8010, 8011, 8021, 8022,
    8031, 8042, 8045, 8081, 8082, 8083, 8084, 8085, 8086, 8087,
    8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193,
    8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333, 8383,
    8400, 8402, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800,
    8873, 8880, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010,
    9011, 9040, 9050, 9071, 9080, 9081, 9091, 9099, 9100, 9101,
    9102, 9103, 9110, 9111, 9191, 9199, 9207, 9220, 9290, 9415,
    9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595,
    9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943,
    9944, 9968, 9998, 9999, 10001, 10002, 10003, 10004, 10009,
    10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566,
    10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111,
    11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783,
    14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660,
    15742, 16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992,
    16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315,
    19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222,
    20828, 21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214,
    27000, 27352, 27353, 27355, 27356, 27715, 28201, 30000, 30718,
    30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773,
    32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782,
    32783, 32784, 33354, 33899, 34571, 34572, 34573, 35500, 38292,
    40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100,
    48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159,
    49160, 49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999,
    50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636,
    50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328,
    55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080,
    60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000,
    65129, 65389,
]))


@dataclass
class ScanResult:
    host: str
    ip: str
    port: int
    state: str  # "open" | "closed" | "filtered"
    service: str
    banner: str = ""
    latency_ms: float = 0.0


@dataclass
class HostResult:
    host: str
    ip: str
    open_ports: list = field(default_factory=list)
    resolve_error: Optional[str] = None


async def resolve_host(host: str) -> Optional[str]:
    """Resolve hostname to IP address."""
    loop = asyncio.get_event_loop()
    try:
        result = await loop.getaddrinfo(host.strip(), None, family=socket.AF_INET)
        if result:
            return result[0][4][0]
    except (socket.gaierror, OSError):
        pass
    return None


async def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to grab a service banner."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        # Send minimal probe for HTTP-like ports
        if port in (80, 443, 8080, 8443, 8000, 8888, 3000, 8008, 8081, 9090):
            writer.write(b"HEAD / HTTP/1.0\r\nHost: scan\r\n\r\n")
            await writer.drain()

        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        banner = data.decode("utf-8", errors="replace").strip()
        # Truncate long banners
        return banner[:200] if banner else ""
    except Exception:
        return ""


async def scan_port(
    ip: str,
    port: int,
    timeout: float = 1.5,
    grab_banners: bool = False,
) -> Optional[tuple]:
    """Scan a single port. Returns (port, latency_ms, banner) if open."""
    start = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        latency = (time.monotonic() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        banner = ""
        if grab_banners:
            banner = await grab_banner(ip, port, timeout=2.0)

        return (port, latency, banner)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def scan_host(
    host: str,
    ports: list,
    concurrency: int = 500,
    timeout: float = 1.5,
    grab_banners: bool = False,
    callback=None,
) -> HostResult:
    """Scan all specified ports on a single host."""
    host = host.strip()
    ip = await resolve_host(host)

    if not ip:
        result = HostResult(host=host, ip="", resolve_error="DNS resolution failed")
        if callback:
            callback(result)
        return result

    host_result = HostResult(host=host, ip=ip)
    sem = asyncio.Semaphore(concurrency)

    async def _scan(port):
        async with sem:
            return await scan_port(ip, port, timeout, grab_banners)

    tasks = [_scan(p) for p in ports]
    results = await asyncio.gather(*tasks)

    for r in results:
        if r:
            port, latency, banner = r
            service = COMMON_SERVICES.get(port, "unknown")
            host_result.open_ports.append(
                ScanResult(
                    host=host,
                    ip=ip,
                    port=port,
                    state="open",
                    service=service,
                    banner=banner,
                    latency_ms=round(latency, 2),
                )
            )

    host_result.open_ports.sort(key=lambda x: x.port)

    if callback:
        callback(host_result)

    return host_result


def get_port_list(mode: str) -> list:
    """Return port list based on scan mode."""
    if mode == "top100":
        return TOP_100_PORTS
    elif mode == "top1000":
        return TOP_1000_PORTS
    elif mode == "full":
        return list(range(1, 65536))
    else:
        return TOP_1000_PORTS
