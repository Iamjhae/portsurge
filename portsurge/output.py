"""
Output formatters for PortSurge scan results.
"""

import json
import csv
import io
import sys
from datetime import datetime, timezone


# ── ANSI colors ──────────────────────────────────────────────────────
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    MAGENTA = "\033[95m"


def _no_color():
    """Disable colors (for piped output)."""
    for attr in ("RED", "GREEN", "YELLOW", "CYAN", "DIM", "BOLD", "RESET", "MAGENTA"):
        setattr(C, attr, "")


if not sys.stdout.isatty():
    _no_color()


# ── Terminal output ──────────────────────────────────────────────────
def print_banner():
    banner = f"""{C.CYAN}{C.BOLD}
    ____            __  _____                      
   / __ \\____  _____/ /_/ ___/__  __________  ___ 
  / /_/ / __ \\/ ___/ __/\\__ \\/ / / / ___/ _ `/ _ \\
 / ____/ /_/ / /  / /_ ___/ / /_/ / /  / _, / ___/
/_/    \\____/_/   \\__//____/\\__,_/_/   \\_, /\\___/ 
                                      /___/       
{C.RESET}{C.DIM}  Async subdomain port scanner for bug bounty recon{C.RESET}
"""
    print(banner)


def print_host_start(host: str, ip: str, total_ports: int):
    print(f"\n{C.BOLD}{C.CYAN}┌── {host}{C.RESET} {C.DIM}({ip}) — scanning {total_ports} ports{C.RESET}")


def print_open_port(result):
    svc = f"{C.YELLOW}{result.service}{C.RESET}" if result.service != "unknown" else f"{C.DIM}unknown{C.RESET}"
    banner_str = ""
    if result.banner:
        short = result.banner.replace("\r", "").replace("\n", " ")[:80]
        banner_str = f" {C.DIM}│ {short}{C.RESET}"
    latency = f"{C.DIM}{result.latency_ms:.0f}ms{C.RESET}"
    print(f"{C.GREEN}│  {result.port:<7}{C.RESET} {svc:<22} {latency}{banner_str}")


def print_host_summary(host_result):
    count = len(host_result.open_ports)
    if host_result.resolve_error:
        print(f"{C.RED}├── ✗ {host_result.host}: {host_result.resolve_error}{C.RESET}")
    elif count == 0:
        print(f"{C.DIM}└── 0 open ports{C.RESET}")
    else:
        print(f"{C.BOLD}└── {C.GREEN}{count} open port{'s' if count != 1 else ''}{C.RESET}")


def print_scan_complete(total_hosts, total_open, elapsed):
    print(f"\n{C.BOLD}{'─' * 55}{C.RESET}")
    print(f"{C.BOLD}  Scan complete:{C.RESET} {total_hosts} hosts, {C.GREEN}{total_open} open ports{C.RESET}, {elapsed:.1f}s elapsed")
    print(f"{C.BOLD}{'─' * 55}{C.RESET}\n")


# ── Progress callback (live terminal) ────────────────────────────────
def make_live_callback(total_ports):
    """Returns a callback that prints results as they come in."""
    def callback(host_result):
        if host_result.resolve_error:
            print_host_summary(host_result)
            return
        print_host_start(host_result.host, host_result.ip, total_ports)
        for r in host_result.open_ports:
            print_open_port(r)
        print_host_summary(host_result)
    return callback


# ── JSON output ──────────────────────────────────────────────────────
def results_to_json(all_results, scan_meta: dict) -> str:
    output = {
        "scan_metadata": {
            "tool": "PortSurge",
            "version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **scan_meta,
        },
        "results": [],
    }
    for hr in all_results:
        entry = {
            "host": hr.host,
            "ip": hr.ip,
            "resolve_error": hr.resolve_error,
            "open_ports": [
                {
                    "port": r.port,
                    "service": r.service,
                    "state": r.state,
                    "banner": r.banner,
                    "latency_ms": r.latency_ms,
                }
                for r in hr.open_ports
            ],
        }
        output["results"].append(entry)
    return json.dumps(output, indent=2)


# ── CSV output ───────────────────────────────────────────────────────
def results_to_csv(all_results) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["host", "ip", "port", "service", "state", "banner", "latency_ms"])
    for hr in all_results:
        if hr.resolve_error:
            writer.writerow([hr.host, "", "", "", "dns_error", hr.resolve_error, ""])
        for r in hr.open_ports:
            writer.writerow([r.host, r.ip, r.port, r.service, r.state, r.banner, r.latency_ms])
    return buf.getvalue()


# ── Grep-friendly one-line-per-port output ───────────────────────────
def results_to_grep(all_results) -> str:
    lines = []
    for hr in all_results:
        for r in hr.open_ports:
            lines.append(f"{r.host}\t{r.ip}\t{r.port}\t{r.service}\t{r.banner}")
    return "\n".join(lines)
