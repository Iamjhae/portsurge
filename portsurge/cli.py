#!/usr/bin/env python3
"""
PortSurge CLI — feed it subdomains, get open ports.

Usage:
    portsurge -l subs.txt
    portsurge -l subs.txt -m full -o results.json
    cat subs.txt | portsurge -m top100 --banners
    portsurge -t api.target.com,admin.target.com -m top1000
"""

import argparse
import asyncio
import sys
import time

from portsurge.scanner import scan_host, get_port_list
from portsurge.output import (
    print_banner,
    print_scan_complete,
    make_live_callback,
    results_to_json,
    results_to_csv,
    results_to_grep,
    C,
)


def parse_args():
    parser = argparse.ArgumentParser(
        prog="portsurge",
        description="Async subdomain port scanner for bug bounty recon.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
scan modes:
  top100     ~50 most common ports (fast)
  top1000    ~1000 common ports (default, balanced)
  full       all 65535 ports (slow but thorough)

examples:
  portsurge -l subs.txt
  portsurge -l subs.txt -m full --banners -o results.json
  portsurge -t app.target.com -m top100
  cat subs.txt | portsurge --format csv > open_ports.csv
  portsurge -l subs.txt -p 80,443,8080,8443
        """,
    )
    input_group = parser.add_argument_group("input")
    input_group.add_argument("-l", "--list", dest="sublist", help="File with subdomains (one per line)")
    input_group.add_argument("-t", "--targets", help="Comma-separated list of targets")

    scan_group = parser.add_argument_group("scan options")
    scan_group.add_argument(
        "-m", "--mode",
        choices=["top100", "top1000", "full"],
        default="top1000",
        help="Port scan mode (default: top1000)",
    )
    scan_group.add_argument("-p", "--ports", help="Custom port list (comma-separated, e.g. 80,443,8080)")
    scan_group.add_argument("-c", "--concurrency", type=int, default=500, help="Max concurrent connections per host (default: 500)")
    scan_group.add_argument("--timeout", type=float, default=1.5, help="Connection timeout in seconds (default: 1.5)")
    scan_group.add_argument("--banners", action="store_true", help="Attempt banner grabbing on open ports")
    scan_group.add_argument("--host-threads", type=int, default=5, help="Max hosts to scan in parallel (default: 5)")

    output_group = parser.add_argument_group("output")
    output_group.add_argument("-o", "--output", help="Output file path (auto-detects format from extension)")
    output_group.add_argument(
        "--format",
        choices=["json", "csv", "grep", "terminal"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    output_group.add_argument("-q", "--quiet", action="store_true", help="Suppress banner and progress output")
    output_group.add_argument("--open-only", action="store_true", default=True, help="Only show hosts with open ports (default)")
    output_group.add_argument("--show-all", action="store_true", help="Show all hosts including those with 0 open ports")

    return parser.parse_args()


def load_targets(args) -> list:
    """Load targets from file, args, or stdin."""
    targets = []

    if args.sublist:
        try:
            with open(args.sublist, "r") as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"{C.RED}[!] File not found: {args.sublist}{C.RESET}", file=sys.stderr)
            sys.exit(1)

    if args.targets:
        targets.extend([t.strip() for t in args.targets.split(",") if t.strip()])

    if not targets and not sys.stdin.isatty():
        targets = [line.strip() for line in sys.stdin if line.strip() and not line.startswith("#")]

    # Strip protocols and paths
    cleaned = []
    for t in targets:
        t = t.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        if t:
            cleaned.append(t)

    return list(dict.fromkeys(cleaned))  # dedupe, preserve order


async def run_scan(targets, ports, args):
    """Run the full scan pipeline."""
    all_results = []
    total_open = 0
    start = time.monotonic()

    callback = None
    if args.format == "terminal" and not args.quiet:
        callback = make_live_callback(len(ports))

    # Scan hosts in parallel batches
    sem = asyncio.Semaphore(args.host_threads)

    async def _scan_one(host):
        async with sem:
            return await scan_host(
                host,
                ports,
                concurrency=args.concurrency,
                timeout=args.timeout,
                grab_banners=args.banners,
                callback=callback,
            )

    tasks = [_scan_one(t) for t in targets]
    results = await asyncio.gather(*tasks)

    for hr in results:
        total_open += len(hr.open_ports)
        if args.show_all or hr.open_ports or hr.resolve_error:
            all_results.append(hr)

    elapsed = time.monotonic() - start
    return all_results, total_open, elapsed


def main():
    args = parse_args()
    targets = load_targets(args)

    if not targets:
        print(f"{C.RED}[!] No targets provided. Use -l <file>, -t <hosts>, or pipe via stdin.{C.RESET}", file=sys.stderr)
        sys.exit(1)

    # Determine ports
    if args.ports:
        ports = sorted(set(int(p) for p in args.ports.split(",") if p.strip().isdigit()))
    else:
        ports = get_port_list(args.mode)

    if not args.quiet and args.format == "terminal":
        print_banner()
        print(f"  {C.BOLD}Targets:{C.RESET}      {len(targets)} subdomains")
        print(f"  {C.BOLD}Ports:{C.RESET}        {len(ports)} ({args.mode}{'—custom' if args.ports else ''})")
        print(f"  {C.BOLD}Concurrency:{C.RESET}  {args.concurrency}/host, {args.host_threads} hosts parallel")
        print(f"  {C.BOLD}Banners:{C.RESET}      {'yes' if args.banners else 'no'}")
        print(f"  {C.BOLD}Timeout:{C.RESET}      {args.timeout}s")

    # Run scan
    all_results, total_open, elapsed = asyncio.run(run_scan(targets, ports, args))

    # Terminal summary
    if not args.quiet and args.format == "terminal":
        print_scan_complete(len(targets), total_open, elapsed)

    # Auto-detect format from output extension
    fmt = args.format
    if args.output:
        if args.output.endswith(".json"):
            fmt = "json"
        elif args.output.endswith(".csv"):
            fmt = "csv"

    # Generate formatted output
    scan_meta = {
        "total_targets": len(targets),
        "port_mode": args.mode if not args.ports else "custom",
        "ports_scanned": len(ports),
        "timeout": args.timeout,
        "banners": args.banners,
    }

    if fmt == "json":
        data = results_to_json(all_results, scan_meta)
    elif fmt == "csv":
        data = results_to_csv(all_results)
    elif fmt == "grep":
        data = results_to_grep(all_results)
    else:
        data = None

    # Write to file or stdout
    if data:
        if args.output:
            with open(args.output, "w") as f:
                f.write(data)
            if not args.quiet:
                print(f"  {C.GREEN}[✓] Results saved to {args.output}{C.RESET}")
        elif fmt != "terminal":
            print(data)


if __name__ == "__main__":
    main()
