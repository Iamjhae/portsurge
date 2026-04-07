# PortSurge

**Async subdomain port scanner built for bug bounty recon.**

Feed it a list of subdomains — it resolves DNS, scans ports with asyncio, grabs banners, and outputs clean results in terminal, JSON, CSV, or grep-friendly format.

```
    ____            __  _____                      
   / __ \____  _____/ /_/ ___/__  __________  ___ 
  / /_/ / __ \/ ___/ __/\__ \/ / / / ___/ _ `/ _ \
 / ____/ /_/ / /  / /_ ___/ / /_/ / /  / _, / ___/
/_/    \____/_/   \__//____/\__,_/_/   \_, /\___/ 
                                      /___/       
```

## Features

- **Pure Python, zero dependencies** — stdlib only, runs anywhere Python 3.8+ exists
- **Async I/O** — scans hundreds of ports per second using `asyncio`
- **DNS resolution** — auto-resolves subdomains, skips unresolvable hosts
- **3 scan modes** — `top100` (fast), `top1000` (balanced), `full` (all 65535 ports)
- **Custom ports** — specify exact ports with `-p 80,443,8080`
- **Banner grabbing** — optional service fingerprinting with `--banners`
- **Parallel host scanning** — scans multiple hosts simultaneously
- **4 output formats** — terminal (colored), JSON, CSV, grep
- **Pipe-friendly** — reads from stdin, writes structured output to stdout
- **Recon pipeline ready** — slots directly after `subfinder` / `httpx-toolkit`

## Installation

```bash
# Clone and install
git clone https://github.com/arookiech/portsurge.git
cd portsurge
pip install .

# Or install directly
pip install git+https://github.com/arookiech/portsurge.git

# Or just run without installing
python -m portsurge -l subs.txt
```

## Usage

### Basic scan from subdomain list
```bash
portsurge -l subdomains.txt
```

### Scan specific targets
```bash
portsurge -t api.target.com,admin.target.com,staging.target.com
```

### Full 65535 port scan with banners
```bash
portsurge -l subs.txt -m full --banners -o results.json
```

### Quick top-100 scan
```bash
portsurge -l subs.txt -m top100
```

### Custom ports only
```bash
portsurge -l subs.txt -p 80,443,8080,8443,3000,9090
```

### Pipe from other tools
```bash
# From subfinder
subfinder -d target.com -silent | portsurge -m top100

# From httpx-toolkit (strip URLs to hosts)
cat live_hosts.txt | portsurge --banners -o scan.json

# Chain with other tools
portsurge -l subs.txt --format grep | grep "8080" | cut -f1
```

### CSV output for spreadsheets
```bash
portsurge -l subs.txt --format csv > ports.csv
```

### Grep-friendly output (TSV)
```bash
portsurge -l subs.txt --format grep | grep redis
```

## Recon Pipeline Integration

PortSurge fits directly into a standard bug bounty recon pipeline:

```bash
TARGET="target.com"

# 1. Enumerate subdomains
subfinder -d $TARGET -all -silent > subs.txt

# 2. Port scan all discovered subdomains
portsurge -l subs.txt -m top1000 --banners -o $TARGET-ports.json

# 3. Feed open HTTP ports back into httpx for tech fingerprinting
portsurge -l subs.txt --format grep | \
    awk -F'\t' '$4=="http" || $4=="https" || $4=="http-proxy" || $4=="http-alt" {print $1":"$3}' | \
    httpx-toolkit -silent -title -tech-detect
```

## Options

```
input:
  -l, --list FILE        File with subdomains (one per line)
  -t, --targets HOSTS    Comma-separated targets

scan options:
  -m, --mode MODE        top100 | top1000 (default) | full
  -p, --ports PORTS      Custom ports (comma-separated)
  -c, --concurrency N    Max connections per host (default: 500)
  --timeout SECS         Connection timeout (default: 1.5s)
  --banners              Grab service banners on open ports
  --host-threads N       Parallel host scans (default: 5)

output:
  -o, --output FILE      Save results (auto-detects .json/.csv)
  --format FORMAT        terminal | json | csv | grep
  -q, --quiet            Suppress progress output
  --show-all             Include hosts with 0 open ports
```

## Output Formats

### Terminal (default)
```
┌── api.target.com (104.21.34.56) — scanning 1000 ports
│  22      ssh                    12ms
│  80      http                   8ms
│  443     https                  9ms
│  8080    http-proxy             15ms │ HTTP/1.1 200 OK
└── 4 open ports
```

### JSON (`-o results.json` or `--format json`)
```json
{
  "scan_metadata": {
    "tool": "PortSurge",
    "version": "1.0.0",
    "timestamp": "2026-04-07T12:00:00+00:00",
    "total_targets": 50,
    "port_mode": "top1000",
    "ports_scanned": 1000
  },
  "results": [
    {
      "host": "api.target.com",
      "ip": "104.21.34.56",
      "open_ports": [
        {"port": 443, "service": "https", "state": "open", "banner": "", "latency_ms": 9.2}
      ]
    }
  ]
}
```

### CSV (`--format csv`)
```
host,ip,port,service,state,banner,latency_ms
api.target.com,104.21.34.56,443,https,open,,9.2
```

### Grep (`--format grep`)
```
api.target.com	104.21.34.56	443	https	
admin.target.com	104.21.34.57	22	ssh	OpenSSH_8.9
```

## Performance Tips

| Mode | Ports | Time per host (~) | Use case |
|------|-------|--------------------|----------|
| `top100` | ~50 | 2-5s | Quick triage |
| `top1000` | ~1000 | 10-30s | Standard recon |
| `full` | 65535 | 2-10min | Deep dive |

- Increase `--concurrency` on fast networks (up to 2000)
- Decrease `--timeout` to 0.8s on local/fast targets
- Use `--host-threads 10` if scanning many hosts on fast infra

## Legal

This tool is intended for **authorized security testing only**. Only scan targets you have explicit permission to test (bug bounty programs, your own infrastructure, authorized pentests). Unauthorized port scanning may violate laws in your jurisdiction.

## License

MIT
