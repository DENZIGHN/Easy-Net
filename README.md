# EasyNet

Network censorship bypass research tool for controlled lab environments.

EasyNet implements multiple DPI (Deep Packet Inspection) bypass techniques and provides
a local proxy that automatically applies the appropriate method for each connection.

> **Research use only.** This tool is designed for studying network censorship mechanisms
> in controlled virtual lab environments.

## Features

### DPI Bypass Methods
- **TCP Fragmentation** — Splits TLS ClientHello across TCP segments to hide the SNI field from DPI
- **HTTP Host Manipulation** — Case randomization, space/tab insertion, trailing dot on Host headers
- **TTL Desync** — Sends fake RST packets with low TTL to trick DPI into dropping connection tracking
- **TCP Desync** — Injects fake data to desynchronize DPI TCP stream reassembly

### Encrypted DNS
- **DNS-over-HTTPS (DoH)** — Cloudflare, Google, Quad9 providers
- **DNS-over-TLS (DoT)** — Fallback encrypted DNS resolution

### Proxy Modes
- **SOCKS5 Proxy** — Local proxy for per-application routing
- **Transparent Proxy** — System-wide interception via iptables (Linux, root required)
- **Split Tunneling** — Only bypass blocked domains; direct routing for everything else

### Smart Routing
- **Auto-detection** — Identifies blocked domains via DNS comparison and timeout analysis
- **Local blocklist** — Manually managed domain list
- **Community sources** — Fetch blocklists from configured URLs
- **Method auto-selection** — Tests bypass methods per domain, caches the working one

### Management
- **CLI** — Full command-line interface
- **Web UI** — Optional localhost dashboard for monitoring and configuration
- **Systemd service** — For running as a Linux daemon

## Requirements

- Python 3.11+
- Linux (primary), macOS, Windows (partial support)
- Root/admin privileges for: transparent proxy, TTL desync, TCP desync

## Installation

```bash
# Clone the repository
git clone <repo-url> easynet
cd easynet

# Install with pip (use a virtualenv)
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,web]"
```

## Quick Start

### Start the SOCKS5 proxy

```bash
# With default config
easynet run

# With custom config
easynet run -c /path/to/config.yaml

# With web UI
easynet run --web

# With transparent proxy (requires root)
sudo easynet run --transparent
```

### Configure your application

Set your browser/application SOCKS5 proxy to `127.0.0.1:1080`.

### Check if a domain is blocked

```bash
easynet check example.com
```

### Resolve a domain via all DNS providers

```bash
easynet resolve example.com
```

### Manage the blocklist

```bash
easynet add-domain blocked-site.com
easynet remove-domain blocked-site.com
```

### Test bypass methods

```bash
easynet test-bypass example.com
easynet test-bypass example.com --method fragmentation
```

### View status

```bash
easynet status
```

## Configuration

Copy and edit the default configuration:

```bash
cp config/default.yaml ~/.easynet/config.yaml
easynet -c ~/.easynet/config.yaml run
```

Key configuration sections:
- `dns` — DoH/DoT providers and timeouts
- `bypass` — Enable/disable individual methods and their parameters
- `proxy` — SOCKS5/transparent proxy settings
- `routing` — Block detection, blocklist sources, method auto-selection
- `web` — Web UI host/port

See `config/default.yaml` for all options with documentation.

## Systemd Service (Linux)

```bash
# Copy service file
sudo cp scripts/easynet.service /etc/systemd/system/

# Copy config
sudo mkdir -p /etc/easynet
sudo cp config/default.yaml /etc/easynet/config.yaml

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now easynet
sudo journalctl -u easynet -f
```

## Running Tests

```bash
pip install -e ".[dev]"
pytest -v
```

## Architecture

```
easynet/
├── core/           # DPI bypass methods
│   ├── base.py           # Abstract base class for bypass methods
│   ├── engine.py         # Orchestrates all bypass methods
│   ├── fragmentation.py  # TLS ClientHello TCP fragmentation
│   ├── host_manipulation.py  # HTTP Host header tricks
│   ├── ttl_desync.py     # TTL-based fake RST injection
│   └── tcp_desync.py     # TCP stream desynchronization
├── dns/            # DNS resolution
│   └── resolver.py       # DoH, DoT, system DNS with caching
├── proxy/          # Proxy servers
│   ├── socks5.py         # SOCKS5 proxy with bypass integration
│   └── transparent.py    # iptables-based transparent proxy
├── routing/        # Smart routing
│   └── router.py         # Block detection, blocklist, method selection
├── cli/            # Command-line interface
│   └── main.py           # Click-based CLI
├── web/            # Web UI
│   └── app.py            # aiohttp localhost dashboard
└── utils/          # Utilities
    ├── config.py         # YAML config loading
    ├── logging.py        # Logging setup
    └── platform.py       # OS detection, dependency checks
```

## How It Works

1. **Client connects** to the SOCKS5 proxy (or traffic is intercepted transparently)
2. **Smart router** checks if the destination domain is blocked (blocklist + auto-detection)
3. If blocked, **encrypted DNS** (DoH/DoT) resolves the domain to bypass DNS poisoning
4. **Bypass engine** selects and applies the appropriate DPI evasion technique
5. **Data is relayed** through the proxy with bypass applied to the first packet

## License

MIT
