# Porttrait

[![Go Version](https://img.shields.io/badge/go-%3E%3D1.22-blue.svg)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Porttrait** is a fast, concurrent network service scanner and banner fingerprinter written in Go. It discovers open TCP and UDP ports, extracts service banners, and accurately fingerprints running software, vendors, and versions using embedded [Rapid7 Recog](https://github.com/rapid7/recog) databases.

---

## Features

- **Fast & Scalable Scanning:** Uses an adaptive concurrent worker pool (up to 5,000 workers) with graceful cancellation via `Ctrl+C`.
- **Dual Protocol Support:** Scans and grabs banners across both **TCP** and **UDP**.
- **Intelligent Banner Grabbing:**
  - Automatically captures banners from server-speaks-first protocols (SSH, FTP, SMTP, MySQL, Telnet).
  - Sends targeted protocol probes (HTTP, TLS, SIP, DNS, NTP, SNMP) when services require a client prompt.
- **Service & Version Fingerprinting:** Matches banners and protocol headers against embedded Rapid7 Recog XML signatures to identify vendors, products, and version strings.
- **Flexible Port Selection:** Scan custom port lists, common ports (`--common`), or full 1–65,535 ranges (`--all`).
- **Stealth Mode:** Randomizes port scanning order with `--stealth` to evade sequential port scan detectors.
- **Clean Output:** Formatted tabular output for quick summaries, with optional `-v, --verbose` detailed inspection.

---

## Installation

### Prerequisites

- [Go](https://golang.org/dl/) 1.22 or higher

### Build from Source

```bash
git clone https://github.com/kieranpritchard/network-service-fingerprinter.git
cd network-service-fingerprinter
go build -o porttrait main.go
```

You can optionally place the binary in your `$PATH`:

```bash
sudo mv porttrait /usr/local/bin/
```

---

## Usage

Porttrait provides two primary commands: **`scan`** and **`grab`**.

```text
A tool for fingerprinting services and grabbing banners

Usage:
  porttrait [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  grab        Grabs the banner of the specified port(s)
  help        Help about any command
  scan        Scans either the specified port(s) or all the ports for open services

Flags:
  -h, --help              help for porttrait
  -p, --ports string      Port to be targeted (single port or comma-separated list)
  -P, --protocol string   Protocol to be used (tcp, udp or both) (default "tcp")
  -t, --target string     Domain or IP address to be targeted
  -T, --timeout int       Length of timeout in seconds (default 10)
```

---

### 1. `scan` — Service Discovery & Port Scanning

Scan targets for open services across TCP, UDP, or both.

#### Scan common ports:
```bash
./porttrait scan -t 192.168.1.1 --common
```

#### Scan specific ports with verbose banner details:
```bash
./porttrait scan -t example.com -p 80,443,8080 -v
```

#### Scan all 65,535 ports in randomized order (stealth mode):
```bash
./porttrait scan -t 10.0.0.5 --all --stealth
```

#### Scan both TCP and UDP protocols:
```bash
./porttrait scan -t 192.168.1.1 -p 53,80,123,443 --protocol both
```

#### Scan Flags:
| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--common` | | `false` | Scans standard common service ports |
| `--all` | | `false` | Scans all ports from 1 to 65,535 |
| `--stealth` | | `false` | Shuffles and randomizes the port scanning order |
| `--protocol` | | `both` | Protocols to scan (`tcp`, `udp`, or `both`) |
| `--verbose` | `-v` | `false` | Show full multiline banners and all fingerprint matches |

---

### 2. `grab` — Targeted Banner Grabbing

Quickly connect to one or more specified ports, grab banners, and fingerprint them.

#### Grab banner from a single port:
```bash
./porttrait grab -t 192.168.1.50 -p 22
```

#### Grab banners from multiple ports across both TCP and UDP:
```bash
./porttrait grab -t 192.168.1.50 -p 21,22,80,443,5060 -P both -T 5
```

---

## Example Output

### Standard Scan
```text
Scanning 192.168.1.50 (tcp) - 4 ports

PORT        STATE   SERVICE              VERSION   BANNER
22/tcp      open    OpenSSH              8.9p1     SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
80/tcp      open    Apache HTTP Server   2.4.52    HTTP/1.1 200 OK
443/tcp     open    Apache HTTP Server   2.4.52    HTTP/1.1 200 OK
3306/tcp    open    MySQL Server         8.0.36    8.0.36-0ubuntu0.22.04.1

4 open port(s) found in 1.42s
```

### Verbose Scan (`-v`)
```text
============================================================
PORT: 80/tcp
STATE: open
BANNER:
HTTP/1.1 200 OK
Date: Wed, 05 Nov 2026 20:00:00 GMT
Server: Apache/2.4.52 (Ubuntu)
Content-Type: text/html

MATCHES:
  - Apache HTTP Server 2.4.52
  - Ubuntu Linux
============================================================
```

---

## Architecture

- **`cmd/`**: CLI definitions and flag bindings powered by [spf13/cobra](https://github.com/spf13/cobra).
- **`internal/scan/`**: Worker pool dispatcher (`scanner.go`), TCP worker logic, and UDP probe state evaluation (`udp.go`).
- **`internal/banners/`**: Raw socket connection handling, server-speaks-first listeners, protocol probe triggers, and banner sanitization.
- **`internal/fingerprinting/`**: Embedded [Rapid7 Recog](https://github.com/rapid7/recog) databases (`recogFiles embed.FS`), target selection heuristics (`select_targets.go`), and matching engine (`match_banners.go`).
- **`internal/input/`**: Input validation and normalization for IPv4, IPv6, hostnames, and port ranges.
- **`internal/output/`**: Tabular formatting, banner truncation, and verbose report rendering.

---

## Testing

Run all unit and integration tests:

```bash
go test -v ./...
```

---

## Acknowledgments & Licenses

- Porttrait is licensed under the [MIT License](LICENSE).
- Service fingerprints are derived from the [Rapid7 Recog](https://github.com/rapid7/recog) project (licensed under the BSD 2-Clause License).
- Signature loading and matching leverages [runZero recog-go](https://github.com/RumbleDiscovery/recog-go) (licensed under the Apache 2.0 License).
- For complete third-party notices, see [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

