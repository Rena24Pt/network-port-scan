# Network Port Scanner

A fast, multithreaded **TCP port scanner** written in pure Python, with
**banner grabbing** for service and version detection. Zero third-party
dependencies — it runs anywhere Python 3.8+ is installed.

This project was built to demonstrate — and to learn — the fundamentals behind
tools like `nmap`: **sockets**, the **TCP/IP handshake**, **banner grabbing**,
and **concurrency** with a thread pool.

```
$ portscan scanme.nmap.org -p 22,80,443,8080

Scan report for scanme.nmap.org (45.33.32.156)
Scanned 4 port(s) in 1.31s — 2 open

PORT      STATE  SERVICE  BANNER
22/tcp    open   ssh      SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
80/tcp    open   http     HTTP/1.1 200 OK (Server: Apache/2.4.7 (Ubuntu))
```

> ⚠️ **Legal notice**
> This tool is for **authorised testing and education only**. Scan only systems
> you **own** or have **explicit written permission** to test. Unauthorised port
> scanning is illegal in many jurisdictions. You are responsible for how you use
> it. `scanme.nmap.org` is a host the Nmap project provides expressly for
> practising scans.

---

## Features

- **TCP connect scan** — no root privileges required.
- **Multithreaded** — scans hundreds of ports concurrently via a thread pool.
- **Banner grabbing** — reads service greetings; sends an HTTP `HEAD` probe to
  web ports and completes a **TLS handshake** for HTTPS ports.
- **Service identification** — maps ports to well-known services and refines the
  guess from the banner.
- **Flexible port selection** — `top`, `all`, ranges (`1-1024`), or lists
  (`22,80,443`).
- **Multiple output formats** — a coloured terminal table or structured JSON.
- **Zero dependencies** — standard library only.
- **Tested** — a pytest suite that exercises the real network path locally.

---

## Installation

```bash
git clone https://github.com/renatoalmeida/network-port-scanner.git
cd network-port-scanner

# Install into a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .
```

This installs the `portscan` command. You can also run it without installing:

```bash
PYTHONPATH=src python -m portscanner scanme.nmap.org
```

---

## Usage

```
portscan TARGET [options]

positional arguments:
  target                hostname or IP address to scan

options:
  -p, --ports PORTS     ports to scan: 'top' (default), 'all',
                        a range '1-1024', or a list '22,80,443'
  -t, --timeout SEC     per-port connection timeout in seconds (default: 1.0)
  -w, --workers N       number of concurrent worker threads (default: 100)
  --no-banner           skip banner grabbing (faster, quieter on the network)
  --json                output results as JSON
  -o, --output FILE     write output to FILE instead of stdout
  -q, --quiet           suppress progress and the legal notice
  --version             show the version and exit
```

### Examples

```bash
# Scan the most common ports (the default)
portscan 192.168.1.1

# Scan the classic well-known range
portscan 192.168.1.1 -p 1-1024

# Scan specific ports and emit JSON for another tool to consume
portscan example.com -p 22,80,443 --json

# Full range, more threads, no banners, saved to a file
portscan 10.0.0.5 -p all -w 500 --no-banner -o report.txt
```

---

## The concepts, explained

The code is written to be read. Here is the theory each part demonstrates.

### 1. Sockets
A **socket** is the operating system's programming interface for network I/O —
one endpoint of a two-way channel. We create a TCP socket with
`socket.socket(AF_INET, SOCK_STREAM)`: `AF_INET` selects IPv4, `SOCK_STREAM`
selects the reliable, ordered, connection-oriented transport, which is TCP.
See [`scanner.py`](src/portscanner/scanner.py).

### 2. TCP/IP and the three-way handshake
Before any data flows, TCP establishes a connection with a **three-way
handshake**:

```
Client            Server
  |----- SYN ------->|      "I'd like to talk"
  |<--- SYN-ACK -----|      "OK, I'm listening"
  |----- ACK ------->|      "Great, connected"
```

A **connect scan** simply asks the OS to complete that handshake
(`connect_ex`). If it succeeds, **the port is open**. If the server replies with
a **RST** (reset) the port is **closed**; if nothing comes back before the
timeout, it is **filtered** (typically by a firewall). This scan needs no
special privileges — a *SYN scan*, which sends a lone SYN and never finishes the
handshake, must craft raw packets and therefore requires root.

### 3. Banner grabbing
When you connect to a service, it often announces itself. SSH, FTP, SMTP, POP3
and IMAP send a greeting immediately, so we just read it. HTTP servers wait to be
asked, so we send a minimal `HEAD / HTTP/1.1` request and read the response
headers (the `Server:` header is gold). For HTTPS we first complete a **TLS
handshake** and then probe the encrypted stream. This is *service/version
detection* — the single most useful signal a scan produces, because knowing
"OpenSSH 6.6.1" is what lets you check it against known vulnerabilities. See
[`banner.py`](src/portscanner/banner.py).

### 4. Concurrency with threads
Scanning is **I/O-bound**: almost all the time is spent *waiting* for the
network, not using the CPU. A naive scan of 1,000 ports with a 1-second timeout
could take many minutes because each port waits in turn. By handing ports to a
**thread pool** (`concurrent.futures.ThreadPoolExecutor`), hundreds of
connections wait *at the same time*, collapsing that to a couple of seconds.
Python's GIL is not a bottleneck here because it is **released while a thread
blocks on a socket**, letting other threads run. See
[`scanner.py`](src/portscanner/scanner.py).

---

## Project structure

```
network-port-scanner/
├── src/portscanner/
│   ├── __init__.py      # package metadata and public API
│   ├── __main__.py      # enables `python -m portscanner`
│   ├── cli.py           # argparse command-line interface
│   ├── scanner.py       # core engine: connect scan + thread pool
│   ├── banner.py        # banner grabbing, TLS, service identification
│   ├── ports.py         # port parsing and well-known service names
│   └── output.py        # table and JSON rendering
├── tests/               # pytest suite
├── pyproject.toml       # packaging + console-script entry point
├── LICENSE              # MIT
└── README.md
```

---

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest
```

The suite spins up a throwaway TCP server on `127.0.0.1`, so it validates the
real handshake-and-banner path without touching any external host.

---

## Roadmap / possible extensions

Ideas for taking this further (each is a good learning exercise):

- **UDP scanning** — connectionless, so it relies on ICMP "port unreachable"
  replies and timeouts.
- **SYN / half-open scan** — using raw sockets (root required); much stealthier.
- **CIDR ranges** — scan `192.168.1.0/24`, not just single hosts (`ipaddress`).
- **Rate limiting** — a `--delay` to be gentler and less detectable.
- **CVE lookup** — cross-reference grabbed banners against a vulnerability feed.
- **IPv6 support** — via `AF_INET6` and `getaddrinfo`.
- **Async rewrite** — an `asyncio` version to compare against the threaded one.

---

## License

Released under the [MIT License](LICENSE).
