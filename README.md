# Network Port Scanner

A fast, multithreaded **TCP port scanner** I wrote in pure Python, with
**banner grabbing** for service and version detection. It has zero third-party
dependencies, so it runs anywhere Python 3.8+ is installed.

I built this to really understand the machinery behind tools like `nmap` instead
of just running them. Along the way I got hands-on with **sockets**, the
**TCP/IP handshake**, **banner grabbing**, and **concurrency** with a thread
pool — and I documented what I learned below so the repo doubles as my notes.

```
$ portscan scanme.nmap.org -p 22,80,443,8080

Scan report for scanme.nmap.org (45.33.32.156)
Scanned 4 port(s) in 1.31s — 2 open

PORT      STATE  SERVICE  BANNER
22/tcp    open   ssh      SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
80/tcp    open   http     HTTP/1.1 200 OK (Server: Apache/2.4.7 (Ubuntu))
```

> ⚠️ **Legal notice**
> This tool is for **authorised testing and education only**. Only scan systems
> you **own** or have **explicit written permission** to test — unauthorised
> port scanning is illegal in many places. `scanme.nmap.org`, used in the
> examples, is a host the Nmap project provides specifically for practising.

---

## Features

- **TCP connect scan** — no root privileges required.
- **Multithreaded** — scans hundreds of ports concurrently with a thread pool.
- **Banner grabbing** — reads service greetings; sends an HTTP `HEAD` probe to
  web ports and completes a **TLS handshake** for HTTPS ports.
- **Service identification** — maps ports to well-known services and refines the
  guess from the banner.
- **Flexible port selection** — `top`, `all`, ranges (`1-1024`), or lists
  (`22,80,443`).
- **Two output formats** — a coloured terminal table or structured JSON.
- **Zero dependencies** — standard library only.
- **Tested** — a pytest suite that exercises the real network path locally.

---

## Installation

```bash
git clone https://github.com/Rena24Pt/network-port-scan.git
cd network-port-scan

# I recommend a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .
```

That gives you the `portscan` command. You can also run it without installing:

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

## What I learned building this

I wrote the code to be read, and here is the theory behind each part.

### 1. Sockets
A **socket** is the operating system's interface for network I/O — one endpoint
of a two-way channel. I create a TCP socket with
`socket.socket(AF_INET, SOCK_STREAM)`: `AF_INET` selects IPv4 and `SOCK_STREAM`
selects the reliable, ordered, connection-oriented transport, which is TCP. See
[`scanner.py`](src/portscanner/scanner.py).

### 2. TCP/IP and the three-way handshake
Before any data flows, TCP sets up a connection with a **three-way handshake**:

```
Client            Server
  |----- SYN ------->|      "I'd like to talk"
  |<--- SYN-ACK -----|      "OK, I'm listening"
  |----- ACK ------->|      "Great, connected"
```

My **connect scan** just asks the OS to complete that handshake (`connect_ex`).
If it succeeds, **the port is open**. If the server replies with a **RST**
(reset) the port is **closed**; if nothing comes back before the timeout, it is
**filtered** — usually by a firewall. This scan needs no special privileges,
unlike a *SYN scan*, which sends a lone SYN, never finishes the handshake, and
has to craft raw packets (so it requires root).

### 3. Banner grabbing
When you connect to a service, it often announces itself. SSH, FTP, SMTP, POP3
and IMAP send a greeting straight away, so I just read it. HTTP servers stay
silent until asked, so I send a minimal `HEAD / HTTP/1.1` request and read the
response headers — the `Server:` header is the useful part. For HTTPS I first
complete a **TLS handshake** and then probe the encrypted stream. This is
*service/version detection*, and it's the most valuable thing a scan produces:
knowing "OpenSSH 6.6.1" is exactly what lets you check a host against known
vulnerabilities. See [`banner.py`](src/portscanner/banner.py).

### 4. Concurrency with threads
Scanning is **I/O-bound** — almost all the time is spent *waiting* on the
network, not using the CPU. Scanning 1,000 ports one at a time with a 1-second
timeout could take many minutes. By handing the ports to a **thread pool**
(`concurrent.futures.ThreadPoolExecutor`), hundreds of connections wait *at the
same time*, which collapses that to a couple of seconds. Python's GIL isn't a
problem here because it's **released while a thread is blocked on a socket**, so
the other threads keep working. See [`scanner.py`](src/portscanner/scanner.py).

---

## Project structure

```
network-port-scan/
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

## Roadmap

Things I want to add next — each is a good excuse to learn something new:

- **UDP scanning** — connectionless, so it leans on ICMP "port unreachable"
  replies and timeouts instead of a handshake.
- **SYN / half-open scan** — using raw sockets (root required); much stealthier
  and the natural next step from a connect scan.
- **CIDR ranges** — scan a whole subnet like `192.168.1.0/24` with `ipaddress`.
- **Rate limiting** — a `--delay` flag to be gentler and less detectable.
- **CVE lookup** — cross-reference grabbed banners against a vulnerability feed.
- **IPv6 support** — via `AF_INET6` and `getaddrinfo`.
- **Async rewrite** — an `asyncio` version to compare against the threaded one.

---

## License

Released under the [MIT License](LICENSE).
