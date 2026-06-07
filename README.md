# BSK Project — Secure Communication with Trusted Third Party

A three-component system implementing mutual authentication and encrypted communication using RSA 4096, AES-256-GCM, and X.509 certificates.

**Course:** Security of Computer Systems (BSK)  
**Technology:** Python 3.8+

## Architecture

```
┌─────────┐     TCP/IP      ┌─────────┐     TCP/IP      ┌─────────┐
│  User   │ ◄─────────────► │ Server  │ ◄─────────────► │   TTP   │
│ (Client)│                 │ (VM #1) │                 │ (VM #2) │
└─────────┘                 └─────────┘                 └─────────┘
```

- **TTP** — Trusted Third Party: certificate authority + authentication server
- **Server** — Service provider; registers with TTP, offers encrypted echo service
- **Client** — GUI application (tkinter) for users

## Prerequisites

- Python 3.8 or later
- `pip` (Python package manager)

## Setup

```bash
# 1. Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate   # Linux/macOS
# venv\Scripts\activate    # Windows

# 2. Install dependencies
pip install -r requirements.txt
```

## Running the Project

The three components must run simultaneously. Open three terminals.

### Terminal 1 — TTP Server
```bash
source venv/bin/activate
python3 ttp.py
```

### Terminal 2 — Service Server
```bash
source venv/bin/activate
python3 server.py
```

### Terminal 3 — Client GUI
```bash
source venv/bin/activate
python3 client.py
```

## How to Use (Client GUI)

1. Click **Register with TTP** — the client generates RSA keys, registers with TTP, and receives an X.509 certificate. Status indicator turns **orange**.
2. Click **Request Service** — the server initiates mutual authentication via TTP. After successful auth, a session key is delivered to both parties. Status indicator turns **green**.
3. Type a message and press **Enter** or click **Send** — messages are encrypted with AES-256-GCM before transmission. The server echoes them back.
4. Click **Close Session** to end the encrypted session.

## Network Configuration (defaults)

| Component | Host | Port |
|---|---|---|
| TTP | 127.0.0.1 | 4444 |
| Server | 127.0.0.1 | 5555 |

To run on separate machines, edit the address fields in the Client GUI, or change the constants in `common.py` (`TTP_HOST`, `TTP_PORT`, `SERVER_HOST`, `SERVER_PORT`).

## Project Structure

```
├── common.py          — Crypto primitives, protocol helpers (RSA 4096, AES-256-GCM, X.509)
├── ttp.py             — TTP server (registration, CA, auth, session keys)
├── server.py          — Service server (encrypted echo service)
├── client.py          — Client GUI (tkinter)
├── requirements.txt   — Dependencies
├── Doxyfile           — Doxygen configuration for code docs
└── docs/
    ├── report.pdf     — Technical report
    └── report.md      — Report source (Markdown)
```

## Generating Code Documentation

```bash
# Install Doxygen, then:
doxygen Doxyfile
# Open docs/doxygen/html/index.html
```

## Logs

- `ttp.log` — TTP server event log with timestamps
- `server.log` — Server event log with timestamps

## Dependencies

- `cryptography` (>= 41.0) — RSA, AES-GCM, X.509 certificates

## License

University project — Gdansk University of Technology, 2026.
