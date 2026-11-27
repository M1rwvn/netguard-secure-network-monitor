# NetGuard — Secure Network Monitor

Flask web app that scans your local subnet via ARP and blocks devices
by injecting ARP spoofing packets with Scapy.

## Setup

```bash
pip install -r requirements.txt
sudo python app.py
```

Open http://localhost:5000

First run creates the `admin` account. Set `NETGUARD_ADMIN_PASSWORD` before starting to choose its password, or let NetGuard generate one and print it once in the terminal:

```bash
NETGUARD_ADMIN_PASSWORD='choose-a-strong-one' sudo -E python app.py
```

There is no fixed default password. Use it only on networks you own or are authorized to test: blocking a device sends ARP spoofing packets to it.

## Secure Programming Concepts

### 1. Authentication (bcrypt)
- Passwords hashed with bcrypt (cost=12) — never stored in plaintext
- Login rate-limited to 10 requests/minute (flask-limiter)
- Session tokens are cryptographically random (secrets.token_bytes)
- Sessions expire after 30 minutes of inactivity
- Session invalidated on logout server-side

### 2. Input Validation & Sanitization
Every API endpoint validates its inputs before any logic runs:
- `/api/scan`   — CIDR regex + ipaddress.ip_network() parse
- `/api/block`  — IP regex (4 octets 0-255) + MAC regex
- `/api/unblock`— MAC regex
- `/api/login`  — username alphanumeric, password length-capped
Malformed input returns 400 with a clear error; nothing proceeds.

### 3. Role-Based Access Control (RBAC)
Two roles enforced by the `@login_required(perm)` decorator:
| Action        | admin | viewer |
|---------------|-------|--------|
| scan          |  ✔    |   ✗    |
| block/unblock |  ✔    |   ✗    |
| view_devices  |  ✔    |   ✔    |
| view_logs     |  ✔    |   ✔    |
Denied actions are logged to the audit trail.

### 4. Encrypted Storage (Fernet, no pickle)
- All persistent data (users, blocked MACs, audit log) stored in `data.enc`
- Encrypted with AES-128-CBC + HMAC-SHA256 via Fernet (cryptography library)
- Encryption key stored in `storage.key` (chmod 600)
- No pickle — pickle can execute arbitrary code on deserialization

### 5. ARP Spoofing (Real, via Scapy)
Blocking a device sends continuous ARP replies to the target:
  Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwsrc=our_mac)
This poisons the target's ARP cache: it thinks the gateway is at our MAC,
so all its traffic is sent to us (and silently dropped).
Runs in a daemon thread every 1.5 seconds until unblocked.

### 6. Audit Logging
Every sensitive action is appended to the encrypted audit log:
- Login success / failure
- Scan start / completion
- Block / unblock events
- Access denied events
Each entry includes: timestamp, level, user, action, detail, source IP.
