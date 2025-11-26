# 🕵️‍♂️ Realistic Credential Traffic Generator for Wireshark Training

> A Python script that generates **19+ protocol flows** with *fake but realistic* usernames/passwords — designed to train analysts in spotting credential exposure, protocol quirks, and attack patterns **in real packet captures**.

---

## 🎯 Why This Exists

In real networks, credentials leak over:
- HTTP POST forms
- Cleartext protocols (FTP, Telnet, SMTP)
- Base64-encoded headers (Basic Auth, NTLM)
- Session tokens (JWT, API keys)

This tool lets you **practice capturing and analyzing these flows** — safely, ethically, and on your own machine.

---

## 🛠️ What It Simulates

| Protocol       | Credential Type Seen | Wireshark Filter Example |
|----------------|----------------------|--------------------------|
| HTTP POST      | `username=admin&password=P@ssw0rd123!` | `http && http.request.method == "POST"` |
| FTP/POP3/Telnet| `USER x\r\nPASS y\r\n` | `tcp contains "PASS "` |
| Basic Auth     | `Authorization: Basic base64(...)` | Right-click → Follow → HTTP Stream |
| SMTP AUTH      | `AUTH PLAIN base64(\0user\0pass)` | `smtp` |
| LDAP           | ASN.1 bind with user/pass | `ldap` |
| MySQL/Postgres | Handshake with username + pass | `mysql || pgsql` |
| NTLM           | Type 3 with domain\user + response | Search `"NTLM "` |
| SMB/RDP/VNC    | Protocol-specific auth | `smb`, `rdp`, `vnc` |
| JWT/API Key    | `Authorization: Bearer ...` or `X-API-Key: ...` | Search `"Bearer "` |

---

## 📥 Get Started

### Prerequisites
- Parrot Linux (or any Linux with Python 3.8+)
- `pip3` installed
- `sudo` access (for raw sockets in some protocols)

### Install
```bash
git clone https://github.com/Evaristus230/wireshark-traffic-simulator
cd wireshark-traffic-simulator
pip3 install -r requirements.txt
sudo python3 enterprise_cred_simulator.py
