#!/usr/bin/env python3
"""
Enterprise-Grade Credential Traffic Simulator
For Wireshark training — generates realistic, multi-protocol login attempts.
✅ Safe | ✅ Fake data only | ✅ Lab-ready | ✅ No real auth
"""

import time
import random
import socket
import base64
import hashlib
import hmac
import json
import requests
import subprocess
import ssl
import sys

# ---- 🧠 Smart Fake Data Generators ----

FIRST_NAMES = ["John", "Jane", "Michael", "Sarah", "David", "Emma", "Robert", "Lisa", "chidubem", "Admin"]
LAST_NAMES = ["Smith", "Doe", "Johnson", "Williams", "Brown", "Davis", "Miller", "Wilson"]
DOMAINS = ["company.local", "corp.net", "example.com", "hr.internal", "dev.lan"]
EMAIL_PROVIDERS = ["gmail.com", "outlook.com", "yahoo.com"]
COMMON_ROLES = ["admin", "user", "svc_backup", "webapp", "monitoring", "jenkins", "guest", "test"]
WEAK_PASSWORDS = [
    "password", "123456", "welcome", "qwerty", "letmein", "P@ssw0rd", "admin123",
    "Summer2024!", "CompanyPass2025", "iloveyou", "Password1!", "changeme"
]
MEDIUM_PASSWORDS = [
    "SecurePass!2024", "MyP@ss1234", "CloudAdmin#99", "BackupUser_2025",
    "DBUser!Mar2024", "WebPortal$Access", "InternalApp@Key"
]

def gen_username():
    style = random.choice([
        "{first}.{last}", "{first}{last_initial}", "{role}", "{first}_{last}",
        "{first}{num}", "{last}{num}", "{initials}{num}"
    ])
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES)
    role = random.choice(COMMON_ROLES)
    num = random.randint(1, 99)
    initials = f"{first[0]}{last[0]}".lower()
    return style.format(
        first=first.lower(), last=last.lower(), last_initial=last[0].lower(),
        role=role, num=num, initials=initials
    ).replace(" ", "")

def gen_password():
    if random.random() < 0.4:
        return random.choice(WEAK_PASSWORDS)
    elif random.random() < 0.7:
        return random.choice(MEDIUM_PASSWORDS)
    else:
        # Slightly stronger fake (but still crackable pattern)
        suf = random.choice(["!", "@", "#"]) + str(random.randint(2020, 2026))
        base = random.choice(["Pass", "Secure", "Login", "User", "Admin"])
        return base + suf

def gen_email(user):
    if "@" in user:
        return user
    domain = random.choice(EMAIL_PROVIDERS + DOMAINS[:2])
    return f"{user}@{domain}"

# ---- 📡 Protocol Simulators ----

def simulate_http_post_login():
    user = gen_username()
    pwd = gen_password()
    payload = {
        "username": user,
        "password": pwd,
        "csrf_token": hashlib.md5(str(time.time()).encode()).hexdigest()[:16]
    }
    try:
        r = requests.post("https://httpbin.org/post", data=payload, timeout=5)
        print(f"[HTTP POST] {user} / {pwd}")
    except:
        pass

def simulate_basic_auth():
    user = gen_username()
    pwd = gen_password()
    token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
    headers = {"Authorization": f"Basic {token}"}
    try:
        requests.get("https://httpbin.org/hidden-basic-auth/user/pass", headers=headers, timeout=5)
        print(f"[BASIC AUTH] {user}:{pwd} → Base64({token[:12]}...)")
    except:
        pass

def simulate_digest_auth():
    # Simulate client-side Digest response (no real auth — just traffic)
    user = gen_username()
    pwd = gen_password()
    realm = "Secure Area"
    nonce = "5ccc1d0a0a5a4d2"
    uri = "/admin"
    method = "GET"
    # Fake HA1 = MD5(user:realm:pwd)
    ha1 = hashlib.md5(f"{user}:{realm}:{pwd}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    auth_header = (
        f'Digest username="{user}", realm="{realm}", nonce="{nonce}", '
        f'uri="{uri}", response="{response}"'
    )
    print(f"[DIGEST AUTH] {user} → challenge-response (HA1 fake)")
    # Send to dummy endpoint
    try:
        requests.get("https://httpbin.org/digest-auth/auth/user/pass", 
                     headers={"Authorization": auth_header}, timeout=5)
    except:
        pass

def simulate_ftp():
    user = gen_username()
    pwd = gen_password()
    try:
        s = socket.create_connection(("127.0.0.1", 21), timeout=2)
        s.recv(1024)  # banner
        s.send(f"USER {user}\r\n".encode())
        s.recv(1024)
        s.send(f"PASS {pwd}\r\n".encode())
        s.recv(1024)
        s.close()
        print(f"[FTP] USER {user} / PASS {pwd}")
    except:
        print(f"[FTP] Attempt: {user} / {pwd} (no server — visible in Wireshark!)")

def simulate_telnet():
    user = gen_username()
    pwd = gen_password()
    try:
        s = socket.create_connection(("127.0.0.1", 23), timeout=2)
        time.sleep(0.3)
        s.send(f"{user}\r\n".encode())
        time.sleep(0.5)
        s.send(f"{pwd}\r\n".encode())
        time.sleep(0.2)
        s.send(b"exit\r\n")
        s.close()
        print(f"[TELNET] {user} / {pwd} (cleartext stream)")
    except:
        pass

def simulate_smtp_auth_plain():
    user = gen_email(gen_username())
    pwd = gen_password()
    auth_plain = f"\x00{user}\x00{pwd}"
    b64 = base64.b64encode(auth_plain.encode()).decode()
    try:
        s = socket.create_connection(("127.0.0.1", 25), timeout=2)
        s.recv(1024)
        s.send(b"EHLO client\r\n")
        s.recv(1024)
        s.send(f"AUTH PLAIN {b64}\r\n".encode())
        s.recv(1024)
        s.close()
        print(f"[SMTP PLAIN] {user} / {pwd} (Base64: {b64[:16]}...)")
    except:
        pass

def simulate_ldap_bind():
    # Simulate LDAP Simple Bind (cleartext)
    user = f"cn={gen_username()},ou=users,dc=company,dc=local"
    pwd = gen_password()
    # LDAP ASN.1 bind request is complex — we send a minimal fake one
    # Wireshark will flag it as LDAP if port 389 used
    try:
        s = socket.create_connection(("127.0.0.1", 389), timeout=2)
        # Send simple bind request (hand-crafted minimal LDAP packet)
        bind_req = (
            b'\x30\x25\x02\x01\x01\x60\x20\x02\x01\x03\x04\x15' +
            user.encode() + b'\x80\x04' + pwd.encode()
        )
        s.send(bind_req)
        s.close()
        print(f"[LDAP BIND] {user} / {pwd}")
    except:
        pass

def simulate_mysql_handshake():
    # Simulate client response to MySQL auth (pre-8.0 native password)
    user = gen_username()
    pwd = gen_password()
    try:
        s = socket.create_connection(("127.0.0.1", 3306), timeout=2)
        # Skip server greeting — just send fake auth packet
        # Format: \x85\xa2 + max_packet + \x00 + cap_flags + \x00*23 + user + \x00 + len(pass) + pass
        auth = (
            b'\x85\xa2\x00\x00\x00\x01\x8d\xa6\xff\x07\x00\x00\x00\x01\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
            user.encode() + b'\x00' + bytes([len(pwd)]) + pwd.encode()
        )
        s.send(auth)
        s.close()
        print(f"[MYSQL AUTH] {user} / {pwd}")
    except:
        pass

def simulate_postgresql_startup():
    user = gen_username()
    pwd = gen_password()
    try:
        s = socket.create_connection(("127.0.0.1", 5432), timeout=2)
        # Startup message
        startup = b'\x00\x00\x00\x54\x00\x03\x00\x00' + \
                  b'user\x00' + user.encode() + b'\x00' + \
                  b'database\x00postgres\x00\x00'
        s.send(startup)
        time.sleep(0.2)
        # Fake password message
        pwd_msg = b'p\x00\x00\x00' + bytes([len(pwd)+5]) + b'\x00' + pwd.encode() + b'\x00'
        s.send(pwd_msg)
        s.close()
        print(f"[POSTGRES AUTH] {user} / {pwd}")
    except:
        pass

def simulate_ntlm_type1_type3():
    # Simulate NTLM auth (e.g., HTTP or SMB) — just headers for visibility
    user = gen_username()
    domain = random.choice(DOMAINS).upper()
    pwd = gen_password()
    # Type 1: Negotiate
    type1 = "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAKAGFKAAAADw=="
    # Type 3 (fake, but structurally plausible)
    # We'll encode user\domain\workstation + fake challenge response
    ntlm_resp = base64.b64encode(
        f"{user.upper()}".encode() + b'\x00'*40
    ).decode()[:40]
    type3 = f"NTLM TlRMTVNTUAADAAAAGAAYAFIAAAAYABgAYgAAABIAEgBwAAAADAAMAIQAAAAWABYAkgAAAAAAAABIAAAABYKIogUBKAoAAAAP{ntlm_resp}"
    print(f"[NTLM AUTH] {domain}\\{user} → Type3 (fake response)")
    # Send via HTTP
    try:
        requests.get("https://httpbin.org/headers", 
                     headers={"Authorization": type3}, timeout=5)
    except:
        pass

def simulate_jwt_auth():
    user = gen_username()
    # Fake JWT: header.payload.signature (all fake but valid format)
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b'=')
    payload = base64.urlsafe_b64encode(
        json.dumps({
            "sub": user,
            "role": random.choice(["user", "admin", "guest"]),
            "exp": int(time.time()) + 3600
        }).encode()
    ).rstrip(b'=')
    signature = base64.urlsafe_b64encode(b"fake-signature-256bits").rstrip(b'=')
    token = f"{header.decode()}.{payload.decode()}.{signature.decode()}"
    try:
        requests.get("https://httpbin.org/bearer", 
                     headers={"Authorization": f"Bearer {token}"}, timeout=5)
        print(f"[JWT] Bearer token for {user} (inspect payload in Wireshark!)")
    except:
        pass

def simulate_api_key():
    user = gen_username()
    key = "ak_" + hashlib.sha1(f"{user}{time.time()}".encode()).hexdigest()[:24]
    try:
        requests.get("https://httpbin.org/get", 
                     headers={"X-API-Key": key}, timeout=5)
        print(f"[API KEY] {user} → {key[:12]}...")
    except:
        pass

def simulate_smb_login_attempt():
    # Simulate raw SMB2 SESSION_SETUP request (minimal)
    user = gen_username()
    domain = random.choice(DOMAINS).upper()
    pwd = gen_password()
    try:
        s = socket.create_connection(("127.0.0.1", 445), timeout=2)
        # Fake SMB2 header + SESSION_SETUP
        smb2_header = b'\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        s.send(smb2_header + f"{domain}\\{user}".encode() + b'\x00' + pwd.encode())
        s.close()
        print(f"[SMB LOGIN] {domain}\\{user} / {pwd} (port 445)")
    except:
        pass

def simulate_rdp_client_info():
    # Simulate RDP client sending username (early in handshake)
    user = gen_username()
    try:
        s = socket.create_connection(("127.0.0.1", 3389), timeout=2)
        # Send fake X.224 Connection Request + early MCS with username
        rdp_conn = b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00Cookie: mstshash=' + user.encode()
        s.send(rdp_conn)
        s.close()
        print(f"[RDP] Client hash: mstshash={user} (visible in TLS ClientHello if unencrypted)")
    except:
        pass

def simulate_vnc_auth():
    # RFB protocol: after version, send auth response (fake)
    pwd = gen_password()[:8].ljust(8, '\x00')  # VNC pads to 8 bytes
    try:
        s = socket.create_connection(("127.0.0.1", 5900), timeout=2)
        s.send(b'RFB 003.008\n')
        time.sleep(0.1)
        s.recv(12)  # version echo
        s.send(b'\x01')  # auth type: VNC Auth
        time.sleep(0.1)
        s.recv(16)  # challenge
        # Fake response (not real DES, but looks right length)
        s.send(b'\x00'*16)  # fake response
        s.close()
        print(f"[VNC AUTH] Attempt with 8-char password (e.g., '{pwd.strip()}')")
    except:
        pass

def simulate_imap_login():
    tag = "A001"
    user = gen_email(gen_username())
    pwd = gen_password()
    try:
        s = socket.create_connection(("127.0.0.1", 143), timeout=2)
        s.recv(1024)  # banner
        s.send(f"{tag} LOGIN {user} {pwd}\r\n".encode())
        s.recv(1024)
        s.close()
        print(f"[IMAP LOGIN] {user} / {pwd}")
    except:
        pass

def simulate_pop3_login():
    user = gen_username()
    pwd = gen_password()
    try:
        s = socket.create_connection(("127.0.0.1", 110), timeout=2)
        s.recv(1024)
        s.send(f"USER {user}\r\n".encode())
        s.recv(1024)
        s.send(f"PASS {pwd}\r\n".encode())
        s.recv(1024)
        s.close()
        print(f"[POP3] USER {user} / PASS {pwd}")
    except:
        pass

def simulate_redis_auth():
    pwd = gen_password()
    try:
        s = socket.create_connection(("127.0.0.1", 6379), timeout=2)
        s.send(f"AUTH {pwd}\r\n".encode())
        s.recv(1024)
        s.close()
        print(f"[REDIS AUTH] {pwd}")
    except:
        pass

def simulate_mongodb_handshake():
    # MongoDB SCRAM-SHA1 — simulate client first message
    user = gen_username()
    pwd = gen_password()
    nonce = base64.b64encode(random.randbytes(24)).decode()[:24]
    # saslStart payload (fake but structured)
    payload = base64.b64encode(f"n={user},r={nonce}".encode()).decode()
    try:
        s = socket.create_connection(("127.0.0.1", 27017), timeout=2)
        # Minimal OP_MSG with SASL payload
        msg = b'\x00\x00\x00\x80\x00\x00\x00\x00\x01\x00\x00\x00\xdd\x07\x00\x00\x00\x00\x00\x00' + \
              b'saslStart\x00\x01\x00\x00\x00mechanism\x00\x0c\x00\x00\x00SCRAM-SHA-1\x00' + \
              f'payload\x00{len(payload)+5}\x00\x02\x00\x00\x00{payload}\x00'.encode()
        s.send(msg)
        s.close()
        print(f"[MONGODB SCRAM] {user} (nonce: {nonce[:8]}...)")
    except:
        pass

# Register all actions
ACTIONS = [
    simulate_http_post_login,
    simulate_basic_auth,
    simulate_digest_auth,
    simulate_ftp,
    simulate_telnet,
    simulate_smtp_auth_plain,
    simulate_ldap_bind,
    simulate_mysql_handshake,
    simulate_postgresql_startup,
    simulate_ntlm_type1_type3,
    simulate_jwt_auth,
    simulate_api_key,
    simulate_smb_login_attempt,
    simulate_rdp_client_info,
    simulate_vnc_auth,
    simulate_imap_login,
    simulate_pop3_login,
    simulate_redis_auth,
    simulate_mongodb_handshake,
]

# ---- 🔄 Main Loop ----

print("🔐 Enterprise Credential Traffic Simulator (v2.0)")
print("🎯 19 protocols | Realistic usernames/passwords | Safe for Wireshark")
print("💡 Tip: In Wireshark, try:")
print("   - `http contains \"password\"`")
print("   - `tcp contains \"PASS \"`")
print("   - `ldap` | `smtp` | `ftp` | `mysql`")
print("   - Follow TCP streams to see full conversations\n")

while True:
    # Pick 3–6 random flows per cycle
    cycle = random.sample(ACTIONS, k=random.randint(3, 6))
    for action in cycle:
        try:
            action()
        except Exception as e:
            print(f"[!] Error in {action.__name__}: {e}")
        time.sleep(random.uniform(0.8, 2.5))
    
    # Human-like break
    wait = random.randint(30, 90)
    print(f"⏸️  User idle ({wait}s) — background services may still chatter...\n")
    time.sleep(wait)
