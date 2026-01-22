#!/usr/bin/env python3
"""
SMTP user enumeration helper
- Tries VRFY, EXPN, and RCPT TO techniques
- Nice, decoded output + clear statuses
- Works with single user (-u) or a list (-U)
"""

import argparse
import socket
import sys
from typing import List, Tuple

def recv_all(sock: socket.socket, bufsize: int = 4096, timeout: float = 2.0) -> bytes:
    sock.settimeout(timeout)
    chunks = []
    try:
        while True:
            part = sock.recv(bufsize)
            if not part:
                break
            chunks.append(part)
            if len(part) < bufsize:
                break
    except socket.timeout:
        pass
    except Exception:
        pass
    return b"".join(chunks)

def sendline(sock: socket.socket, line: bytes) -> bytes:
    if not line.endswith(b"\r\n"):
        line += b"\r\n"
    sock.sendall(line)
    return recv_all(sock)

def decode(b: bytes) -> str:
    try:
        return b.decode("utf-8", errors="ignore").strip()
    except Exception:
        return repr(b)

def connect(host: str, port: int, timeout: float) -> Tuple[socket.socket, str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    banner = decode(recv_all(s))
    return s, banner

def ehlo_or_helo(sock: socket.socket, helo_name: str) -> None:
    resp = sendline(sock, b"EHLO " + helo_name.encode())
    text = decode(resp)
    if not text.startswith("250"):
        # Fallback to HELO
        resp = sendline(sock, b"HELO " + helo_name.encode())
        text = decode(resp)
    print(f"[+] EHLO/HELO response:\n{text}\n")

def try_vrfy(sock: socket.socket, user: str) -> str:
    resp = sendline(sock, b"VRFY " + user.encode())
    return decode(resp)

def try_expn(sock: socket.socket, user: str) -> str:
    resp = sendline(sock, b"EXPN " + user.encode())
    return decode(resp)

def try_rcpt(sock: socket.socket, user: str, domain: str, mail_from: str) -> str:
    # Minimal SMTP transaction for RCPT TO enumeration
    sendline(sock, b"RSET")  # reset any state
    sendline(sock, b"MAIL FROM:<" + mail_from.encode() + b">")
    # Some servers reply with multi-line 250; we don't need to parse it deeply
    recv_all(sock)
    rcpt = f"<{user}@{domain}>" if domain else f"<{user}>"
    resp = sendline(sock, b"RCPT TO:" + rcpt.encode())
    return decode(resp)

def classify(code_line: str) -> str:
    """
    Rough classification based on reply code.
    250/251 -> likely exists/accepted
    550/551/553 -> user unknown/relaying denied
    252 -> cannot VRFY but will accept (indeterminate)
    500/502/504 -> command not recognized/disabled
    """
    if not code_line:
        return "no response"
    try:
        code = int(code_line[:3])
    except Exception:
        return "unknown"
    if code in (250, 251):
        return "accepted (likely exists)"
    if code in (550, 551, 553):
        return "rejected (unknown/denied)"
    if code == 252:
        return "cannot verify (indeterminate)"
    if code in (500, 502, 504, 521):
        return "command unsupported/disabled"
    if 400 <= code < 500:
        return "temp failure"
    return "other"

def enumerate_user(host: str, port: int, timeout: float, helo_name: str,
                   user: str, domain: str, mail_from: str) -> dict:
    res = {"user": user}
    try:
        s, banner = connect(host, port, timeout)
        print(f"[+] Connected: {banner}\n")
        ehlo_or_helo(s, helo_name)

        vrfy = try_vrfy(s, user)
        res["VRFY_raw"] = vrfy
        res["VRFY"] = classify(vrfy)

        expn = try_expn(s, user)
        res["EXPN_raw"] = expn
        res["EXPN"] = classify(expn)

        rcpt = try_rcpt(s, user, domain, mail_from)
        res["RCPT_raw"] = rcpt
        res["RCPT"] = classify(rcpt)

        sendline(s, b"QUIT")
        s.close()
    except (ConnectionRefusedError, TimeoutError, socket.timeout) as e:
        res["error"] = f"connection error: {e}"
    except Exception as e:
        res["error"] = f"unexpected error: {e}"
    return res

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SMTP user enumeration via VRFY/EXPN/RCPT")
    p.add_argument("-t", "--target", required=True, help="Target IP/host")
    p.add_argument("-p", "--port", type=int, default=25, help="Port (default: 25)")
    p.add_argument("-u", "--user", help="Single username")
    p.add_argument("-U", "--userlist", help="File with usernames (one per line)")
    p.add_argument("-d", "--domain", default="", help="Domain for RCPT TO (optional)")
    p.add_argument("--from", dest="mail_from", default="probe@localhost",
                   help="MAIL FROM address used for RCPT (default: probe@localhost)")
    p.add_argument("--helo", default="scanner.local", help="HELO/EHLO name (default: scanner.local)")
    p.add_argument("--timeout", type=float, default=5.0, help="Socket timeout seconds (default: 5)")
    return p.parse_args()

def load_users(args: argparse.Namespace) -> List[str]:
    users: List[str] = []
    if args.user:
        users.append(args.user.strip())
    if args.userlist:
        with open(args.userlist, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    users.append(line)
    if not users:
        print("[-] Provide -u USER or -U USERLIST", file=sys.stderr)
        sys.exit(1)
    return users

def main():
    args = parse_args()
    users = load_users(args)

    print(f"[i] Target: {args.target}:{args.port}")
    if args.domain:
        print(f"[i] Using domain for RCPT TO: {args.domain}")
    print(f"[i] MAIL FROM: {args.mail_from}\n")

    for u in users:
        print(f"=== Testing user: {u} ===")
        r = enumerate_user(
            host=args.target,
            port=args.port,
            timeout=args.timeout,
            helo_name=args.helo,
            user=u,
            domain=args.domain,
            mail_from=args.mail_from,
        )

        if "error" in r:
            print(f"  ERROR: {r['error']}\n")
            continue

        print(f"  VRFY -> {r['VRFY']}\n    {r['VRFY_raw']}")
        print(f"  EXPN -> {r['EXPN']}\n    {r['EXPN_raw']}")
        print(f"  RCPT -> {r['RCPT']}\n    {r['RCPT_raw']}\n")

if __name__ == "__main__":
    main()
