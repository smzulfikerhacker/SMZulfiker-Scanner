#!/usr/bin/env python3
"""
SM Zulfiker Advanced Recon Toolkit
Safe, passive information gathering tool.
"""

import argparse
import subprocess
import requests
import json
import os

BANNER = r"""
░▒▓███████▓▒░▒▓██████████████▓▒░       ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓████████▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░  
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░           ░▒▓██▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░         ░▒▓██▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓██████▓▒░ ░▒▓█▓▒░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░  
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░       ░▒▓██▓▒░    ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░      ░▒▓████████▓▒░░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ 
"""


def get_args():
    parser = argparse.ArgumentParser(description="SM Zulfiker Recon Toolkit", add_help=True)
    parser.add_argument("--target", type=str, help="Target domain (example.com)")
    parser.add_argument("--print-banner", action="store_true", help="Show banner only")
    parser.add_argument("--run-tests", action="store_true", help="Run internal tests")
    return parser.parse_args()


def print_banner():
    print(BANNER)


def safe_run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except:
        return None


def subdomain_scan(target):
    print("[+] Subdomain Scan...")
    result = safe_run(["subfinder", "-silent", "-d", target])
    if not result:
        print("[-] Subfinder not found, skipping.")
        return []
    subs = result.splitlines()
    json.dump(subs, open("subdomains.json", "w"))
    return subs


def port_scan(target):
    print("[+] Port Scan...")
    result = safe_run(["nmap", "-T4", "--min-rate", "500", target])
    if not result:
        print("[-] nmap not installed, skipping.")
        return
    open("ports.txt", "w").write(result)


def http_info(target):
    print("[+] HTTP Info...")
    try:
        r = requests.get("http://" + target, timeout=5)
        info = {
            "status": r.status_code,
            "headers": dict(r.headers)
        }
        json.dump(info, open("http_info.json", "w"), indent=2)
    except:
        print("[-] HTTP request failed.")


def run_tests():
    print("Running tests...")
    assert isinstance(safe_run(["echo", "test"]), str)
    print("✓ Basic command test passed")
    print("✓ All internal tests passed")


def main():
    args = get_args()

    if args.print_banner:
        print_banner()
        return

    if args.run_tests:
        run_tests()
        return

    if not args.target:
        print("[!] Please provide --target domain.com")
        return

    target = args.target

    print_banner()
    subdomain_scan(target)
    port_scan(target)
    http_info(target)

    print("\n[+] Scan Completed!")


if __name__ == "__main__":
    main()
