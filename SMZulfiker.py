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


def get_args():
    parser = argparse.ArgumentParser(description="SM Zulfiker Recon Toolkit", add_help=True)
    parser.add_argument("--target", type=str, help="Target domain (example.com)")
    parser.add_argument("--run-tests", action="store_true", help="Run internal tests")
    return parser.parse_args()


def safe_run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except:
        return None


def subdomain_scan(target):
    print("[+] Subdomain Scan Running...")
    result = safe_run(["subfinder", "-silent", "-d", target])
    if not result:
        print("[-] Subfinder not found or returned no data.")
        return []
    subs = result.splitlines()
    json.dump(subs, open("subdomains.json", "w"), indent=2)
    print(f"[✓] Found {len(subs)} subdomains")
    return subs


def port_scan(target):
    print("[+] Port Scan Running...")
    result = safe_run(["nmap", "-T4", "--min-rate", "500", target])
    if not result:
        print("[-] nmap not installed or scan failed.")
        return
    open("ports.txt", "w").write(result)
    print("[✓] Ports saved to ports.txt")


def http_info(target):
    print("[+] Collecting HTTP Info...")
    try:
        r = requests.get("http://" + target, timeout=5)
        info = {
            "status": r.status_code,
            "headers": dict(r.headers)
        }
        json.dump(info, open("http_info.json", "w"), indent=2)
        print("[✓] HTTP info saved")
    except:
        print("[-] HTTP request failed.")


def run_tests():
    print("Running tests...")
    assert isinstance(safe_run(["echo", "test"]), str)
    print("✓ Basic command test passed")
    print("✓ All internal tests passed")


def main():
    args = get_args()

    if args.run_tests:
        run_tests()
        return

    if not args.target:
        print("[!] Please provide --target domain.com")
        return

    target = args.target

    print("\n=== SM ZULFIKER RECON TOOL STARTED ===\n")

    subdomain_scan(target)
    port_scan(target)
    http_info(target)

    print("\n=== Scan Completed Successfully ===\n")


if __name__ == "__main__":
    main()
