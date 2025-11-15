#!/usr/bin/env python3
# SMZulfiker - Live Recon + Report (safe-lite checks)
# Author: SM Zulfiker (BLACK MAFIA COMMANDER)
# NOTE: Use only on targets you are authorized to test.

import argparse, requests, threading, time, sys, socket, random, string, os, re, datetime
from urllib.parse import urljoin, urlparse, parse_qs

# -------- terminal colors ----------
C = "\033[36m"
G = "\033[32m"
Y = "\033[33m"
R = "\033[31m"
M = "\033[35m"
W = "\033[0m"
BOLD = "\033[1m"
RESET = "\033[0m"

# -------- helper: spinner ----------
spinner_run = False
def spinner(text):
    symbols = ["|","/","-","\\"]
    i = 0
    while spinner_run:
        sys.stdout.write(f"\r{C}{text} {symbols[i%4]}{RESET}")
        sys.stdout.flush()
        time.sleep(0.15)
        i += 1
    sys.stdout.write("\r" + " "*(len(text)+6) + "\r")

# -------- util ----------
def now():
    return datetime.datetime.utcnow().isoformat() + "Z"

def save_report(target, lines):
    os.makedirs("reports", exist_ok=True)
    path = os.path.join("reports", f"{target}_report.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path

# -------- reconnaissance functions ----------
def crt_subdomains(domain):
    """collect subdomains from crt.sh (public)"""
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=12)
        arr = r.json()
        subs = set()
        for e in arr:
            name = e.get("name_value", "")
            for line in name.splitlines():
                sub = line.strip()
                if sub:
                    subs.add(sub)
        return sorted(subs)
    except Exception:
        return []

def port_probe(domain, ports=[80,443,21,22,25,3306,8080,8443,8888,53,110]):
    open_ports = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.6)
        try:
            rc = s.connect_ex((domain, p))
            if rc == 0:
                open_ports.append(p)
        except:
            pass
        finally:
            s.close()
    return open_ports

def fetch_http(domain, use_https=True):
    schemes = ["https","http"] if use_https else ["http"]
    for scheme in schemes:
        try:
            url = f"{scheme}://{domain}/"
            r = requests.get(url, timeout=8, allow_redirects=True, headers={"User-Agent":"SMZulfikerRecon/1.0"})
            return r
        except:
            continue
    return None

def check_common_files(domain):
    """check robots, .git, .env, backup.zip, sitemap"""
    items = {
        "robots.txt": "/robots.txt",
        ".git": "/.git/",           # directory listing unlikely; test for 200
        "backup.zip": "/backup.zip",
        ".env": "/.env",
        "sitemap.xml": "/sitemap.xml"
    }
    found = []
    for name, path in items.items():
        url = f"http://{domain}{path}"
        try:
            r = requests.head(url, timeout=6, allow_redirects=True)
            if r.status_code == 200:
                found.append((name, url, r.status_code))
        except:
            pass
    return found

def harvest_links(domain, r):
    """extract links from homepage response r"""
    links = set()
    if not r or not r.text:
        return links
    hrefs = re.findall(r'href=[\'"]?([^\'" >]+)', r.text, flags=re.I)
    for h in hrefs:
        try:
            full = urljoin(r.url, h)
            parsed = urlparse(full)
            if parsed.netloc and domain in parsed.netloc:
                links.add(full)
        except:
            continue
    return sorted(links)

def extract_param_urls(links):
    param_urls = []
    for u in links:
        if "?" in u:
            param_urls.append(u)
    return param_urls

# ------- passive/low-impact checks -------
SQL_ERRORS = ["you have an error in your sql syntax", "mysql_fetch", "syntax error", "unclosed quotation mark", "warning: mysql", "pdoexception"]
def simple_sqli_test(url):
    """append a single quote to each parameter value and look for SQL error patterns"""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return False, None
    for p in qs:
        # build mutated url with param value = original + "'"
        params = qs.copy()
        params[p] = [ (v + "'") if v != "" else ["'"] for v in params[p] ]
        # assemble
        new_q = "&".join([f"{k}={v[0]}" for k,v in params.items()])
        new_url = parsed._replace(query=new_q).geturl()
        try:
            r = requests.get(new_url, timeout=8)
            body = r.text.lower()
            for err in SQL_ERRORS:
                if err in body:
                    return True, new_url
        except:
            continue
    return False, None

def reflection_test(url):
    """send a unique token as value and check if reflected in response (possible XSS candidate).
       This is light active test — only injects a random token."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return False, None
    token = "SMZ_TOKEN_" + "".join(random.choices(string.ascii_letters+string.digits, k=6))
    for p in qs:
        params = qs.copy()
        params[p] = [ token ]
        new_q = "&".join([f"{k}={v[0]}" for k,v in params.items()])
        new_url = parsed._replace(query=new_q).geturl()
        try:
            r = requests.get(new_url, timeout=8)
            if token in r.text:
                return True, new_url
        except:
            continue
    return False, None

def detect_waf(r):
    if not r:
        return None
    headers = {k.lower(): v.lower() for k,v in r.headers.items()}
    wafs = []
    if "server" in headers and "cloudflare" in headers["server"]:
        wafs.append("cloudflare")
    if "cf-ray" in headers:
        wafs.append("cloudflare")
    if "sucuri" in "".join(headers.keys()):
        wafs.append("sucuri")
    if "amazon" in "".join(headers.values()):
        wafs.append("aws")
    return wafs

def find_admin_paths(domain):
    common = ["admin","admin/login","administrator","manage","cpanel","wp-admin","adminpanel","dashboard","login"]
    found = []
    for p in common:
        url = f"http://{domain}/{p}"
        try:
            r = requests.head(url, timeout=5, allow_redirects=True)
            if r.status_code in (200,301,302):
                found.append((p,url,r.status_code))
        except:
            pass
    return found

# ---------- Orchestration & live output ----------
def run_recon(domain):
    report_lines = []
    header = f"=== SMZulfiker LIVE REPORT for {domain} ===\nGenerated: {now()}\n"
    print(BOLD + C + header + RESET)
    report_lines.append(header)

    # 1) Subdomain collection
    global spinner_run
    spinner_run = True
    t = threading.Thread(target=spinner, args=(f"{Y}Collecting subdomains via crt.sh{RESET}",))
    t.start()
    subs = crt_subdomains(domain)
    spinner_run = False
    t.join()
    print(f"{G}[+] Subdomains found: {len(subs)}{RESET}")
    for s in subs[:30]:
        print("  -", s)
    if len(subs) > 30:
        print(f"  ...and {len(subs)-30} more")
    report_lines.append(f"Subdomains: {len(subs)}")
    report_lines += [f" SUB: {s}" for s in subs]

    # 2) Port probe
    spinner_run = True
    t = threading.Thread(target=spinner, args=(f"{Y}Probing common ports{RESET}",))
    t.start()
    open_ports = port_probe(domain)
    spinner_run = False
    t.join()
    print(f"{G}[+] Open ports: {open_ports}{RESET}")
    report_lines.append(f"Open ports: {open_ports}")

    # 3) HTTP fetch root
    spinner_run = True
    t = threading.Thread(target=spinner, args=(f"{Y}Fetching HTTP headers{RESET}",))
    t.start()
    r = fetch_http(domain)
    spinner_run = False
    t.join()
    if r:
        print(f"{G}[+] HTTP {r.status_code} - {r.url}{RESET}")
        for k,v in r.headers.items():
            print(f"   {C}{k}{RESET}: {v}")
        report_lines.append(f"HTTP: {r.status_code} {r.url}")
    else:
        print(f"{R}[-] Could not fetch HTTP root{RESET}")
        report_lines.append("HTTP: no response")

    # WAF detection
    wafs = detect_waf(r)
    if wafs:
        print(f"{M}[!] Possible WAF/proxy detected: {wafs}{RESET}")
        report_lines.append(f"WAF: {wafs}")
    else:
        print(f"{G}[+] No obvious WAF signatures found (heuristic){RESET}")
        report_lines.append("WAF: none-detected")

    # 4) common files
    spinner_run = True
    t = threading.Thread(target=spinner, args=(f"{Y}Checking common files (robots/.git/.env)...{RESET}",))
    t.start()
    found_files = check_common_files(domain)
    spinner_run = False
    t.join()
    if found_files:
        print(f"{R}[!] Interesting files found:{RESET}")
        for name,url,code in found_files:
            print(f"   - {name} -> {url} ({code})")
            report_lines.append(f"File: {name} -> {url} ({code})")
    else:
        print(f"{G}[+] No obvious public files found{RESET}")
        report_lines.append("Files: none")

    # 5) harvest links from homepage
    spinner_run = True
    t = threading.Thread(target=spinner, args=(f"{Y}Harvesting links from homepage{RESET}",))
    t.start()
    links = harvest_links(domain, r)
    spinner_run = False
    t.join()
    print(f"{G}[+] Links harvested: {len(links)}{RESET}")
    for l in links[:30]:
        print("   ", l)
    report_lines.append(f"Harvested links: {len(links)}")

    # 6) param URLs
    param_urls = extract_param_urls(links)
    print(f"{Y}[+] Parameterized URLs found: {len(param_urls)}{RESET}")
    for u in param_urls[:20]:
        print("   -", u)
    report_lines.append(f"Param URLs: {len(param_urls)}")
    report_lines += [f" PARAM: {u}" for u in param_urls]

    # 7) Passive vulnerability checks (light active tests)
    xss_candidates = []
    sqli_candidates = []
    for u in param_urls:
        # reflection test
        refl, refl_url = reflection_test(u)
        if refl:
            xss_candidates.append(refl_url)
            print(f"{R}[POTENTIAL XSS]{RESET} {refl_url}")
            report_lines.append(f"POTENTIAL_XSS: {refl_url}")
        # sqli test
        sqli, sqli_url = simple_sqli_test(u)
        if sqli:
            sqli_candidates.append(sqli_url)
            print(f"{R}[POTENTIAL SQLi]{RESET} {sqli_url}")
            report_lines.append(f"POTENTIAL_SQLI: {sqli_url}")

    if not xss_candidates:
        print(f"{G}[+] No reflected token detections (XSS candidates) found.{RESET}")
    if not sqli_candidates:
        print(f"{G}[+] No SQL error patterns found on tested param URLs.{RESET}")

    # 8) admin paths
    spinner_run = True
    t = threading.Thread(target=spinner, args=(f"{Y}Searching common admin panels{RESET}",))
    t.start()
    admins = find_admin_paths(domain)
    spinner_run = False
    t.join()
    if admins:
        print(f"{R}[!] Admin-like endpoints found:{RESET}")
        for p,u,code in admins:
            print(f"  - {u} ({code})")
            report_lines.append(f"ADMIN: {u} ({code})")
    else:
        print(f"{G}[+] No common admin endpoints found{RESET}")
        report_lines.append("Admin: none")

    # Final summary
    summary = [
        "\n===== SMZulfiker REPORT SUMMARY =====",
        f"Target: {domain}",
        f"Generated: {now()}",
        f"Subdomains: {len(subs)}",
        f"Open ports: {open_ports}",
        f"Harvested links: {len(links)}",
        f"Param URLs: {len(param_urls)}",
        f"XSS candidates: {len(xss_candidates)}",
        f"SQLi candidates: {len(sqli_candidates)}",
        f"Admin endpoints: {len(admins)}",
        f"WAFs: {wafs}",
        "====================================="
    ]
    print(BOLD + "\n".join(summary) + RESET)
    report_lines += summary

    # save report
    path = save_report(domain, report_lines)
    print(f"{G}[+] Report saved: {path}{RESET}")

# ---------------- CLI ----------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SMZulfiker Recon - live + report")
    parser.add_argument("--target", "-t", help="target domain (example.com)", required=True)
    args = parser.parse_args()
    run_recon(args.target)
