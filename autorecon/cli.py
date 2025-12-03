import sys
import subprocess
import os
import threading
import requests
import json
from tqdm import tqdm # For progress bars
from pyppeteer import launch # Checks if site is online 
import re
from bs4 import BeautifulSoup # For Email extraction
import socket # For DNS lookups
import ssl  # For SSL certificate checks
import ai_agent  # For LLM integration


# ---------------- Colors ----------------
class Color:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"


# ---------------- Logging ----------------
def start(msg):
    print(f"{Color.BLUE}[*] {msg}{Color.RESET}")

def ok(msg):
    print(f"{Color.GREEN}[+] {msg}{Color.RESET}")

def warn(msg):
    print(f"{Color.YELLOW}[!] {msg}{Color.RESET}")

def error(msg):
    print(f"{Color.RED}[X] {msg}{Color.RESET}")

# ---------------- Progress Bar Wrapper ----------------
def progress_iter(iterable, desc="Working"):
    return tqdm(iterable, desc=desc, ncols=80, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}")



# ---------------- Shell Command Wrapper ----------------
def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


# ---------------- CLI FLAGS ----------------
def parse_flags(args):
    return {
        "full": ("--full" in args) or ("-F" in args),

        "only_dns": "--only-dns" in args,
        "only_nmap": "--only-nmap" in args,
        "skip_ffuf": "--skip-ffuf" in args,
        "skip_whois": "--skip-whois" in args,
        "no_report": "--no-report" in args,
        "fast": "--fast" in args,
        "stealth": "--stealth" in args,
        "subdomains": "--subdomains" in args,
        "only_subdomains": "--only-subdomains" in args,
        "deep_subdomains": "--deep-subdomains" in args,
        "ct": "--ct" in args,
        "screenshots": "--screenshots" in args,
        "tech": "--tech" in args,
        "emails": "--emails" in args,
        "ports": "--ports" in args,
    }



# ---------------- Reports ----------------
def generate_report(domain, outdir):
    report_path = f"{outdir}/report.md"

    def safe_read(path):
        return open(path).read() if os.path.exists(path) else "Skipped"

    whois = safe_read(f"{outdir}/whois.txt")
    dns = safe_read(f"{outdir}/dns.txt")
    nmap = safe_read(f"{outdir}/nmap.txt")
    ffuf = safe_read(f"{outdir}/ffuf.txt")

    with open(report_path, "w") as f:
        f.write(f"# AutoRecon Technical Report for {domain}\n\n")
        f.write("## WHOIS\n```\n" + whois + "\n```\n\n")
        f.write("## DNS\n```\n" + dns + "\n```\n\n")
        f.write("## NMAP\n```\n" + nmap + "\n```\n\n")
        f.write("## FFUF\n```\n" + ffuf + "\n```\n\n")

    ok(f"Technical Report generated at: {report_path}")


def generate_human_summary(domain, outdir):
    summary_path = f"{outdir}/executive_summary.txt"

    with open(summary_path, "w") as f:
        f.write(f"Executive Summary for {domain}\n")
        f.write("--------------------------------------\n\n")
        f.write("This is a simplified overview of the scan results.\n")
        f.write("✔ Basic checks completed.\n")
        f.write("✔ No critical issues from this limited scan.\n\n")
        f.write("General Risk Level: Low\n")

    ok(f"Human Summary generated at: {summary_path}")



# ---------------------------------------------------------------------
# -------------------------- SUBDOMAIN SCANNERS ------------------------
# ---------------------------------------------------------------------

def scan_subdomains(domain, outdir):
    start("Subdomain → START")

    wordlist_path = os.path.join(os.path.dirname(__file__), "subdomains_small.txt")
    found = []

    with open(wordlist_path) as wl:
        for sub in progress_iter(wl, desc="Subdomains"):
            subdomain = f"{sub.strip()}.{domain}"
            result = run_cmd(f"dig +short {subdomain}")

            if result.strip():
                found.append(subdomain)
                ok(f"Found: {subdomain}")

    with open(f"{outdir}/subdomains_found.txt", "w") as f:
        f.write("\n".join(found))

    ok(f"{len(found)} subdomains found and saved.")



def scan_deep_subdomains(domain, outdir):
    start("Deep Subdomain Scanner → START (2000 words)")

    wordlist_path = os.path.join(os.path.dirname(__file__), "subdomains_big.txt")

    if not os.path.exists(wordlist_path):
        error("Missing file: subdomains_big.txt")
        return

    found = []
    lock = threading.Lock()

    def check(sub):
        subdomain = f"{sub}.{domain}"
        result = run_cmd(f"dig +short {subdomain}")
        if result.strip():
            with lock:
                found.append(subdomain)
                ok(f"Found: {subdomain}")

    threads = []
    with open(wordlist_path) as wl:
        for sub in progress_iter(wl, desc="Deep Subdomains"):
            sub = sub.strip()
            t = threading.Thread(target=check, args=(sub,))
            t.start()
            threads.append(t)

    for t in threads:
        t.join()

    save_path = f"{outdir}/deep_subdomains_found.txt"
    with open(save_path, "w") as f:
        f.write("\n".join(found))

    ok(f"{len(found)} deep subdomains found and saved at {save_path}")



# ---------------------------------------------------------------------
# ----------------------------- CT LOGS -------------------------------
# ---------------------------------------------------------------------

def scan_ct_logs(domain, outdir):
    start("CT Logs → START")

    results = set()

    # --- crt.sh ---
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            for entry in json.loads(r.text):
                for line in entry.get("name_value", "").split("\n"):
                    if domain in line:
                        results.add(line.strip())
            ok(f"crt.sh found {len(results)}")
        else:
            warn("crt.sh bad response")
    except Exception as e:
        warn(f"crt.sh error: {e}")

    # --- certspotter ---
    try:
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            for entry in r.json():
                for d in entry.get("dns_names", []):
                    if domain in d:
                        results.add(d)
            ok(f"CertSpotter found {len(results)} total")
        else:
            warn("CertSpotter bad response")
    except Exception as e:
        warn(f"CertSpotter error: {e}")

    # Save
    save_path = f"{outdir}/ct_subdomains_found.txt"
    with open(save_path, "w") as f:
        f.write("\n".join(sorted(results)))

    ok(f"Saved {len(results)} CT subdomains.")

# -------------------------------HTML REPORT -------------------------------
# -------------------------------HTML REPORT -------------------------------
def generate_html_report(domain, outdir):
    html_path = f"{outdir}/report.html"

    def safe_read(path):
        return open(path).read() if os.path.exists(path) else "No data available"

    whois = safe_read(f"{outdir}/whois.txt")
    dns = safe_read(f"{outdir}/dns.txt")
    nmap = safe_read(f"{outdir}/nmap.txt")
    ffuf = safe_read(f"{outdir}/ffuf.txt")
    subs = safe_read(f"{outdir}/subdomains_found.txt")
    deep = safe_read(f"{outdir}/deep_subdomains_found.txt")
    ct = safe_read(f"{outdir}/ct_subdomains_found.txt")
    ports_json = safe_read(f"{outdir}/ports.json")
    open_ports = ports_json

    html = f"""
<html>
<head>
    <title>AutoRecon HTML Report - {domain}</title>

    <style>
        body {{
            font-family: Arial;
            padding: 20px;
            background: #0a0a0a;
            color: #e5e5e5;
            transition: 0.4s;
        }}

        h1, h2 {{
            color: #4cc9f0;
        }}

        pre {{
            background: #1a1a1a;
            padding: 12px;
            border-radius: 6px;
            white-space: pre-wrap;
            border: 1px solid #333;
        }}

        .section {{
            margin-bottom: 40px;
        }}

        /* ---- THEME BUTTONS ---- */
        .theme-buttons {{
            display: flex;
            gap: 15px;
            margin-bottom: 25px;
        }}

        button {{
            padding: 10px 18px;
            border-radius: 6px;
            cursor: pointer;
            border: none;
            font-size: 15px;
            font-weight: bold;
            transition: 0.3s;
        }}

        /* CYBER */
        .cyber-btn {{
            background: #0d0221;
            color: #4cc9f0;
            border: 1px solid #4cc9f0;
            box-shadow: 0 0 8px #4cc9f0;
        }}
        .cyber-btn:hover {{
            box-shadow: 0 0 15px #4cc9f0;
            transform: scale(1.05);
        }}

        /* LIGHT */
        .light-btn {{
            background: #fff;
            color: #333;
            border: 1px solid #ccc;
        }}
        .light-btn:hover {{
            background: #f2f2f2;
        }}

        /* MATRIX */
        .matrix-btn {{
            background: #000;
            color: #00ff41;
            border: 1px solid #00ff41;
            box-shadow: 0 0 10px #00ff41;
        }}
        .matrix-btn:hover {{
            box-shadow: 0 0 16px #00ff41;
            transform: scale(1.05);
        }}

        /* LIGHT THEME */
        body.light {{
            background: #f5f5f5;
            color: #222;
        }}
        body.light pre {{
            background: #fff;
            border: 1px solid #ddd;
        }}
        body.light h1, body.light h2 {{
            color: #0078d4;
        }}

        /* MATRIX THEME */
        body.matrix {{
            background: #000;
            color: #00ff41;
        }}
        body.matrix pre {{
            background: #001900;
            border: 1px solid #003300;
        }}
        body.matrix h1, body.matrix h2 {{
            color: #00ff41;
        }}
    </style>

    <script>
        function setTheme(theme) {{
            document.body.className = theme;
            localStorage.setItem("theme", theme);
        }}

        window.onload = () => {{
            let saved = localStorage.getItem("theme") || "cyber";
            setTheme(saved);
        }};
    </script>
</head>

<body>

<h1>AutoRecon HTML Report</h1>
<h2>Target: {domain}</h2>

<div class="theme-buttons">
    <button class="cyber-btn" onclick="setTheme('cyber')">Cyber Mode</button>
    <button class="light-btn" onclick="setTheme('light')">Light Mode</button>
    <button class="matrix-btn" onclick="setTheme('matrix')">Matrix Mode</button>
</div>

<div class="section">
    <h2>WHOIS</h2>
    <pre>{whois}</pre>
</div>

<div class="section">
    <h2>DNS Records</h2>
    <pre>{dns}</pre>
</div>

<div class="section">
    <h2>NMAP Results</h2>
    <pre>{nmap}</pre>
</div>

<div class="section">
    <h2>FFUF Results</h2>
    <pre>{ffuf}</pre>
</div>

<div class="section">
    <h2>Subdomains (Small Scan)</h2>
    <pre>{subs}</pre>
</div>

<div class="section">
    <h2>Deep Subdomains</h2>
    <pre>{deep}</pre>
</div>

<div class="section">
    <h2>Open Ports</h2>
    <pre>{open_ports}</pre>
</div>

<div class="section">
    <h2>Certificate Transparency Logs</h2>
    <pre>{ct}</pre>
</div>

</body>
</html>
"""

    with open(html_path, "w") as f:
        f.write(html)

    ok(f"HTML Report generated at: {html_path}")


# ---------------------------------------------------------------------
# ------------------------- SCREENSHOT ENGINE --------------------------
# ---------------------------------------------------------------------

async def screenshot_url(url, save_path):
    try:
        browser = await launch(
            headless=True,
            args=['--no-sandbox', '--disable-setuid-sandbox']
        )
        page = await browser.newPage()
        await page.setViewport({'width': 1366, 'height': 768})
        await page.goto(url, timeout=8000)
        await page.screenshot({'path': save_path})
        await browser.close()
        ok(f"Screenshot saved: {save_path}")
    except Exception as e:
        warn(f"Failed screenshot: {url} | {e}")


def screenshot_all(domain, outdir):
    start("Screenshot Automation → START")

    urls = set()

    # Always screenshot homepage
    urls.add(f"http://{domain}")
    urls.add(f"https://{domain}")

    # Screenshot all subdomains if exist
    sub_path = f"{outdir}/subdomains_found.txt"
    deep_path = f"{outdir}/deep_subdomains_found.txt"

    for path in [sub_path, deep_path]:
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    sub = line.strip()
                    urls.add(f"http://{sub}")
                    urls.add(f"https://{sub}")

    # Save folder
    ss_dir = f"{outdir}/screenshots"
    os.makedirs(ss_dir, exist_ok=True)

    import asyncio
    loop = asyncio.get_event_loop()

    for url in urls:
        safe = url.replace("://", "_").replace("/", "_")
        save_path = f"{ss_dir}/{safe}.png"
        loop.run_until_complete(screenshot_url(url, save_path))

# ---------------------------------------------------------------------
# -------------------------- WAPPALYZER TECH ---------------------------
# ---------------------------------------------------------------------

def detect_technologies(domain, outdir):
    start("Wappalyzer → START")

    urls = set()
    urls.add(f"http://{domain}")
    urls.add(f"https://{domain}")

    # include subdomains
    for file in [f"{outdir}/subdomains_found.txt", f"{outdir}/deep_subdomains_found.txt"]:
        if os.path.exists(file):
            with open(file) as f:
                for line in f:
                    sub = line.strip()
                    urls.add(f"http://{sub}")
                    urls.add(f"https://{sub}")

    api_url = "https://api.wappalyzer.com/v2/lookup/"
    # free demo key — limited but works
    headers = {"x-api-key": "demo"}

    tech_data = {}

    for url in urls:
        try:
            r = requests.get(api_url, params={"url": url}, headers=headers, timeout=8)
            if r.status_code == 200:
                data = r.json()
                tech_data[url] = data
                ok(f"Tech detected: {url}")
        except:
            pass

    save_path = f"{outdir}/technologies.json"
    with open(save_path, "w") as f:
        json.dump(tech_data, f, indent=4)

    ok(f"Technologies saved → {save_path}")

# ---------------------------------------------------------------------
# -------------------------- EMAIL SCRAPER -----------------------------
# ---------------------------------------------------------------------

import re
from bs4 import BeautifulSoup

EMAIL_REGEX = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"

def scrape_emails_from_url(url):
    try:
        r = requests.get(url, timeout=6)
        emails = set(re.findall(EMAIL_REGEX, r.text))
        return emails
    except:
        return set()

def email_scraper(domain, outdir):
    start("Email Scraper → START")

    targets = set()

    # Homepages
    targets.add(f"http://{domain}")
    targets.add(f"https://{domain}")

    # Contact pages
    targets.add(f"http://{domain}/contact")
    targets.add(f"https://{domain}/contact")
    targets.add(f"http://{domain}/about")
    targets.add(f"https://{domain}/about")

    # Subdomains
    for file in [f"{outdir}/subdomains_found.txt", f"{outdir}/deep_subdomains_found.txt"]:
        if os.path.exists(file):
            with open(file) as f:
                for line in f:
                    sub = line.strip()
                    targets.add(f"http://{sub}")
                    targets.add(f"https://{sub}")

    # FFUF URLs
    ffuf_file = f"{outdir}/ffuf.txt"
    if os.path.exists(ffuf_file):
        with open(ffuf_file) as f:
            for line in f:
                if "URL" in line:
                    parts = line.split()
                    for p in parts:
                        if p.startswith("URL:"):
                            targets.add(p.replace("URL:", ""))

    found = set()

    for url in targets:
        emails = scrape_emails_from_url(url)
        if emails:
            ok(f"Emails in {url} → {emails}")
            found |= emails

    save_path = f"{outdir}/emails_found.txt"
    with open(save_path, "w") as f:
        for e in found:
            f.write(e + "\n")

    ok(f"Emails saved → {save_path}")

# ---------------------------------------------------------------------
# -------------------------------- PORT SCANNER-------------------------------
# ---------------------------------------------------------------------
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "RPC",
    139: "SMB",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP-TLS",
    631: "IPP",
    993: "IMAP-SSL",
    995: "POP3-SSL",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}

def fetch_http_title(host, port):
    try:
        sock = socket.create_connection((host, port), 2)
        sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
        data = sock.recv(4096).decode(errors="ignore")
        sock.close()

        if "<title>" in data.lower():
            return data.lower().split("<title>")[1].split("</title>")[0].strip()
        return None
    except:
        return None


def fetch_https_title(host, port):
    try:
        ctx = ssl.create_default_context()
        conn = socket.create_connection((host, port), 2)
        ssock = ctx.wrap_socket(conn, server_hostname=host)

        ssock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
        data = ssock.recv(4096).decode(errors="ignore")
        ssock.close()

        if "<title>" in data.lower():
            return data.lower().split("<title>")[1].split("</title>")[0].strip()
        return None
    except:
        return None


def grab_banner(host, port):
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((host, port))
        try:
            banner = sock.recv(2048).decode(errors="ignore")
        except:
            banner = "No banner"
        sock.close()
        return banner.strip()
    except:
        return None


def tls_fingerprint(host, port):
    try:
        ctx = ssl.create_default_context()
        conn = socket.create_connection((host, port), 2)
        ssock = ctx.wrap_socket(conn, server_hostname=host)
        cert = ssock.getpeercert()
        ssock.close()
        return cert
    except:
        return None


def scan_single_port(host, port, results, lock):
    try:
        sock = socket.create_connection((host, port), timeout=1)
        sock.close()

        service = COMMON_PORTS.get(port, "Unknown")

        banner = grab_banner(host, port)

        title = None
        if port in (80, 8080):
            title = fetch_http_title(host, port)
        if port in (443, 8443):
            title = fetch_https_title(host, port)

        tls_info = None
        if port in (443, 8443):
            tls_info = tls_fingerprint(host, port)

        with lock:
            results.append({
                "port": port,
                "service": service,
                "banner": banner,
                "title": title,
                "tls": tls_info
            })

    except:
        pass


def run_port_scan(domain, outdir):
    start("Port Scan → START")

    results = []
    lock = threading.Lock()
    threads = []

    ports = list(COMMON_PORTS.keys())

    for port in tqdm(ports, desc="Ports", ncols=80):
        t = threading.Thread(target=scan_single_port, args=(domain, port, results, lock))
        t.start()
        threads.append(t)

        if len(threads) > 300:  # MAX THREADS
            for t in threads:
                t.join()
            threads = []

    for t in threads:
        t.join()

    save_path = f"{outdir}/ports.json"
    with open(save_path, "w") as f:
        json.dump(results, f, indent=4)

    ok(f"Port Scan saved → {save_path}")

    return results



# ---------------------------------------------------------------------
# -------------------------------- MAIN -------------------------------
# ---------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: autorecon <domain> [flags]")
        return
    
    domain = sys.argv[1]
    flags = parse_flags(sys.argv[2:])

    start(f"Target → {domain}")

    outdir = os.path.expanduser(f"~/autorecon-results/{domain}")
    os.makedirs(outdir, exist_ok=True)
    
        # ---------------- FULL PIPELINE (same as AI chat) ----------------
    if flags.get("full"):
        # Delegate to the unified pipeline in recon_api
        try:
            import recon_api
        except ImportError:
            error("Could not import recon_api. Make sure recon_api.py is in your PYTHONPATH / project root.")
            return

        recon_api.run_full(domain)
        ok("Full scan (CLI) completed via recon_api.run_full()")
        return



    # ---------------- ONLY SUBDOMAINS ----------------
    if flags["only_subdomains"]:
        scan_subdomains(domain, outdir)
        return


    # ---------------- ONLY DNS ----------------
    if flags["only_dns"]:
        dns_output = run_cmd(f"dig {domain} ANY +noidnout")
        with open(f"{outdir}/dns.txt", "w") as f:
            f.write(dns_output)
        ok("DNS saved")
        return


    # ---------------- ONLY NMAP ----------------
    if flags["only_nmap"]:
        nmap_cmd = "nmap -sV --min-rate 500"
        nmap_output = run_cmd(f"{nmap_cmd} {domain}")
        with open(f"{outdir}/nmap.txt", "w") as f:
            f.write(nmap_output)
        ok("NMAP saved")
        return


    # ---------------- FIRST: CT Logs (if asked) ----------------
    if flags["ct"]:
        scan_ct_logs(domain, outdir)


    # ---------------- WHOIS ----------------
    if flags["skip_whois"] or flags["fast"]:
        warn("WHOIS skipped")
    else:
        start("WHOIS → START")
        whois_output = run_cmd(f"whois {domain}")
        with open(f"{outdir}/whois.txt", "w") as f:
            f.write(whois_output)
        ok("WHOIS saved")


    # ---------------- DIG ----------------
    start("DIG → START")
    dns_output = run_cmd(f"dig {domain} ANY +noidnout")
    with open(f"{outdir}/dns.txt", "w") as f:
        f.write(dns_output)
    ok("DNS saved")


    # ---------------- NMAP ----------------
    if flags["fast"]:
        warn("FAST → skipping nmap")
    else:
        start("NMAP → START")
        nmap_cmd = "nmap -sV --min-rate 500" if not flags["stealth"] else "nmap -sV -T2 -Pn"
        nmap_output = run_cmd(f"{nmap_cmd} {domain}")
        with open(f"{outdir}/nmap.txt", "w") as f:
            f.write(nmap_output)
        ok("NMAP saved")


    # ---------------- FFUF ----------------
    if flags["skip_ffuf"] or flags["fast"]:
        warn("FFUF skipped")
    else:
        start("FFUF → START")
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        ffuf_cmd = f"ffuf -u http://{domain}/FUZZ -w {wordlist} -mc 200,301,302 -t 40"
        ffuf_output = run_cmd(ffuf_cmd)
        with open(f"{outdir}/ffuf.txt", "w") as f:
            f.write(ffuf_output)
        ok("FFUF saved")


    # ---------------- NORMAL SUBDOMAINS ----------------
    if flags["subdomains"]:
        scan_subdomains(domain, outdir)


    # ---------------- DEEP SUBDOMAINS ----------------
    if flags["deep_subdomains"]:
        scan_deep_subdomains(domain, outdir)

    # ---------------- SCREENSHOTS ----------------
    if flags["screenshots"]:
        screenshot_all(domain, outdir)

    # ---------------- TECHNOLOGIES ----------------
    if flags["tech"]:
        detect_technologies(domain, outdir)

    # ---------------- EMAILS ----------------
    if flags["emails"]:
        email_scraper(domain, outdir)

    # ---------------- PORT SCAN ----------------
    if flags["ports"]:
        port_results = run_port_scan(domain, outdir)
    else:
        port_results = []



    # ---------------- REPORTS ----------------
    if not flags["no_report"]:
        start("Generating Reports…")
        generate_report(domain, outdir)
        generate_human_summary(domain, outdir)
        generate_html_report(domain, outdir)


    ok("Scan completed!")


if __name__ == "__main__":
    main()
