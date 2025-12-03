import os
import sys
from datetime import datetime
import subprocess
from typing import Dict, Any, List, Set
import json


PROGRESS_BASE = os.path.expanduser("~/autorecon-results")

def _progress_path(domain: str) -> str:
    domain_dir = os.path.join(PROGRESS_BASE, domain)
    os.makedirs(domain_dir, exist_ok=True)
    return os.path.join(domain_dir, "progress.log")


def init_progress(domain: str) -> None:
    """
    Create/overwrite the progress log for a given domain.
    """
    path = _progress_path(domain)
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(path, "w") as f:
        f.write(f"[{ts}] Starting recon for {domain}\n")


def log_progress(domain: str, message: str) -> None:
    """
    Append a line to the progress log with a timestamp.
    """
    path = _progress_path(domain)
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(path, "a") as f:
        f.write(f"[{ts}] {message}\n")


def read_progress(domain: str) -> list[str]:
    """
    Read all progress lines for a domain (for the /progress API).
    """
    path = _progress_path(domain)
    if not os.path.exists(path):
        return []
    with open(path, "r", errors="ignore") as f:
        return [l.rstrip("\n") for l in f.readlines() if l.strip()]

# ============================
#  INTERNAL HELPERS
# ============================

def _prepare_outdir(domain: str) -> str:
    """
    Create (if needed) and return the output directory for a given domain.
    """
    outdir = os.path.expanduser(f"~/autorecon-results/{domain}")
    os.makedirs(outdir, exist_ok=True)
    return outdir


# ============================
#  PUBLIC API FUNCTIONS
# ============================



def run_subdomains(domain: str) -> str:
    from autorecon import cli as autorecon_cli
    outdir = _prepare_outdir(domain)
    autorecon_cli.scan_subdomains(domain, outdir)
    return f"{outdir}/subdomains_found.txt"


def run_deep_subdomains(domain: str) -> str:
    from autorecon import cli as autorecon_cli
    outdir = _prepare_outdir(domain)
    autorecon_cli.scan_deep_subdomains(domain, outdir)
    return f"{outdir}/deep_subdomains_found.txt"


def run_ct(domain: str) -> str:
    from autorecon import cli as autorecon_cli
    outdir = _prepare_outdir(domain)
    autorecon_cli.scan_ct_logs(domain, outdir)
    return f"{outdir}/ct_subdomains_found.txt"


def run_ports(domain: str):
    from autorecon import cli as autorecon_cli
    outdir = _prepare_outdir(domain)
    return autorecon_cli.run_port_scan(domain, outdir)


def run_tech(domain: str) -> str:
    from autorecon import cli as autorecon_cli
    outdir = _prepare_outdir(domain)
    autorecon_cli.detect_technologies(domain, outdir)
    return f"{outdir}/technologies.json"


def run_emails(domain: str) -> str:
    from autorecon import cli as autorecon_cli
    outdir = _prepare_outdir(domain)
    autorecon_cli.email_scraper(domain, outdir)
    return f"{outdir}/emails_found.txt"


def run_screenshots(domain: str) -> str:
    from autorecon import cli as autorecon_cli
    outdir = _prepare_outdir(domain)
    autorecon_cli.screenshot_all(domain, outdir)
    return f"{outdir}/screenshots"

def run_screenshots_external(domain: str, outdir: str) -> None:
    """
    Run screenshot_all(domain, outdir) in a separate Python process,
    so that it can safely use 'signal' in the main thread.

    This script will be run_screenshots.py located next to recon_api.py.
    """
    script_path = os.path.join(os.path.dirname(__file__), "run_screenshots.py")
    cmd = [sys.executable, script_path, domain, outdir]



    subprocess.run(cmd, cwd=os.path.dirname(__file__), check=False)

def run_core_cli_recon(domain: str, outdir: str, log_func):
    """
    Run the same core steps as 'python3 -m autorecon.cli <domain>'
    without flags: WHOIS, DIG, NMAP, FFUF.

    log_func(domain, msg) should be recon_api.log_progress.
    """
    def run_cmd(cmd: str) -> str:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout

    # WHOIS
    log_func(domain, "WHOIS → START")
    whois_output = run_cmd(f"whois {domain}")
    with open(os.path.join(outdir, "whois.txt"), "w") as f:
        f.write(whois_output)
    log_func(domain, "WHOIS saved")

    # DIG
    log_func(domain, "DIG → START")
    dns_output = run_cmd(f"dig {domain} ANY +noidnout")
    with open(os.path.join(outdir, "dns.txt"), "w") as f:
        f.write(dns_output)
    log_func(domain, "DNS saved")

    # NMAP
    log_func(domain, "NMAP → START")
    nmap_cmd = "nmap -sV --min-rate 500"
    nmap_output = run_cmd(f"{nmap_cmd} {domain}")
    with open(os.path.join(outdir, "nmap.txt"), "w") as f:
        f.write(nmap_output)
    log_func(domain, "NMAP saved")

    # FFUF
    log_func(domain, "FFUF → START")
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    ffuf_cmd = f"ffuf -u http://{domain}/FUZZ -w {wordlist} -mc 200,301,302 -t 40"
    ffuf_output = run_cmd(ffuf_cmd)
    with open(os.path.join(outdir, "ffuf.txt"), "w") as f:
        f.write(ffuf_output)
    log_func(domain, "FFUF saved")


def run_full(domain: str) -> str:
    from autorecon import cli as autorecon_cli

    outdir = _prepare_outdir(domain)

    # ===  progress log ===
    init_progress(domain)
    log_progress(domain, "Starting FULL recon pipeline.")
    log_progress(domain, f"Output directory: {outdir}")

    # Step 1: Core scan (WHOIS, DNS, NMAP, FFUF)
    log_progress(domain, "Step 1/9: Core scan (WHOIS/DNS/NMAP/FFUF) started.")
    run_core_cli_recon(domain, outdir, log_progress)
    log_progress(domain, "Step 1/9: Core scan (WHOIS/DNS/NMAP/FFUF) finished.")

    # Step 2: Subdomains (small)
    log_progress(domain, "Step 2/9: Subdomains scan started.")
    autorecon_cli.scan_subdomains(domain, outdir)
    log_progress(domain, "Step 2/9: Subdomains scan finished.")

    # Step 3: Deep subdomains
    log_progress(domain, "Step 3/9: Deep subdomains scan started.")
    autorecon_cli.scan_deep_subdomains(domain, outdir)
    log_progress(domain, "Step 3/9: Deep subdomains scan finished.")

    # Step 4: CT logs
    log_progress(domain, "Step 4/9: CT logs collection started.")
    autorecon_cli.scan_ct_logs(domain, outdir)
    log_progress(domain, "Step 4/9: CT logs collection finished.")

    # Step 5: Technology detection (Wappalyzer-style)
    log_progress(domain, "Step 5/9: Technology detection started.")
    autorecon_cli.detect_technologies(domain, outdir)
    log_progress(domain, "Step 5/9: Technology detection finished.")

    # Step 6: Email scraping
    log_progress(domain, "Step 6/9: Email scraping started.")
    autorecon_cli.email_scraper(domain, outdir)
    log_progress(domain, "Step 6/9: Email scraping finished.")

    # Step 7: Port scan (with banners, TLS, etc.)
    log_progress(domain, "Step 7/9: Port scan started.")
    autorecon_cli.run_port_scan(domain, outdir)
    log_progress(domain, "Step 7/9: Port scan finished.")

    # Step 8: Screenshotsי
    log_progress(domain, "Step 8/9: Screenshot capture (external) started.")
    try:
        run_screenshots_external(domain, outdir)
        log_progress(domain, "Step 8/9: Screenshot capture (external) finished.")
    except Exception as e:
        log_progress(domain, f"Step 8/9: Screenshot capture FAILED: {e}")

    # Step 9: Reports (technical + human + HTML)
    log_progress(domain, "Step 9/9: Report generation started.")
    autorecon_cli.generate_report(domain, outdir)
    log_progress(domain, "Technical report generated.")
    autorecon_cli.generate_human_summary(domain, outdir)
    log_progress(domain, "Human summary generated.")
    autorecon_cli.generate_html_report(domain, outdir)
    log_progress(domain, "HTML report generated.")
    log_progress(domain, "FULL recon pipeline completed successfully.")

    return outdir




# set of ports considered "high risk" for alerting purposes
HIGH_RISK_PORTS = {
    21,   # FTP
    22,   # SSH
    23,   # Telnet
    25,   # SMTP
    80,   # HTTP
    110,  # POP3
    139,  # NetBIOS
    143,  # IMAP
    445,  # SMB
    3306, # MySQL
    3389, # RDP
    5432, # PostgreSQL
    5900, # VNC
}


def _read_lines_if_exists(path: str) -> List[str]:
    """Read non-empty stripped lines from a file if it exists."""
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def _load_json_if_exists(path: str):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return None


def summarize_results(domain: str) -> Dict[str, Any]:
    """
    Build a structured summary of recon results for the given domain.

    Returns a dict like:
    {
        "domain": "tesla.com",
        "outdir": "/home/kali/autorecon-results/tesla.com",
        "subdomains_total": 27,
        "subdomains_sample": [...],
        "open_ports": [80, 443],
        "high_risk_ports": [80],
        "emails_total": 1,
        "emails_sample": [...],
        "technologies_total": 10,
        "technologies_sample": [...],
        "reports": {
            "technical_report": "/path/report.md" (or None),
            "human_summary": "/path/executive_summary.txt" (or None),
            "html_report": "/path/report.html" (or None),
        },
        "risks": [
            "Port 80 (HTTP) is open – unencrypted web traffic.",
            "Login / auth portals found on subdomains: auth.tesla.com, accounts.tesla.com"
        ],
    }
    """
    outdir = _prepare_outdir(domain)

    summary: Dict[str, Any] = {
        "domain": domain,
        "outdir": outdir,
        "subdomains_total": 0,
        "subdomains_sample": [],
        "open_ports": [],
        "high_risk_ports": [],
        "emails_total": 0,
        "emails_sample": [],
        "technologies_total": 0,
        "technologies_sample": [],
        "reports": {
            "technical_report": None,
            "human_summary": None,
            "html_report": None,
        },
        "risks": [],
    }

    # ---------- Subdomains ----------
    sub_file = os.path.join(outdir, "subdomains_found.txt")
    deep_file = os.path.join(outdir, "deep_subdomains_found.txt")
    ct_file = os.path.join(outdir, "ct_subdomains.txt")

    subdomains: Set[str] = set()
    for path in (sub_file, deep_file, ct_file):
        subdomains.update(_read_lines_if_exists(path))

    subdomains_list = sorted(subdomains)
    summary["subdomains_total"] = len(subdomains_list)
    summary["subdomains_sample"] = subdomains_list[:10]  

    # ---------- Ports ----------
    ports_path = os.path.join(outdir, "ports.json")
    ports_json = _load_json_if_exists(ports_path)
    open_ports: List[int] = []

    if isinstance(ports_json, list):
        #  [{"port": 80, "service": "http", ...}, ...]
        for item in ports_json:
            if not isinstance(item, dict):
                continue
            p = item.get("port") or item.get("port_number") or item.get("portnum")
            try:
                if p is not None:
                    open_ports.append(int(p))
            except (ValueError, TypeError):
                continue
    elif isinstance(ports_json, dict):
        # {"ports": [...]}
        maybe_list = ports_json.get("ports")
        if isinstance(maybe_list, list):
            for item in maybe_list:
                if not isinstance(item, dict):
                    continue
                p = item.get("port") or item.get("port_number") or item.get("portnum")
                try:
                    if p is not None:
                        open_ports.append(int(p))
                except (ValueError, TypeError):
                    continue

    open_ports = sorted(set(open_ports))
    summary["open_ports"] = open_ports
    summary["high_risk_ports"] = [p for p in open_ports if p in HIGH_RISK_PORTS]

    # ---------- Emails ----------
    emails_path = os.path.join(outdir, "emails_found.txt")
    emails_list = _read_lines_if_exists(emails_path)
    summary["emails_total"] = len(emails_list)
    summary["emails_sample"] = emails_list[:10]

    # ---------- Technologies ----------
    tech_path = os.path.join(outdir, "technologies.json")
    tech_json = _load_json_if_exists(tech_path)

    tech_names: List[str] = []
    if isinstance(tech_json, list):
        
        for t in tech_json:
            if isinstance(t, str):
                tech_names.append(t)
            elif isinstance(t, dict):
                name = t.get("name") or t.get("technology") or t.get("title")
                if isinstance(name, str):
                    tech_names.append(name)
    elif isinstance(tech_json, dict):
        
        maybe_list = tech_json.get("technologies") or tech_json.get("items")
        if isinstance(maybe_list, list):
            for t in maybe_list:
                if isinstance(t, str):
                    tech_names.append(t)
                elif isinstance(t, dict):
                    name = t.get("name") or t.get("technology") or t.get("title")
                    if isinstance(name, str):
                        tech_names.append(name)

    tech_names = sorted(set(tech_names))
    summary["technologies_total"] = len(tech_names)
    summary["technologies_sample"] = tech_names[:10]

    # ---------- Reports paths ----------
    tech_report = os.path.join(outdir, "report.md")
    human_summary = os.path.join(outdir, "executive_summary.txt")
    html_report = os.path.join(outdir, "report.html")

    if os.path.exists(tech_report):
        summary["reports"]["technical_report"] = tech_report
    if os.path.exists(human_summary):
        summary["reports"]["human_summary"] = human_summary
    if os.path.exists(html_report):
        summary["reports"]["html_report"] = html_report

    # ---------- Risk hints ----------
    risks: List[str] = []

    if 80 in open_ports:
        risks.append("Port 80 (HTTP) is open – unencrypted web traffic.")
    if 443 in open_ports:
        risks.append("Port 443 (HTTPS) is open – standard secure web traffic.")
    if 22 in open_ports:
        risks.append("SSH (port 22) is open – check for brute-force exposure and key management.")
    if 3389 in open_ports:
        risks.append("RDP (port 3389) is open – high-value target for remote desktop attacks.")
    if 445 in open_ports:
        risks.append("SMB (port 445) is open – historically exploited in many worms (e.g., EternalBlue).")

    login_like = [s for s in subdomains_list if any(
        kw in s.lower() for kw in ("auth.", "login.", "accounts.", "sso.")
    )]
    if login_like:
        risks.append(
            "Login / auth portals found on subdomains: " +
            ", ".join(login_like[:5]) +
            ("..." if len(login_like) > 5 else "")
        )

    summary["risks"] = risks

    return summary


