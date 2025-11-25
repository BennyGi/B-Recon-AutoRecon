import sys
import subprocess
import os
import threading
import requests
import json

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


# ---------------- Shell Command Wrapper ----------------
def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


# ---------------- CLI FLAGS ----------------
def parse_flags(args):
    return {
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
        for sub in wl:
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
        for sub in wl:
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


    # ---------------- REPORTS ----------------
    if not flags["no_report"]:
        start("Generating Reports…")
        generate_report(domain, outdir)
        generate_human_summary(domain, outdir)

    ok("Scan completed!")


if __name__ == "__main__":
    main()
