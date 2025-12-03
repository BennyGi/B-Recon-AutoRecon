#!/usr/bin/env python3

import sys
import os


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: run_screenshots.py <domain> <outdir>", file=sys.stderr)
        return 1

    domain = sys.argv[1]
    outdir = sys.argv[2]
    outdir = os.path.abspath(outdir)

    project_dir = os.path.dirname(__file__)
    os.chdir(project_dir)

    from autorecon import cli as autorecon_cli
    from recon_api import log_progress  

    print(f"[*] [run_screenshots.py] Starting screenshot_all for {domain} -> {outdir}")
    log_progress(domain, "[run_screenshots] screenshot_all started in external process.")

    try:
        autorecon_cli.screenshot_all(domain, outdir)
    except Exception as e:
        msg = f"[run_screenshots] screenshot_all FAILED: {e}"
        print(f"[!] {msg}", file=sys.stderr)
        log_progress(domain, msg)
        return 1

    print(f"[+] [run_screenshots.py] Screenshot capture finished.")
    log_progress(domain, "[run_screenshots] screenshot_all finished successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
