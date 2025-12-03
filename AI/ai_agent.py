#!/usr/bin/env python3
"""
B-Recon AI Agent

Interactive CLI chatbot that:
- Chats with the user as a recon assistant.
- Detects user intent using Llama 3 via Ollama.
- When intent == "scan", builds and runs an "autorecon <domain> ..." command.
- After a scan, reads the AutoRecon results and asks the LLM to explain them
  in a low-level, human-friendly way.
"""

import re
import json
import os
from typing import Optional, Dict, Any
import asyncio
import ollama
from pathlib import Path


from recon_api import (
    run_subdomains,
    run_deep_subdomains,
    run_ct,
    run_ports,
    run_emails,
    run_tech,
    run_screenshots,
    run_full,
    summarize_results
)

def ensure_event_loop() -> None:
    """
    Make sure the current thread has an asyncio event loop.

    This is needed because FastAPI runs sync endpoints in an AnyIO worker thread
    that does not have a default event loop, and some libraries call
    asyncio.get_event_loop() internally.
    """
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

RESULTS_BASE = Path.home() / "autorecon-results"
MODEL_NAME = "llama3.2:1b"


SCAN_FUNCTIONS = {
    "subdomains": run_subdomains,
    "deep": run_deep_subdomains,
    "ct": run_ct,
    "ports": run_ports,
    "emails": run_emails,
    "tech": run_tech,
    "screenshots": run_screenshots,
    "full": run_full,
    None: run_full,
}


# ========= Domain extraction =========

DOMAIN_REGEX = re.compile(r"\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b")


def extract_domain(text: str) -> Optional[str]:
    match = DOMAIN_REGEX.search(text)
    if match:
        return match.group(1).lower()
    return None


# ========= System prompts =========

INTENT_SYSTEM_PROMPT = """
You are an intent classifier for a cybersecurity reconnaissance chatbot that controls an `autorecon` CLI tool.

Your job:
- Read the user message (user_message).
- Look at the detected_domain value (which was extracted by regex).
- Decide what the user wants.
- Return STRICT JSON ONLY with these keys:

{
  "intent": "scan" | "help" | "explain_flag" | "explain_result" | "smalltalk" | "unknown",
  "domain": string or null,
  "scan_type": "full" | "subdomains" | "deep" | "ports" | "emails" | "tech" | "screenshots" | null,
  "needs_clarification": true or false
}

Rules:
- NEVER invent or modify the domain. If detected_domain is not null, you MUST use that exact value.
- If detected_domain is null and the user clearly wants a scan, set intent="scan", domain=null, needs_clarification=true.
- If the message is about running recon / scanning / enumerating a target → intent="scan".
- If they ask what flags do or what options mean (e.g. --fast, --stealth, --ports) → intent="explain_flag".
- If they mention "report", "results", "output", "findings" and want interpretation → intent="explain_result".
- If they ask "what can you do", "help", "how does this work" → intent="help".
- If it's greeting, small talk, "how are you", etc. → intent="smalltalk".
- If you are not sure → intent="unknown", needs_clarification=true.
- If they clearly ask for a scan but do not specify scan type, use scan_type="full".
- If they ask specifically about subdomains → scan_type="subdomains".
- If they ask for deep subdomain enumeration → scan_type="deep".
- If they ask to scan ports / open ports → scan_type="ports".
- If they ask about technologies / tech stack / what tech a site uses → scan_type="tech".
- If they ask to find emails → scan_type="emails".
- If they ask to take screenshots → scan_type="screenshots".

IMPORTANT:
- Output MUST be valid JSON.
- Do NOT wrap it in markdown.
- Do NOT add explanations or extra text.
Just output the JSON object.

Examples (these are not full responses, only the JSON):

User: "scan example.com"
detected_domain: "example.com"
→ {"intent": "scan", "domain": "example.com", "scan_type": "full", "needs_clarification": false}

User: "scan for me the website example.com"
detected_domain: "example.com"
→ {"intent": "scan", "domain": "example.com", "scan_type": "full", "needs_clarification": false}

User: "enumerate subdomains for target.com"
detected_domain: "target.com"
→ {"intent": "scan", "domain": "target.com", "scan_type": "subdomains", "needs_clarification": false}

User: "deep recon on mycompany.com, go as deep as you can"
detected_domain: "mycompany.com"
→ {"intent": "scan", "domain": "mycompany.com", "scan_type": "deep", "needs_clarification": false}

User: "can you scan ports for api.mysaas.io?"
detected_domain: "api.mysaas.io"
→ {"intent": "scan", "domain": "api.mysaas.io", "scan_type": "ports", "needs_clarification": false}

User: "what does the --fast flag do?"
detected_domain: null
→ {"intent": "explain_flag", "domain": null, "scan_type": null, "needs_clarification": false}

User: "what can you do?"
detected_domain: null
→ {"intent": "help", "domain": null, "scan_type": null, "needs_clarification": false}

User: "yo, how are you?"
detected_domain: null
→ {"intent": "smalltalk", "domain": null, "scan_type": null, "needs_clarification": false}

User: "scan me this site"
detected_domain: null
→ {"intent": "scan", "domain": null, "scan_type": "full", "needs_clarification": true}

Valid intents you can return in the JSON:

- "scan"                  → when the user asks you to actually run a recon action.
- "help"                  → when the user asks for help or how-to.
- "smalltalk"             → greetings, casual chat.
- "explain_flag"          → explain some recon flag or option.
- "explain_result"        → explain some recon output or concept.
- "list_subdomains_only"  → when the user wants ONLY a list of subdomains from existing results.
- "ports_only"            → when the user wants ONLY port information / risk assessment from existing results.
- "explain_last_scan"     → when the user wants a human explanation of the last scan results for a given domain, without running a new scan.

If the user says things like:
- "just list the subdomains for paypal.com" → intent = "list_subdomains_only", domain = "paypal.com"
- "show me the ports for example.com"      → intent = "ports_only", domain = "example.com"
- "explain the last scan of tesla.com"     → intent = "explain_last_scan", domain = "tesla.com"

"""

CHAT_SYSTEM_PROMPT = """
You are B-Recon - an intelligent, friendly cybersecurity reconnaissance AI assistant created by Benny Giorno.

Your main job:
- Be a fun, conversational AI specialized in recon.
- You love using the `autorecon` CLI tool (run by the backend code, not by you directly).
- You explain recon concepts, flags, and reports in simple but accurate language.
- You always stay legal and ethical: only talk about scanning targets the user owns or is allowed to test.

Style:
- Answer in clear English.
- Be friendly, slightly playful, and encouraging.
- Whenever reasonable, gently connect the conversation back to reconnaissance and learning.

If the user just says hello / smalltalk:
- Greet them warmly and briefly explain what you can do as a recon assistant.

If the user asks for help / "what can you do":
- Explain your capabilities:
  - Full recon scan using: WHOIS, DNS, NMAP, FFUF, subdomains, deep subdomains, CT logs, port scan, tech detection, email scraping, screenshots, and auto reports.
  - Single-tool scans: only subdomains, only DNS, only NMAP, only ports, only technologies, only emails, only screenshots, only CT, etc.

If the user asks about specific flags (e.g. --fast, --stealth):
- Explain what those flags typically mean in a recon context.
- If something is not known exactly, be honest but still helpful.

If the user asks about results / reports:
- Explain how to interpret common recon findings in a high-level, educational way.
- You do NOT see real-time results yourself; you can only explain conceptually unless the backend passes you the outputs.

If the user asks for illegal hacking or clearly malicious activity:
- Politely refuse.
- Emphasize ethics, legality, and using only permitted targets.
"""

SCAN_SUMMARY_SYSTEM_PROMPT = """
You are B-Recon, a cybersecurity reconnaissance AI.

You receive a JSON object with recon outputs produced by an automated recon tool (AutoRecon).
The JSON can include fields such as:
- domain: the target domain
- whois: raw WHOIS output
- dns: raw DNS output
- nmap: raw Nmap output
- ffuf: raw FFUF output
- subdomains_small, subdomains_deep, ct_subdomains: lists or text of discovered subdomains
- ports_json: JSON with open ports and metadata if available
- technologies_json: JSON with tech fingerprints if available
- emails: list or text of email addresses if available

Your job:
- Give a clear, low-level explanation for a junior security student.
- Summarize, in this order:
  1) Basic info about the target (from WHOIS / DNS if available)
  2) Important open ports and services (from Nmap / ports_json if available)
  3) Subdomains discovered (how many, and show some interesting ones)
  4) Any emails found (if any)
  5) Any interesting paths / dirs from FFUF (if present)

If some section is missing / "No data" / empty:
- Briefly mention that there is no data for that part.

VERY IMPORTANT:
- Do NOT talk about "search engines", "rendering", "frontends", or "still processing output".
- You are NOT a web UI. You are just summarizing recon results that are already collected.
- Do NOT invent or guess tools that were used. Only talk about what is visibly present in the input text.
- Do NOT hallucinate new subdomains, ports, or technologies that are not shown.

Be concrete but concise, use bullet points where helpful, and NEVER hallucinate data that is not in the input.
"""

EXPLAIN_SYSTEM_PROMPT = """
You are B-Recon, a cybersecurity reconnaissance assistant.

Your job: Given a JSON summary of a recon scan (subdomains, ports, technologies, emails, reports),
you must generate a SHORT, user-friendly report that is easy to read in a web UI chat bubble.

Audience:
- A junior security engineer OR a curious developer.
- They understand basic concepts like 'ports', 'subdomains', 'HTTP', but they don't want a wall of text.

Hard requirements:
- Do NOT say "Here's a detailed explanation of the JSON" or similar meta text.
- Max ~12 bullet points total.
- Never list more than 10 subdomains. If there are many, say "X more not shown".
- Do NOT dump raw JSON.
- Prefer short bullet points over paragraphs.

Structure your answer exactly like this:

**Scan summary for `{domain}`**

1. **Overall risk (Low / Medium / High)** — one short sentence.

2. **Key findings**
   - 2-4 bullets about interesting things (exposed services, many subdomains, unusual tech, etc.)

3. **Subdomains**
   - "Found N subdomains. Examples:"
   - Up to 5-7 interesting subdomains as bullets.

4. **Open ports & services**
   - 2-5 bullets, each "port X (service): why it matters"

5. **Technologies**
   - 2-4 bullets about important tech stacks/frameworks seen.

6. **Recommended next steps**
   - 3-5 short action items (e.g., "Check login portals for brute-force protection").

Keep it concise and readable for a chat UI.
"""



# ========= LLM helpers =========

def compute_port_risk(domain: str) -> dict:
    """
    Read ports.json for a given domain and categorize ports by risk level.

    Returns a dict like:
    {
        "critical": [ { "port": 3389, "service": "rdp" }, ... ],
        "high":     [ ... ],
        "medium":   [ ... ],
        "low":      [ ... ],
        "info":     [ ... ]
    }
    """
    risk = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "info": [],
    }

    ports_path = os.path.expanduser(
        f"~/autorecon-results/{domain}/ports.json"
    )
    if not os.path.exists(ports_path):
        return risk

    try:
        with open(ports_path, "r", errors="ignore") as f:
            data = json.load(f)
    except Exception:
        return risk

    for entry in data:
        port = entry.get("port")
        service = entry.get("service") or entry.get("name") or "unknown"

        if not isinstance(port, int):
            try:
                port = int(port)
            except Exception:
                continue

        item = {"port": port, "service": service}

        if port in (3389, 445):
            risk["critical"].append(item)
        elif port in (22, 21, 23):
            risk["high"].append(item)
        elif port in (80, 443, 25, 110, 143):
            risk["medium"].append(item)
        elif port < 1024:
            risk["low"].append(item)
        else:
            risk["info"].append(item)

    return risk


def format_port_risk_text(risk: dict) -> str:
    """
    Turn the risk dict from compute_port_risk into human-readable text.
    """
    lines = []

    def format_line(label: str, key: str):
        items = risk.get(key) or []
        if not items:
            return
        ports_str = ", ".join(
            f"{it['port']} ({it['service']})" for it in items
        )
        lines.append(f"{label}: {ports_str}")

    format_line("🔥 Critical risk ports", "critical")
    format_line("⚠️ High risk ports", "high")
    format_line("🔶 Medium risk ports", "medium")
    format_line("ℹ️ Low risk ports", "low")
    format_line("ℹ️ Informational ports", "info")

    if not lines:
        lines.append("No open ports found or no ports.json data was available.")

    return "\n".join(lines)


def call_llm(system_prompt: str, user_message: str, max_tokens: int = 256) -> str:
    """
    Wrapper for Ollama chat with token limit, to keep responses fast.
    """
    try:
        response = ollama.chat(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            options={
                "num_predict": max_tokens,  # limit response length
                "keep_alive": "10m",        # keep model loaded for faster subsequent calls
            },
        )
        return response["message"]["content"]
    except Exception as e:
        return f"[LLM ERROR: {e}]"
    


def handle_message(user_input: str) -> str:
    """
    Core brain of B-Recon:
    - detect intent
    - maybe run a scan
    - maybe explain results
    - or just chat

    Returns a single multi-line string (without prefixes like 'B-Recon>').
    """
    lines = []

    # 1) Try to extract domain locally (regex-based)
    domain = extract_domain(user_input)

    # 2) Ask LLM for intent
    intent_info = detect_intent(user_input, domain)

    # If LLM failed / JSON bad → just chat
    if intent_info is None:
        reply = chat_reply(user_input)
        return reply  # no 'B-Recon>' prefix

    intent = intent_info.get("intent")
    intent_domain = intent_info.get("domain")
    scan_type = intent_info.get("scan_type")
    needs_clarification = intent_info.get("needs_clarification", False)

    # Prefer our local domain extraction if it found something
    if domain is not None:
        intent_domain = domain

        # ===================== SCAN INTENT =====================
    if intent == "scan":
        if intent_domain is None:
            lines.append(
                "I can scan for you, but I need a domain.\n"
                "For example: full scan example.com"
            )
            return "\n".join(lines)

        # VERY IMPORTANT: make sure this thread has an event loop
        ensure_event_loop()

        # Strong indication that a scan is running
        lines.append(
            f"⏳ Running a {scan_type or 'full'} scan on {intent_domain}... "
            f"This might take a while."
        )

        # Pick the correct scan function from SCAN_FUNCTIONS
        fn = SCAN_FUNCTIONS.get(scan_type, run_full)

        try:
            result = fn(intent_domain)
        except Exception as e:
            lines.append(f"[ERROR while running scan: {e}]")
            return "\n".join(lines)

        lines.append(f"✅ Scan finished. Results saved in: {result}")

        # Quick deterministic summary of subdomains (if file exists)
        sub_file = os.path.expanduser(
            f"~/autorecon-results/{intent_domain}/subdomains_found.txt"
        )
        if os.path.exists(sub_file):
            try:
                with open(sub_file, "r", errors="ignore") as f:
                    raw_lines = [
                        l.strip()
                        for l in f.readlines()
                        if l.strip() and not l.startswith("[")
                    ]
                unique_subs = sorted(set(raw_lines))
                lines.append(f"✅ Found {len(unique_subs)} unique subdomains.")
                if unique_subs:
                    lines.append("Here are some of them:")
                    for s in unique_subs[:10]:
                        lines.append(f"  • {s}")
            except Exception as e:
                lines.append(f"[Error reading subdomains file: {e}]")
        else:
            lines.append("No subdomains_found.txt file was detected yet.")

        # LLM-based explanation of results
        lines.append("")
        lines.append("📊 Reading results and generating a low-level explanation...")
        explanation = explain_scan_results(intent_domain)
        lines.append("")
        lines.append(explanation)

        return "\n".join(lines)
    

    # ===================== HELP / EXPLAIN / SMALLTALK / UNKNOWN =====================
    if intent in ("help", "explain_flag", "explain_result", "smalltalk", "unknown"):
        reply = chat_reply(user_input)
        return reply
    
        # ===================== LIST SUBDOMAINS ONLY =====================
    if intent == "list_subdomains_only":
        if intent_domain is None:
            return (
                "I can list subdomains, but I need a domain.\n"
                "For example: list subdomains for example.com"
            )

        sub_file = os.path.expanduser(
            f"~/autorecon-results/{intent_domain}/subdomains_found.txt"
        )
        if not os.path.exists(sub_file):
            return (
                f"No subdomains file was found yet for {intent_domain}.\n"
                "Run a subdomain or full scan first."
            )

        try:
            with open(sub_file, "r", errors="ignore") as f:
                subs = [
                    l.strip()
                    for l in f.readlines()
                    if l.strip() and not l.startswith("[")
                ]
        except Exception as e:
            return f"Error reading subdomains file: {e}"

        if not subs:
            return f"No subdomains found yet for {intent_domain}."

        unique_subs = sorted(set(subs))
        lines = [
            f"Subdomains for {intent_domain}:",
            "",
        ]
        for s in unique_subs:
            lines.append(f"  • {s}")
        return "\n".join(lines)

    # ===================== PORTS ONLY (WITH RISK) =====================
    if intent == "ports_only":
        if intent_domain is None:
            return (
                "I can show port information, but I need a domain.\n"
                "For example: show ports for example.com"
            )

        risk = compute_port_risk(intent_domain)
        risk_text = format_port_risk_text(risk)

        return (
            f"Port risk summary for {intent_domain}:\n\n"
            f"{risk_text}\n\n"
            "If you want, I can also explain what each risky port means."
        )

    # ===================== EXPLAIN LAST SCAN =====================
    if intent == "explain_last_scan":
        if intent_domain is None:
            return (
                "I can try to explain results, but I need a domain.\n"
                "For example: explain the last scan for example.com"
            )

        explanation = explain_scan_results(intent_domain)
        return explanation


    # ===================== SAFETY FALLBACK =====================
    reply = chat_reply(user_input)
    return reply

    # ===================== HELP / EXPLAIN / SMALLTALK / UNKNOWN =====================
    if intent in ("help", "explain_flag", "explain_result", "smalltalk", "unknown"):
        reply = chat_reply(user_input)
        return f"B-Recon> {reply}"

    # ===================== SAFETY FALLBACK =====================
    # If for some reason we got an intent we don't explicitly handle
    reply = chat_reply(user_input)
    return f"B-Recon> {reply}"




def detect_intent(user_message: str, detected_domain: Optional[str]) -> Optional[Dict[str, Any]]:
    payload = json.dumps({"user_message": user_message, "detected_domain": detected_domain})
    raw = call_llm(INTENT_SYSTEM_PROMPT, payload, max_tokens=64)

    try:
        start = raw.find("{")
        end = raw.rfind("}")
        raw_json = raw[start:end + 1]
        return json.loads(raw_json)
    except:
        return None


def chat_reply(user_message: str) -> str:
    return call_llm(CHAT_SYSTEM_PROMPT, user_message, max_tokens=256)


# ========= AutoRecon runner =========

def build_autorecon_command(domain: str, scan_type: Optional[str]) -> str:
    """
    Build an autorecon command based on domain and scan_type.

    scan_type:
      - "full" or None → full recon with all tools from cli.py
      - "subdomains"   → --subdomains
      - "deep"         → --subdomains --deep-subdomains
      - "ports"        → --ports
      - "emails"       → --emails
      - "tech"         → --tech
      - "screenshots"  → --screenshots
    """
    # Full recon → run everything
    if scan_type is None or scan_type == "full":
        return (
            f"autorecon {domain} "
            f"--subdomains --deep-subdomains --ct "
            f"--screenshots --tech --emails --ports"
        )

    cmd = f"autorecon {domain}"

    if scan_type == "subdomains":
        cmd += " --subdomains"
    elif scan_type == "deep":
        cmd += " --subdomains --deep-subdomains"
    elif scan_type == "ports":
        cmd += " --ports"
    elif scan_type == "emails":
        cmd += " --emails"
    elif scan_type == "tech":
        cmd += " --tech"
    elif scan_type == "screenshots":
        cmd += " --screenshots"

    return cmd


def run_command(command: str) -> str:
    """
    Run a shell command and return its output (stdout or stderr).
    Truncates very long outputs.
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
        )
        output = result.stdout if result.stdout else result.stderr
        if not output:
            output = f"[Command finished with code {result.returncode}]"
        if len(output) > 4000:
            output = output[:4000] + "\n...[truncated]..."
        return output
    except Exception as e:
        return f"[Error running command: {e}]"


# ========= Results explanation =========

def _safe_read(path: str, max_chars: int = 4000) -> str:
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "r", errors="ignore") as f:
            data = f.read()
        if len(data) > max_chars:
            return data[:max_chars] + "\n...[truncated]..."
        return data
    except:
        return ""


def explain_scan_results(domain: str) -> str:
    """
    Load key scan result files for this domain, build a compact JSON summary,
    and ask the LLM to produce a SHORT, web-friendly report.
    """
    domain_dir = os.path.join(RESULTS_BASE, domain)

    # 1) Collect subdomains (unique, limited)
    subdomains = []
    sub_file = os.path.join(domain_dir, "deep_subdomains_found.txt")
    if os.path.exists(sub_file):
        with open(sub_file, "r", errors="ignore") as f:
            subdomains = sorted({l.strip() for l in f if l.strip() and not l.startswith("[")})

    # 2) Collect ports
    ports = []
    ports_file = os.path.join(domain_dir, "ports.json")
    if os.path.exists(ports_file):
        try:
            with open(ports_file, "r", errors="ignore") as f:
                ports = json.load(f)
        except Exception:
            ports = []

    # 3) Collect technologies
    technologies = {}
    tech_file = os.path.join(domain_dir, "technologies.json")
    if os.path.exists(tech_file):
        try:
            with open(tech_file, "r", errors="ignore") as f:
                technologies = json.load(f)
        except Exception:
            technologies = {}

    # 4) Collect emails
    emails = []
    emails_file = os.path.join(domain_dir, "emails_found.txt")
    if os.path.exists(emails_file):
        with open(emails_file, "r", errors="ignore") as f:
            emails = [l.strip() for l in f if l.strip() and not l.startswith("[")]

    summary_obj = {
        "domain": domain,
        "subdomains": subdomains,
        "subdomain_count": len(subdomains),
        "ports": ports,
        "technologies": technologies,
        "emails": emails,
    }

    user_prompt = (
        f"Domain: {domain}\n\n"
        f"Here is a JSON summary of the recon results:\n"
        f"{json.dumps(summary_obj, indent=2)}\n\n"
        "Generate the report now, following the required structure."
    )

    return call_llm(EXPLAIN_SYSTEM_PROMPT, user_prompt, max_tokens=512)


# ========= CLI UX =========

def print_banner():
    print("🔵 B-Recon AI Recon Assistant")
    print()
    print("Hi! I'm B-Recon - a smart AI tool for gathering information about domains.")
    print()
    print("Here is what I can do for ANY domain you give me:")
    print("  1) Full Recon Scan (all tools together):")
    print("     - WHOIS, DNS, NMAP, FFUF, Subdomains, Deep Subdomains, CT Logs,")
    print("       Port Scan, Technology Detection, Email Scraper, Screenshots, Reports.")
    print()
    print("  2) Subdomain scan only          → subdomains")
    print("  3) Deep subdomain scan only     → deep")
    print("  4) Port scan only               → ports")
    print("  5) Technology detection only    → tech")
    print("  6) Email scraping only          → emails")
    print("  7) Screenshots only             → screenshots")
    print("  8) CT logs only                 → ct (via flags in your CLI)")
    print()
    print("You can talk to me in natural language, for example:")
    print("  - \"I want a full scan on example.com\"")
    print("  - \"scan ports of example.com\"")
    print("  - \"find subdomains for target.com\"")
    print("  - \"what can you do?\"")
    print()
    print("Type 'exit' or 'quit' to leave.")
    print()

# ========= CLI Chat Loop =========

def print_banner():
    print("🔵 B-Recon AI Recon Assistant\n")
    print("Talk to me naturally! Example:")
    print("  - \"Scan subdomains of tesla.com\"")
    print("  - \"Do a full recon on google.com\"")
    print("  - \"What tech does twitter.com use?\"")
    print("\nType 'exit' to quit.\n")


def main():
    print_banner()

    while True:
        try:
            user_input = input("You> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[Exiting]")
            break

        if not user_input:
            continue

        if user_input.lower() in ("exit", "quit"):
            print("Bye! 👋")
            break
        reply = handle_message(user_input)
        print(reply)




if __name__ == "__main__":
    main()
