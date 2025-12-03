🚀 B-Recon
AI-Powered Reconnaissance Toolkit (CLI + Web Chat Assistant)

B-Recon began as a simple Python recon script and evolved into a complete recon platform:

✅ Classic CLI Recon (fast, scriptable, no AI required)

🤖 AI Web Chat Assistant (FastAPI + Ollama) that explains results like a “Security GPT”

Give it a domain → it performs full recon → the AI interprets the results for you.

🔎 Features
1. Classic Recon CLI (cli.py)

A fully automated recon pipeline:

🌐 Subdomain enumeration

🔎 Deep subdomain brute force

🔏 Certificate Transparency (CT) logs

🧠 Tech stack fingerprinting

🔢 Port scanning

📧 Email scraping

📸 Screenshots (optional)

📄 Report generation:

Technical (report.md)

Executive summary (executive_summary.txt)

HTML report (report.html)

Results saved under:

autorecon-results/<domain>/

2. B-Recon AI Chat (FastAPI + Ollama)

A modern web chat interface that:

Talks to an LLM via Ollama

Parses natural commands like:

“Do a full recon on tesla.com”

“Explain port 3389”

Decides autonomously:

When to run a real scan

When to answer from knowledge

Reads recon output files and explains them like a cybersecurity analyst

Shows live scan progress

Provides download links for reports

Live progress example:

Step 1/8: Subdomains scan started
Step 2/8: Deep subdomains scan...
...
FULL recon pipeline completed successfully

🗂 Project Structure
.
├── autorecon/
│   ├── cli.py               # Classic recon pipeline
│   ├── ...                  # Subdomain/ports/tech/screenshot modules
├── ai_agent.py              # LLM logic + intent detection + report explanations
├── api/
│   ├── ask_ai.py            # FastAPI backend (AI, progress, downloads)
├── templates/
│   ├── chat.html            # Web chat UI (HTML + inline JS/CSS)
├── autorecon-results/       # All scan output (per domain)
├── requirements.txt
├── commands.txt
└── README.md

📦 Requirements
System

Linux (tested on Kali)

Python 3.11+

External tools:

nmap

ffuf

curl, wget

Optional

Playwright / Chromium for screenshots

Headless browser environment

Python packages

(Full list in requirements.txt)

fastapi, uvicorn

requests

tqdm

ollama

jinja2

pydantic

LLM

Install Ollama

Pull a model:

ollama pull llama3.2:1b


Make sure the model name matches the one in ai_agent.py.

⚙️ Installation
git clone <your-repo-url> b-recon
cd b-recon

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt


Install required tools:

sudo apt update
sudo apt install -y nmap ffuf


Start Ollama:

ollama serve

🖥️ Using the Classic CLI
Full recon
python autorecon/cli.py full tesla.com

Only subdomains
python autorecon/cli.py subdomains tesla.com

Only ports
python autorecon/cli.py ports tesla.com

Help
python autorecon/cli.py -h

💬 Using the AI Chat Interface
Start the backend
uvicorn api.ask_ai:app --host 0.0.0.0 --port 8000 --reload

Open the chat UI
http://127.0.0.1:8000/chat/

Try example prompts:

Do a full recon on tesla.com

Scan subdomains of paypal.com

What does an open 3389 port mean?

Explain the last scan

📥 Downloading Reports

After a full scan, the AI sends links for:

Technical report

Human summary

Endpoints:

/download/report?domain=<domain>
/download/summary?domain=<domain>

🧠 Internal Architecture (High-Level)
autorecon/cli.py

Handles the classic scan steps:

Subdomains

Deep subdomains

CT logs

Tech detection

Ports

Emails

Screenshots

Reports

ai_agent.py

Talks to the LLM using Ollama

Detects intent (“scan”, “explain”, “ask”)

Runs recon when needed

Reads results + creates explanations

api/ask_ai.py

FastAPI handles:

/ai — main AI endpoint

/progress — live scan updates

/download/... — report downloads

/chat/ — UI template

templates/chat.html

Frontend UI:

Chat bubbles

Typing indicator

Live progress

Auto-scroll

API connectivity indicator

⚠️ Disclaimer

This tool is for educational and authorized security testing only.
Do not use it on domains you do not own or do not have permission to scan.

Unauthorized scanning can result in:

IP bans

Abuse reports

Legal issues

Use responsibly.
