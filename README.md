# B-Recon

<div align="center">

![B-Recon Banner](assets/B-ReconV2.png)

**AI-Powered Automated Reconnaissance Toolkit with Natural Language Processing**

An intelligent security reconnaissance platform that combines a full-featured recon engine with an LLM-powered assistant. Scan domains using natural language commands, get real-time progress updates, and receive AI-generated insights—all through a beautiful cybersecurity-themed web UI.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![Ollama LLM](https://img.shields.io/badge/Ollama-Local%20LLM-blue.svg)](https://ollama.ai/)

</div>

---

## 🚀 What is B-Recon?

B-Recon is a **next-generation reconnaissance platform** that merges automated security scanning with AI-driven analysis. Instead of memorizing CLI flags and parsing raw output, you simply tell B-Recon what you want in natural language.

### The Innovation

- **AI Assistant that understands intent** – "Scan Tesla for subdomains" automatically triggers the right tools
- **Real-time progress streaming** – Watch scans happen live with detailed progress logs
- **Smart port risk categorization** – Automatically flags critical ports (3389, 445, etc.)
- **Local LLM inference** – No cloud dependencies, no data leaving your machine
- **Beautiful cybersecurity UI** – Matrix rain animations, glitch effects, hacker aesthetic
- **Multi-format reports** – Markdown, HTML, and human-readable executive summaries

### Perfect For

- 🎓 Security students learning reconnaissance
- 🔍 Penetration testers who want faster workflows
- 🤖 Teams automating security assessments
- 🛡️ Bug bounty hunters gathering intelligence

---

## ✨ Core Features

### 🤖 AI-Powered Assistant

The heart of B-Recon. Uses local LLM (Ollama) to:

- **Detect user intent** – Understands 8+ intent types:
  - `scan` – Run automated recon
  - `explain_result` – Interpret past scan results  
  - `explain_flag` – Explain security concepts
  - `list_subdomains_only` – Extract specific data
  - `ports_only` – Show port risk assessment
  - `explain_last_scan` – Re-analyze previous results
  - `help` – List capabilities
  - `smalltalk` – Casual conversation

- **Natural language understanding** – No weird flags to remember
  - ✅ "Do a full scan on tesla.com"
  - ✅ "Find subdomains for google.com"
  - ✅ "What's risky about port 3389?"
  - ✅ "Explain the last scan"

- **Human-friendly output** – Complex findings explained simply
  - Converts raw recon data into analyst-ready summaries
  - Risk categorization (critical → low)
  - Actionable recommendations

### 🔍 Reconnaissance Engine

Comprehensive domain intelligence gathering:

| Tool | Purpose |
|------|---------|
| **WHOIS** | Domain registration & ownership info |
| **DNS (DIG)** | Record enumeration & DNS configuration |
| **NMAP** | Port scanning & service detection |
| **FFUF** | Directory & path fuzzing |
| **Subdomain Enumeration** | 500+ wordlist entries |
| **Deep Subdomains** | 2000+ wordlist entries for thorough scanning |
| **Certificate Transparency** | Logs from crt.sh & CertSpotter |
| **Wappalyzer API** | Technology fingerprinting (frameworks, CDNs, etc.) |
| **Email Scraper** | Extract emails from target websites |
| **Port Scanner** | Custom socket-based scanner with TLS fingerprinting |
| **Screenshots** | Headless browser screenshots of discovered sites |
| **Report Generator** | Markdown, HTML, & executive summaries |

### 💬 Web Chat Interface

Beautiful, responsive UI built with React:

- **Real-time progress updates** – See scan progress live without polling
- **Typing indicators** – Know when B-Recon is thinking
- **One-click downloads** – Get reports directly from chat
- **Cybersecurity aesthetics** – Matrix rain, glitch effects, neon colors
- **Mobile responsive** – Works on phones, tablets, desktops
- **Quick action buttons** – Pre-built commands for common tasks

### 📊 Multi-Format Reports

After each scan:

- **Technical Report** (Markdown) – Raw outputs for deep analysis
- **Executive Summary** (TXT) – C-level friendly overview  
- **HTML Report** – Interactive 3 theme toggle (Cyber/Light/Matrix)

---

## 📋 System Requirements

### Minimum

- **OS:** Linux (Kali, Debian, Ubuntu recommended)
- **Python:** 3.11+
- **RAM:** 2GB+
- **Disk:** 1GB for results

### Required Tools

```bash
nmap           # Port scanning
ffuf           # Subdomain fuzzing
curl, wget     # HTTP utilities
whois          # WHOIS queries
dig            # DNS lookups
```

### Optional (for advanced features)

```bash
Playwright     # Screenshots
Chromium       # Headless browser
Ollama         # Local LLM (for AI assistant)
```

---

## 🛠️ Installation

### Quick Start (5 minutes)

```bash
# 1. Clone
git clone https://github.com/your-username/B-Recon.git
cd B-Recon

# 2. Virtual environment
python3 -m venv venv && source venv/bin/activate

# 3. Install Python deps
pip install -r requirements.txt

# 4. Install system tools (Linux)
sudo apt update && sudo apt install -y nmap ffuf curl wget whois dnsutils

# 5. Setup Ollama (AI backend)
# Download from https://ollama.ai and run:
ollama serve
# In another terminal:
ollama pull llama3.2:1b

# 6. Start API server
uvicorn api.ask_ai:app --host 0.0.0.0 --port 8000

# 7. Open browser
# Visit: http://127.0.0.1:8000/chat/
```

### Detailed Installation

#### Step 1: Clone Repository
```bash
git clone https://github.com/your-username/B-Recon.git
cd B-Recon
```

#### Step 2: Python Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

Windows:
```cmd
python3 -m venv venv
venv\Scripts\activate
```

#### Step 3: Dependencies
```bash
pip install -r requirements.txt
```

#### Step 4: System Tools

**Debian/Kali:**
```bash
sudo apt update
sudo apt install -y nmap ffuf curl wget whois dnsutils
```

**macOS (Homebrew):**
```bash
brew install nmap ffuf curl wget whois bind-tools
```

**Arch Linux:**
```bash
sudo pacman -S nmap ffuf curl wget whois bind-tools
```

#### Step 5: Ollama Setup

1. Download from [ollama.ai](https://ollama.ai)
2. Start service: `ollama serve`
3. In another terminal: `ollama pull llama3.2:1b`

Available models:
- **Fast (1B):** `llama3.2:1b`, `tinyllama:latest`
- **Balanced (7B):** `llama2:7b`, `mistral:7b`
- **Smart (13B):** `llama2:13b`

#### Step 6: Run Services

Terminal 1 (Ollama):
```bash
ollama serve
```

Terminal 2 (B-Recon API):
```bash
cd B-Recon
source venv/bin/activate
uvicorn api.ask_ai:app --host 0.0.0.0 --port 8000 --reload
```

Terminal 3 (Browser):
```
Open: http://127.0.0.1:8000/chat/
```

---

## 🖥️ Usage Guide

### Via Web UI (Recommended)

Once running, open http://127.0.0.1:8000/chat/ and try:

```
"Scan tesla.com for subdomains"
"Do a full recon on google.com"
"What ports are open on github.com?"
"Find emails on example.com"
"Explain what port 3389 means"
"Show me the subdomain list for paypal.com"
"What technologies does amazon.com use?"
"List subdomains only for twitter.com"
"Show port risk for api.example.com"
```

The AI will:
1. ✅ Parse your command
2. ✅ Detect intent automatically
3. ✅ Run appropriate tools
4. ✅ Stream progress in real-time
5. ✅ Generate human-readable summary
6. ✅ Provide download links

### Via CLI

```bash
# Full reconnaissance
python autorecon/cli.py full tesla.com

# Individual scans
python autorecon/cli.py subdomains tesla.com
python autorecon/cli.py deep_subdomains tesla.com
python autorecon/cli.py ports tesla.com
python autorecon/cli.py emails tesla.com
python autorecon/cli.py screenshots tesla.com
python autorecon/cli.py tech tesla.com
```

Results stored in: `~/autorecon-results/<domain>/`

---

## 📸 Screenshots & Examples

### Web UI Chat Interface

**Hello/Greeting Examples:**
<div align="center">
  <img src="assets/AI(UI)-Hello.png" width="75%" alt="B-Recon Hello Chat">
  <img src="assets/AI(UI)-Hello2.png" width="75%" alt="B-Recon Chat Example 2">
</div>

**Full Reconnaissance Scan Examples:**
<div align="center">
  <img src="assets/AI(UI)-FullScan1.png" width="75%" alt="Full Scan Output 1">
  <img src="assets/AI(UI)-FullScan2.png" width="75%" alt="Full Scan Output 2">
  <img src="assets/AI(UI)-FullScan3.png" width="75%" alt="Full Scan Output 3">
</div>

<div align="center">
  <img src="assets/AI(UI)-FullScan4.png" width="75%" alt="Full Scan Output 4">
  <img src="assets/AI(UI)-FullScan5.png" width="75%" alt="Full Scan Output 5">
  <img src="assets/AI(UI)-FullScan6.png" width="75%" alt="Full Scan Output 6">
</div>

### AI Assistant Output Examples

**LLM-Powered Analysis (No UI):**
<div align="center">
  <img src="assets/AI(NoUI).png" width="75%" alt="AI Analysis Output">
  <img src="assets/AI(NoUI)2.png" width="75%" alt="AI Analysis Output 2">
  <img src="assets/AI(NoUI)3.png" width="75%" alt="AI Analysis Output 3">
</div>

### CLI Terminal Example

**Automated Reconnaissance via Command Line:**
<div align="center">
  <img src="assets/AutoReconTerminalGoogle.com.png" width="75%" alt="CLI Terminal Output">
</div>

---

## 📁 Project Architecture

### Directory Structure

```
B-Recon/
├── ai/
│   └── ai_agent.py
│       ├── Intent detection (8 types)
│       ├── LLM orchestration (Ollama)
│       ├── Results explanation
│       └── Port risk calculation
│
├── api/
│   └── ask_ai.py
│       ├── FastAPI routes (/ai, /progress, /reports)
│       ├── Progress streaming
│       └── Report downloads
│
├── autorecon/
│   ├── cli.py (Core scanning logic)
│   ├── subdomains_small.txt
│   └── subdomains_big.txt
│
├── backend/
│   ├── recon_api.py (Orchestration)
│   ├── run_screenshots.py
│   └── screenshot_service.py
│
├── web/
│   └── index.html (React UI with real-time updates)
│
└── [config files]
```

### System Architecture

```
┌──────────────────────────────────────────────────┐
│          Beautiful React Web UI                  │
│  (Matrix rain, glitch effects, live chat)        │
└─────────────────────┬──────────────────────────┘
                      │
                   HTTP/REST
                      │
┌─────────────────────▼──────────────────────────┐
│        FastAPI Backend (ask_ai.py)             │
│  • Routes: /ai, /progress, /reports            │
│  • WebSocket progress streaming                │
│  • Report file downloads                       │
└─────────────────────┬──────────────────────────┘
                      │
        ┌─────────────┼──────────────┐
        │             │              │
    ┌───▼──┐   ┌─────▼───┐  ┌──────▼────┐
    │ AI   │   │ Recon   │  │ Progress  │
    │Agent │   │ API     │  │ Logger    │
    └───┬──┘   └────┬────┘  └──────┬────┘
        │           │             │
        └───────────┼─────────────┘
                    │
    ┌───────────────┼───────────────┐
    │               │               │
 ┌──▼─┐     ┌──────▼───┐      ┌───▼──┐
 │nmap│     │ffuf+DIG  │      │curl  │
 │    │     │socket    │      │wget  │
 │port│     │scanning  │      │      │
 └────┘     └──────────┘      └──────┘
```

---

## 🧠 How AI Intent Detection Works

The system classifies user input into 8 categories:

| Intent | Examples | Action |
|--------|----------|--------|
| **scan** | "Scan example.com", "full recon on tesla.com" | Run automated tools |
| **list_subdomains_only** | "Show subs for github.com" | Extract subdomain list |
| **ports_only** | "What ports are open?" | Show port risk assessment |
| **explain_last_scan** | "Explain the scan for example.com" | Re-analyze existing results |
| **explain_flag** | "What does port 3389 mean?" | Educational explanation |
| **explain_result** | "What did you find?" | Summarize recent scan |
| **help** | "What can you do?" | List capabilities |
| **smalltalk** | "How are you?", "Hi" | Friendly conversation |

**Built-in safeguards:**
- Validates domains before scanning
- Requires domain for scan operations
- Handles missing data gracefully
- Truncates large outputs

---

## ⚙️ Configuration

### Change AI Model

Edit `ai/ai_agent.py`:
```python
MODEL_NAME = "llama2:7b"  # or mistral:7b, neural-chat:7b
```

Lighter models (faster): `llama3.2:1b`, `tinyllama:latest`  
Smarter models (slower): `llama2:13b`, `mistral:7b`

### Adjust Scan Wordlists

In `autorecon/cli.py`:
```python
# Quick scan (500 words)
wordlist_path = "subdomains_small.txt"

# Deep scan (2000 words)
wordlist_path = "subdomains_big.txt"
```

### Port Scan Range

In `backend/recon_api.py`:
```python
# Full scan (slow)
nmap -p 1-65535 {domain}

# Quick scan (fast)
nmap -p 1-10000 {domain}
```

---

## 📊 Example Workflows

### Workflow 1: Quick Domain Overview
```
User: "Scan tesla.com for subdomains"

→ AI detects: intent=scan, domain=tesla.com, scan_type=subdomains
→ Runs: WHOIS, DIG, subdomain enumeration
→ Returns: 247 subdomains found, 3 high-risk ports
→ User downloads: technical report
```

### Workflow 2: Full Security Assessment
```
User: "Do a full recon on example.com"

→ AI detects: intent=scan, domain=example.com, scan_type=full
→ Executes 9-step pipeline:
   [1] Core scan (WHOIS/DNS/NMAP/FFUF)
   [2] Subdomain enumeration
   [3] Deep subdomain scan
   [4] CT log collection
   [5] Technology detection
   [6] Email scraping
   [7] Port scan (with TLS fingerprinting)
   [8] Screenshots
   [9] Report generation

→ User sees: Real-time progress, live updates
→ Results: 3 reports + full intelligence
```

### Workflow 3: Risk Assessment
```
User: "What's risky about example.com?"

→ Reads: ports.json from last scan
→ Categorizes: Critical/High/Medium/Low ports
→ Highlights: 
   🔥 Port 3389 (RDP) = Remote desktop attacks
   🔥 Port 445 (SMB) = Worm entry point
   ⚠️  Port 22 (SSH) = Brute-force target

→ Recommends: Check login protection, update systems
```

---

## 🐳 Docker

```bash
docker build -t b-recon .
docker run -p 8000:8000 -p 11434:11434 -it b-recon
```

Visit: `http://localhost:8000/chat/`

---

## 🔒 Security & Legal

**⚠️ Authorization Required**

B-Recon is for authorized testing ONLY:
- ✅ Domains you own
- ✅ Systems with written permission
- ❌ Unauthorized scanning is illegal
- ❌ Respect jurisdiction laws
- ❌ The author accepts no liability

---

## 📚 Documentation

- **API Docs** – http://127.0.0.1:8000/docs (Swagger UI)
- **AI Logic** – See `ai/ai_agent.py` for intent detection & prompts
- **Scan Pipeline** – See `backend/recon_api.py` for orchestration
- **Web UI** – React + Tailwind in `web/index.html`

---

## 🚀 Performance Tips

| Task | Speed Up By |
|------|------------|
| **Slow subdomains** | Use `subdomains_small.txt` instead of big |
| **Port scan bottleneck** | Reduce threads in `scan_single_port()` |
| **Slow LLM responses** | Use `llama3.2:1b` instead of larger models |
| **Memory issues** | Reduce screenshot concurrency |

---

## 🤝 Contributing

```bash
# Fork & clone
git clone https://github.com/your-username/B-Recon.git

# Create feature branch
git checkout -b feature/cool-feature

# Make changes & test
python -m pytest tests/

# Commit & push
git commit -m "Add cool feature"
git push origin feature/cool-feature

# Open Pull Request
```

---

## 📝 License

MIT License – See [LICENSE](LICENSE) for details

---

## 🙏 Built With

- **[Ollama](https://ollama.ai/)** – Local LLM inference
- **[FastAPI](https://fastapi.tiangolo.com/)** – Modern Python web framework
- **[React](https://react.dev/)** – UI framework
- **[nmap](https://nmap.org/)** – Network scanner
- **[ffuf](https://github.com/ffuf/ffuf)** – Fuzzer
- **[Playwright](https://playwright.dev/)** – Browser automation

---

<div align="center">

**Built with ❤️ by Benny Giorno**

Intelligence gathering for the modern age

[⬆ Back to top](#b-recon)

</div>
