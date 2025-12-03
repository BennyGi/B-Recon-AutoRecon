# B-Recon

<div align="center">

![B-Recon Banner](assets/banner.png)

**AI-Powered Automated Reconnaissance Toolkit**

A modern recon engine combined with an AI assistant that explains findings, supports natural-language commands, and provides a clean web-based UI.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

</div>

---

## 🚀 Overview

B-Recon is a hybrid reconnaissance toolkit that combines a classic recon pipeline with an AI assistant powered by local LLMs. Originally built as a learning project, it has evolved into a practical, well-structured tool designed for security professionals and penetration testers.

### What You Get

- **Automated Recon Pipeline** – Subdomain enumeration, port scanning, technology detection, and more
- **AI Assistant** – Natural-language commands that understand intent and explain findings
- **Web Chat Interface** – Clean, modern UI for interactive scanning and reporting
- **Professional Reports** – Markdown, HTML, and human-readable summaries

---

## ✨ Features

### 🔍 Reconnaissance Engine

- ✅ Subdomain enumeration (wordlist-based)
- ✅ Deep subdomain scanning
- ✅ Certificate Transparency (CT) log collection
- ✅ Technology fingerprinting
- ✅ Email scraping
- ✅ Port scanning with optional service banners
- ✅ Screenshots (optional headless browser)
- ✅ Multiple report formats (Markdown, HTML, summary)

### 🤖 AI Assistant

- ✅ Natural-language command understanding
- ✅ Intent detection (scan/explain/general knowledge)
- ✅ Automatic output parsing and analysis
- ✅ Clear, analyst-friendly explanations
- ✅ Powered by local LLM (Ollama) – no cloud dependencies

### 💬 Web Interface

- ✅ Real-time chat with live progress updates
- ✅ Download generated reports directly
- ✅ Typing indicators and auto-scroll
- ✅ Responsive design

---

## 📋 Requirements

### System Requirements

- **OS:** Linux (Kali, Debian, Ubuntu tested)
- **Python:** 3.11 or higher
- **RAM:** 2GB+ recommended

### External Dependencies

Required:
- `nmap` – Port scanning
- `ffuf` – Subdomain enumeration
- `curl`, `wget` – HTTP utilities

Optional:
- `Playwright` + headless browser – For screenshots
- `Ollama` – For local LLM inference

### Python Dependencies

All Python packages are listed in `requirements.txt`

---

## 🛠️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/B-Recon.git
cd B-Recon
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

On Windows:
```cmd
python3 -m venv venv
venv\Scripts\activate
```

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 4. Install System Tools (Linux/Debian/Kali)

```bash
sudo apt update
sudo apt install -y nmap ffuf curl wget
```

On macOS (using Homebrew):
```bash
brew install nmap ffuf curl wget
```

### 5. Set Up Ollama (for AI Assistant)

Download and install [Ollama](https://ollama.ai/), then start the server:

```bash
ollama serve
```

In another terminal, download a lightweight model:

```bash
ollama pull llama2:7b
```

Or use `llama3.2:1b` for faster inference on limited hardware.

---

## 🖥️ Usage

### Option 1: Classic CLI

Run reconnaissance scans from the command line:

```bash
# Full reconnaissance
python autorecon/cli.py full tesla.com

# Individual scans
python autorecon/cli.py subdomains tesla.com
python autorecon/cli.py ports tesla.com
python autorecon/cli.py screenshots tesla.com
python autorecon/cli.py emails tesla.com
```

Results are stored in:
```
autorecon-results/<domain>/
```

### Option 2: Web Chat Interface (Recommended)

Start the FastAPI server:

```bash
uvicorn api.ask_ai:app --host 0.0.0.0 --port 8000 --reload
```

Open your browser and navigate to:

```
http://127.0.0.1:8000/chat/
```

#### Example Commands

```
"Do a full recon on tesla.com"
"Scan ports of paypal.com"
"Explain the last scan"
"What does an open 3389 port mean?"
"Find subdomains for example.com"
"Screenshot all discovered subdomains"
```

The AI assistant will:
- Parse your command
- Execute the appropriate scan
- Display real-time progress
- Explain results in plain English
- Provide download links for reports

---

## 📁 Project Structure

```
B-Recon/
├── ai/
│   └── ai_agent.py              # LLM logic, intent detection, explanations
│
├── api/
│   ├── ask_ai.py                # FastAPI backend (chat, progress, downloads)
│   └── __init__.py
│
├── autorecon/
│   ├── cli.py                   # Classic recon pipeline
│   ├── subdomains_big.txt       # Large wordlist
│   ├── subdomains_small.txt     # Quick wordlist
│   └── __init__.py
│
├── backend/
│   ├── recon_api.py             # Orchestration layer
│   └── screenshot_service.py    # Headless browser logic
│
├── scripts/
│   └── run_all.sh               # Development helper scripts
│
├── web/
│   └── index.html               # Web chat UI (HTML + JS)
│
├── assets/
│   ├── logo.png                 # Project logo
│   └── banner.png               # README banner
│
├── .github/
│   └── workflows/
│       └── ci.yml               # CI/CD pipeline
│
├── Dockerfile                   # Docker configuration
├── .gitignore
├── LICENSE                      # MIT License
├── MANIFEST.in
├── README.md                    # This file
├── requirements.txt             # Python dependencies
└── setup.py                     # Package configuration
```

---

## 🚀 Quick Start

### Minimal Setup (CLI Only)

```bash
# Clone and setup
git clone https://github.com/your-username/B-Recon.git
cd B-Recon
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
sudo apt install -y nmap ffuf curl wget

# Run a scan
python autorecon/cli.py full example.com
```

### Full Setup (Web UI + AI)

```bash
# Complete installation (from steps above)
# Then start both services:

# Terminal 1: Start Ollama
ollama serve

# Terminal 2: Start API server
source venv/bin/activate
uvicorn api.ask_ai:app --host 0.0.0.0 --port 8000 --reload

# Terminal 3: Open in browser
# Navigate to http://127.0.0.1:8000/chat/
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Web Chat Interface                     │
│                    (index.html)                          │
└────────────────────────┬────────────────────────────────┘
                         │
                    HTTP/WebSocket
                         │
┌────────────────────────▼────────────────────────────────┐
│              FastAPI Backend (ask_ai.py)                │
│          Chat routes, progress tracking, downloads      │
└────────────────────────┬────────────────────────────────┘
                         │
          ┌──────────────┼──────────────┐
          │              │              │
    ┌─────▼──────┐  ┌──▼────────┐  ┌──▼──────────┐
    │  AI Agent  │  │ Recon API │  │ Screenshot  │
    │  (Ollama)  │  │  (Backend)│  │  Service    │
    └─────┬──────┘  └──┬────────┘  └──┬──────────┘
          │            │              │
          └────────────┼──────────────┘
                       │
       ┌───────────────┼───────────────┐
       │               │               │
    ┌──▼──┐      ┌────▼───┐      ┌───▼───┐
    │nmap │      │ffuf    │      │curl   │
    └─────┘      └────────┘      └───────┘
  (Port scan)  (Subdomains)  (HTTP requests)
```

---

## ⚙️ Configuration

### Changing LLM Model

Edit `ai/ai_agent.py` and modify the model parameter:

```python
response = ollama.generate(model="llama3.2:1b", prompt=prompt)
```

Available models: `llama2:7b`, `mistral:7b`, `neural-chat:7b`

### Adjusting Scan Depth

Modify timeout and wordlist settings in `autorecon/cli.py`:

```python
WORDLIST = "subdomains_small.txt"  # Quick scan
WORDLIST = "subdomains_big.txt"    # Deep scan
```

### Port Scan Range

Edit the nmap command in `backend/recon_api.py`:

```python
nmap -p 1-65535 target.com  # Full range
nmap -p 1-10000 target.com  # Quick range
```

---

## 📊 Example Output

### CLI Report
```
[*] Scanning tesla.com
[+] Found 247 subdomains
[+] Open ports: 80, 443, 22
[+] Technologies: nginx, OpenSSL, Cloudflare
[+] Report saved: autorecon-results/tesla.com/report.md
```

### Web UI
- Real-time progress updates
- Downloadable reports (Markdown, HTML)
- AI-generated summaries and explanations

---

## 🐳 Docker Support

Build and run with Docker:

```bash
docker build -t b-recon .
docker run -p 8000:8000 -it b-recon
```

Visit `http://localhost:8000/chat/`

---

## 📚 Documentation

- **CLI Usage** – See `autorecon/cli.py` for detailed command options
- **API Routes** – FastAPI auto-docs at `http://127.0.0.1:8000/docs`
- **AI Agent** – Custom intent detection logic in `ai/ai_agent.py`

---

## ⚠️ Legal Disclaimer

**This tool is for authorized security testing ONLY.**

- Only use B-Recon on domains/systems you own or have explicit written permission to test
- Unauthorized access to computer networks is illegal
- Respect laws and regulations in your jurisdiction
- The authors are not responsible for misuse

---

## 🤝 Contributing

Contributions are welcome! Here's how:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Powered by [Ollama](https://ollama.ai/) for local LLM inference
- Built with [FastAPI](https://fastapi.tiangolo.com/) and [Playwright](https://playwright.dev/)

---

<div align="center">

**Built with ❤️ and curiosity**

[⬆ Back to top](#b-recon)

</div>
