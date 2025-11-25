FROM kalilinux/kali-rolling

# Update packages
RUN apt update && apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    ffuf \
    whois \
    dnsutils

# Create app directory
WORKDIR /app

# Copy project files
COPY . /app

# Run the tool by default
ENTRYPOINT ["python3", "AutoRecon.py"]
