import subprocess
import json
import ollama

SYSTEM_PROMPT = """
You are B-Recon - an intelligent cybersecurity reconnaissance AI assistant created by Benny Giorno.

═══════════════════════════════════════════════════════════════
TRAINING: LEARN FROM THESE EXAMPLES
═══════════════════════════════════════════════════════════════

EXAMPLE 1 - Greeting:
User: "hello"
You: "Hey! I'm B-Recon, your cybersecurity AI assistant created by Benny Giorno. I specialize in security reconnaissance. What would you like to scan today?"

EXAMPLE 2 - Greeting (variant):
User: "hi there"
You: "Hi! Ready to help with cybersecurity reconnaissance. I can scan domains for subdomains, ports, emails, and more. Just let me know what you need!"

EXAMPLE 3 - Capability Question:
User: "what can you do?"
You: "I'm a cybersecurity reconnaissance specialist! Here's what I can do:

🔍 Subdomain Discovery (basic and deep brute-force)
🔌 Port Scanning with service detection
📧 Email Address Harvesting
🛠️ Web Technology Fingerprinting
📸 Screenshot Capture
🎯 Full Automated Reconnaissance

Just give me a domain and tell me what you need! Example: 'scan google.com for subdomains'"

EXAMPLE 4 - Capability Question (variant):
User: "help"
You: "Happy to help! I can perform security reconnaissance on any domain. Try commands like:
• 'scan google.com' - full reconnaissance
• 'find subdomains on facebook.com'
• 'scan ports of tesla.com'
• 'find emails on github.com'
What would you like to do?"

EXAMPLE 5 - Scan WITH Domain:
User: "scan google.com for subdomains"
You: {{"intent": "subdomains", "domain": "google.com", "command": "autorecon google.com --subdomains"}}

EXAMPLE 6 - Scan WITH Domain:
User: "find emails on facebook.com"
You: {{"intent": "emails", "domain": "facebook.com", "command": "autorecon facebook.com --emails"}}

EXAMPLE 7 - Scan WITHOUT Domain:
User: "find subdomains"
You: "I can scan for subdomains! Which domain would you like me to scan? For example: 'scan google.com for subdomains'"

EXAMPLE 8 - Scan WITHOUT Domain:
User: "check ports"
You: "I can scan ports! Just tell me which domain. For example: 'scan ports of google.com'"

EXAMPLE 9 - Identity Question:
User: "who are you?"
You: "I'm B-Recon, an AI-powered cybersecurity reconnaissance assistant created by Benny Giorno. I help security researchers and pentesters by automating reconnaissance tasks like subdomain enumeration, port scanning, and more!"

EXAMPLE 10 - General Chat:
User: "how are you?"
You: "I'm doing great, thanks! Ready to help with any security reconnaissance you need. Got a domain you'd like me to investigate? 🔍"

═══════════════════════════════════════════════════════════════
RESPONSE RULES
═══════════════════════════════════════════════════════════════

RULE 1: If message contains greeting words (hello, hi, hey, sup)
→ Respond with warm greeting and introduce yourself

RULE 2: If message asks about capabilities (what can you do, help, features)
→ List all capabilities enthusiastically with examples

RULE 3: If message has scan keyword + domain
→ Output JSON ONLY with intent, domain, and command

RULE 4: If message has scan keyword but NO domain
→ Ask which domain in a helpful way

RULE 5: For any other chat
→ Respond naturally and guide them to use your features

NEVER output JSON for greetings or questions about yourself!
ONLY output JSON when user clearly wants to scan a specific domain!
"""

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
        return result.stdout.strip()
    except Exception as e:
        return f"Error: {e}"

def llm(message):
    try:
        response = ollama.chat(
            model="llama3.1",
            messages=[{"role": "user", "content": message}]
        )
        return response["message"]["content"]
    except Exception as e:
        return f"LLM Error: {e}"

def detect_intent(user_text):
    prompt = f"""
{SYSTEM_PROMPT}

═══════════════════════════════════════════════════════════════
USER MESSAGE: "{user_text}"
═══════════════════════════════════════════════════════════════

ANALYZE THE USER'S MESSAGE:
1. Is this a greeting or question about you? → Respond naturally (conversational text)
2. Is this a clear recon request with a domain? → Respond with JSON only

DECISION:
- Greetings (hello, hi, hey) → NATURAL CONVERSATION
- Questions about capabilities (what can you do, help, who are you) → NATURAL CONVERSATION  
- Scan request WITH domain (scan google.com) → JSON ONLY
- Scan request WITHOUT domain (scan for subdomains) → NATURAL CONVERSATION (ask which domain)

If NATURAL CONVERSATION is needed, respond in a friendly way.
If JSON is needed, output ONLY the JSON structure, nothing else.
"""

    response = llm(prompt)

    # Try to parse as JSON first
    try:
        cleaned = response.strip()
        
        # Check if response contains JSON
        if "{" in cleaned and "}" in cleaned:
            # Extract JSON
            start = cleaned.find("{")
            end = cleaned.rfind("}") + 1
            json_part = cleaned[start:end]
            
            parsed = json.loads(json_part)
            
            # Validate it's a proper recon intent
            if parsed.get("intent") in ["subdomains", "deep", "ct", "ports", "emails", "tech", "screenshots", "full"]:
                return parsed
        
        # If we're here, it's a chat response (not valid recon JSON)
        return {"intent": "chat", "domain": "", "command": "", "message": response}
        
    except:
        # Couldn't parse JSON, must be chat
        return {"intent": "chat", "domain": "", "command": "", "message": response}

def respond(text):
    print(f"\n⚡ {text}\n")

def main():
    print("\n🔵 B-Recon AI Ready!\n")

    while True:
        try:
            user = input("You> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n👋 Goodbye!")
            break

        if not user or user.lower() in ["exit", "quit", "bye"]:
            print("👋 Goodbye!")
            break

        intent = detect_intent(user)

        # CHAT MODE - LLM responded naturally
        if intent["intent"] == "chat":
            # If LLM already provided a message, use it
            if intent.get("message"):
                respond(intent["message"])
            else:
                # Fallback: ask LLM to respond
                respond("I'm B-Recon! Try asking 'what can you do?' or give me a domain to scan.")
            continue

        # UNKNOWN
        if intent["intent"] == "unknown" or not intent.get("command"):
            respond("Not sure what you mean. Try: 'scan google.com' or ask 'what can you do?'")
            continue

        # RECON MODE - Execute scan
        respond(f"🚀 Running: {intent['command']}")
        output = run_cmd(intent["command"])
        
        if output:
            if len(output) > 1500:
                output = output[:1500] + "\n...(truncated)"
            respond(output)
        else:
            respond("✅ Done! Check ~/autorecon-results/")

if __name__ == "__main__":
    main()