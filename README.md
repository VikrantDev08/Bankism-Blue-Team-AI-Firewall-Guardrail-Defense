# Bankism-Blue-Team-AI-Firewall-Guardrail-Defense
Bankism: Blue-Team AI Firewall &amp; Guardrail Defense — A real-time cybersecurity dashboard and guardrail engine designed to inspect, detect, and block prompt injection attacks, system overrides, and PII data leaks in banking AI systems

# 🛡️ Bankism: Blue-Team AI Firewall & Guardrail Defense

**Bankism** is a browser-based cybersecurity defense dashboard designed to serve as a protective security layer (AI Firewall) between banking customers and financial AI models. 

Built for the **PromptWars x UVCE** hackathon, this project demonstrates how Blue-Team defenses can proactively inspect, filter, and sanitize incoming natural language requests before they reach core LLM logic or database endpoints.

---

## 🚀 Key Features

* **Real-Time Guardrail Engine:** Evaluates incoming user prompts instantly against dynamic security rules.
* **Prompt Injection & Jailbreak Prevention:** Detects malicious directives attempting to override system rules, expose internal instructions, or bypass security protocols.
* **Data Privacy Protection (PII Safeguard):** Scans for sensitive customer identifiers (credit card numbers, PINs, SSNs) to prevent data exfiltration.
* **Live Audit Log & Dashboard:** Displays real-time security telemetry, including threat categorization, timestamped logs, and action status (Blocked 🚫 / Allowed ✅).
* **Interactive Threat Testing:** Features built-in preset attack scenarios for quick demonstration and verification.

---

## 🛠️ Tech Stack

* **Frontend:** Pure HTML5, CSS3 (Modern Dark Mode UI)
* **Logic:** Modern JavaScript (Security Rule Evaluation Engine)
* **Hosting & CI/CD:** Vercel
* **Version Control:** GitHub

---

## 🎯 Hackathon Problem Statement

**Challenge:** Bankism: Blue-Team AI Firewall & Guardrail Defense  
**Event:** PromptWars x UVCE  

---

## 📜 License

This project is licensed under the MIT License.
