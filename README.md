# QuantumShield 🛡️
### Next-Generation AI-Powered Honeypot & ML Firewall

QuantumShield is an advanced cybersecurity defense system that sits in front of your web applications. Unlike traditional WAFs that simply block attacks, QuantumShield uses machine learning to detect threats and redirects attackers to a highly realistic, LLM-powered honeypot to gather intelligence while protecting your real infrastructure.

---

## 🛠 Tech Stack

| Category | Technology Stack |
| :--- | :--- |
| **Frontend** | Next.js, Tailwind CSS |
| **Honeypot** | Groq, FastAPI, MongoDB |
| **ML Models** | PyTorch, DistilBERT, XGBoost |
| **Backend** | Python, SendGrid |

---

## Key Features

*   **ML Firewall :** Semantic analysis of SQLi & NoSQLi payloads using Transformer models to understand the "meaning" of an attack, catching what regex misses.
*   **Adaptive Honeypot :** A dynamic deception engine that uses LLMs to generate realistic HTML/JSON responses on the fly. Trapped attackers never hit a dead end.
*   **Counter-Based Blocking :** A progressive response system where attackers get 5 chances before a permanent IP ban, with persistence backed by MongoDB.
*   **Live Dashboard :** Real-time visibility into attacks happening live, featuring session replays to analyze exactly what the attackers tried to do.

---

## System Architecture

<p align="center">
  <img src="C:\Users\hp\AppData\Local\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\LocalState\sessions\2F502EA250DA1B4D84889F58822B289E802866C7\transfers\2025-52\Screenshot 2025-12-10 012652.png" alt="QuantumShield Architecture">
</p>

---
##  How It Works (User Flow)

1.  **Request Arrival:** Every incoming request hits the QuantumShield smart reverse proxy.
2.  **ML Analysis:** The request is analyzed by DistilBERT models to assign a threat confidence score.
3.  **Smart Routing:**
    *   **Safe Traffic:** Forwarded seamlessly to your real application.
    *   **Suspicious Traffic:** Quietly routed to the LLM-powered honeypot.
    *   **Malicious Traffic:** Blocked immediately if the threat score is too high.
4.  **Intelligence Gathering:** Every action the attacker takes in the honeypot is logged for security analysis.

---

##  Setup & Installation

### Prerequisites
- Python 3.9+
- Node.js 18+
- MongoDB

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/quantumshield.git
   cd quantumshield
   ```

2. **Setup the Honeypot (Gateway)**
   ```bash
   cd honeypot
   pip install -r requirements.txt
   # Add your GROQ_API_KEY to the .env file
   python main.py
   ```

3. **Setup the Dashboard & Demo App**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

---

## Why QuantumShield? (Business & Strategic Value)

QuantumShield represents a shift from reactive defense to proactive deception. It is an essential tool for modern enterprises for several reasons:

*   **Detection of Zero-Day Exploits:** By focusing on the semantic intent of a payload rather than known signatures, it protects against novel attacks that have no existing "patch" or rule.
*   **Cost & Resource Exhaustion:** Attacking a system takes time and money. By engaging attackers in an LLM-powered "hallucination," we waste their resources, making your company an unprofitable and frustrating target.
*   **High-Fidelity Intelligence:** Instead of a simple "IP Blocked" log, you receive a full report of the attacker's methodology. This data can be used to harden your internal systems against the specific techniques being used against you.
*   **Elimination of False Positives:** Traditional WAFs often block legitimate customers due to rigid rules. QuantumShield’s ML scoring provides a more nuanced approach, ensuring your business stays open to real users.
*   **Scalable Security:** Built on high-performance frameworks like FastAPI and Next.js, QuantumShield is designed to scale with your traffic while maintaining enterprise-grade security.
