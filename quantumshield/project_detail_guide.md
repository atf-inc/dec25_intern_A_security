# QuantumShield Project Detail Guide

This guide provides a detailed analysis of the QuantumShield IPS/Firewall architecture, focusing on its multi-layered defense mechanisms, Machine Learning (ML) integration, and external tool orchestration.

## 1. Project Architecture Overview

QuantumShield is a modular Intrusion Prevention System (IPS) and Next-Gen Firewall (NGFW) protecting three distinct layers:
1.  **Network Layer (L3/L4)**: Filters packet-level attacks (DDoS, Floods).
2.  **Application Layer (L7)**: inspects HTTP/HTTPS traffic (SQLi, XSS, Bots).
3.  **LLM Security Layer**: Protects against Prompt Injection and Jailbreaks for GenAI systems.

The core orchestration is handled by `quantumshield/core/engine.py`, which coordinates data flow between these layers and a centralized Decision Maker.

---

## 2. Core Modules & ML Integration

### A. Network Layer Defense Module
**Location**: `quantumshield/network_layer/`
**Core Function**:
*   **Traffic Monitoring**: Captures packets and analyzes flow statistics (PPS, BPS, Flags) via `packet_monitor.py`.
*   **DDoS Detection**: Identifies volumetric attacks like SYN Floods and UDP Floods.

**ML Integration**:
*   **Algorithm**: **Random Forest Classifier** (`sklearn`).
*   **Implementation**: `ddos_detector.py`.
*   **How it works**:
    *   extracts 7 key features: `[packet_len, protocol, pps, bps, is_tcp, is_udp, tcp_flags]`.
    *   The model predicts a "malicious" probability score (0-1).
    *   Includes an auto-training mechanism to establish specific network baselines.
*   **Integration Support**:
    *   **Snort**: Can validate dropped packets against signature database.
    *   **Fail2Ban**: Can permanently ban IPs identified by the ML model.

### B. Application Layer Defense Module
**Location**: `quantumshield/application_layer/` & `quantumshield/ml_waf/`
**Core Function**:
*   **Web Application Firewall (WAF)**: `waf_engine.py` orchestrates defense.
*   **Deep Packet Inspection**: `http_inspector.py` parses full HTTP context.
*   **Rule-Based Security**: Implements OWASP Core Rule Set (CRS) for known vulnerabilities (SQLi, XSS).

**ML Integration**:
The Application Layer uses a **Hybrid Neuro-Symbolic** approach:
1.  **Anomaly Detection (Deep Learning)**:
    *   **Algorithm**: **Hybrid LSTM-CNN** (`ml_waf/detector.py`).
    *   **Purpose**: Detects zero-day attacks by finding sequence anomalies in HTTP headers/URIs.
    *   **Detail**: LSTM captures temporal dependencies in request sequences, while CNN extracts local feature patterns.
2.  **Adaptive Regulation (Reinforcement Learning)**:
    *   **Algorithm**: **Deep Q-Network (DQN)** (`ml_waf/agent.py`).
    *   **Purpose**: Adapts blocking thresholds dynamically based on network state and feedback rewards.
3.  **Traffic Classification**:
    *   **Module**: `ml_models/traffic_classifier`.
    *   **Purpose**: Classifies traffic types (Benign, SQLi, XSS) using Transformer-based models (e.g., BERT-tiny).

**Integration Support**:
*   **ModSecurity**: Can import existing rulesets.
*   **OWASP ZAP**: Can be used to validation defense against active scanning.

### C. LLM Security Level Defense Module
**Location**: `quantumshield/quantum_llma/`
**Core Function**:
*   **GenAI Protection**: Filters inputs to Large Language Models (LLMs).
*   **Threats Handled**: Prompt Injection, Jailbreaking, PII leakage.

**ML Integration**:
*   **Framework**: **QuantumLLMA** (Powered by PurpleLlama).
*   **Models**:
    *   **CodeShield**: Detects insecure code generation.
    *   **PromptGuard**: ML-based classification of prompt attacks.
*   **Implementation**: `manager.py` acts as a gateway/middleware. It asynchronously scans prompts before they reach the backend LLM.

**Integration Support**:
*   **LangChain**: Can be integrated as a custom tool/chain.
*   **ReAct Agents**: Protects agent thought loops.

---

## 3. Integration Module Structure

**Location**: `quantumshield/integrations/`
**Core Function**:
The `ToolManager` (`tool_manager.py`) allows QuantumShield to orchestrate external security binaries. This transforms it from a passive filter into an active security operations platform.

The system is designed to integrate the following 10 core security tools:

| Tool Name | Layer | Core Task | Supported OS | Functionality / Role |
| :--- | :--- | :--- | :--- | :--- |
| **Snort** | Network (L3/L4) | IDS / Signature Matching | Linux (Rec.), Windows | Validates packets against a massive database of known attack signatures. Verifies ML alerts. |
| **Nmap** | Network (L3/L4) | Active Reconnaissance | Linux, Windows, macOS | Performs port scanning and OS fingerprinting on attacking IPs to gather counter-intelligence. |
| **Fail2Ban** | Response | IP Blocking / Jail | Linux | Persistence mechanism. Parses logs and updates firewall rules (iptables) to permanently ban repeat offenders. |
| **Wireshark (TShark)** | Network (L3-L7) | Deep Packet Analysis | Linux, Windows, macOS | Captures and decodes full packet data for forensic analysis and debugging. |
| **Metasploit** | Verification | Penetration Testing | Linux, Windows | Used in "Simulation Mode" to launch controlled attacks against the system to verify defenses. |
| **Burp Suite** | App (L7) | Web Vulnerability Scanning | Linux, Windows, macOS | Acts as an external proxy to test WAF rules against complex web attack vectors. |
| **Hydra** | Auth | Brute Force Testing | Linux, Windows | Tests the system's ability to detect and block rapid login attempts (credential stuffing). |
| **Sqlmap** | App (L7) | SQL Injection Testing | Linux, Windows | specialized tool to bombard the WAF with SQL injection patterns to ensure robustness. |
| **OSSEC** | Host (HIDS) | File Integrity Monitoring | Linux, Windows | Monitors critical system files and logs for unauthorized changes (Host-based IDS). |
| **Aircrack-ng** | Network (WiFi) | Wireless Auditing | Linux, Windows | *Optional*: Monitors wireless interfaces for unauthorized access points or deauth attacks. |

**Implementation Status**:
*   **Active**: Snort, Nmap (Wrappers available in `wrappers/`).
*   **Planned**: Fail2Ban, TShark, others.

---

## 4. Summary of ML Stack

| Defense Layer | ML Model / Algorithm | Library | Feature Input |
| :--- | :--- | :--- | :--- |
| **Network (DDoS)** | Random Forest | Scikit-learn | PPS, BPS, Packet Size, Flags |
| **WAF (Anomaly)** | Hybrid LSTM-CNN | PyTorch | Tokenized URI & Header sequences |
| **WAF (Policy)** | Deep Q-Network (DQN) | PyTorch | System State (Threat Level, Latency) |
| **LLM Security** | Transformer (BERT-based) | QuantumLLMA | Raw Text / Prompt |

## 5. How to Extend

To add a new defense module:
1.  **Define Interface**: Create a class in `detection_engines/` implementing `analyze(flow_data)`.
2.  **Register**: Add to `QuantumShieldEngine._load_detection_engines`.
3.  **Integrate ML**: If using ML, implement model loading in `ModelManager` and inference logic in the engine's `_run_ml_models` loop.
