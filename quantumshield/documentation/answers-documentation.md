# Technical Questions and Answers

## Question 1: Model Selection & Performance

I am very interested in the range of ML/AI models you have experimented with. I would greatly appreciate it if you could provide a matrix or list summarizing: the models you have tried, their respective accuracies or performance metrics, and the reasons for not considering certain models for your final solution.

Additionally, you mentioned that you are currently performing fine-tuning. Could you please share which fine-tuning technique you are applying at the moment?

### Model Selection & Performance Report

#### 1. Model Experimentation Matrix

We evaluated a hybrid architecture separating Payload Analysis (Text-based) and Traffic Flow Analysis (Statistical). Below is the summary of models experimented with:

| Model Architecture | Target Data | Status | Accuracy / F1 | Reasoning for Selection/Rejection |
|-------------------|-------------|--------|---------------|-----------------------------------|
| DistilBERT (Transformer) | SQLi / XSS Payloads | Selected | 99.79% | Best semantic understanding of malicious strings. Lightweight compared to BERT, fast enough for inference. |
| LSTM / Bi-LSTM | SQLi / XSS Payloads | Rejected | ~83.80% | Slower training time (sequential processing). Struggled with long-distance dependencies in complex SQL queries compared to Self-Attention. |
| Naive Bayes / SVM | SQLi / XSS Payloads | Rejected | ~76.78% | Rely too much on "bag-of-words." Failed to detect obfuscated attacks or novel patterns. |
| XGBoost (Gradient Boosting) | Network Flow (DDoS) | Selected | 98.91% | State-of-the-art for tabular data (UNSW-NB15). Extremely fast inference and handles feature imbalance well. |
| 1D-CNN | Network Flow (DDoS) | Alternative | 93.53% | Good at capturing local patterns in packet sequences, but slightly heavier compute cost than XGBoost for similar results. |
| Deep Autoencoder | Zero-Day / Anomalies | Hybrid | N/A (Threshold) | Selected specifically for Zero-Day detection. It does not classify; it flags high reconstruction errors as "Suspicious." |

#### 2. Detailed Performance Metrics (Selected Models)

**Text Classifier: DistilBERT (Fine-Tuned)**

Target: SQL Injection, XSS, Command Injection

- Dataset: SQLiV3 (Modified)
- Accuracy: 99.79%
- Precision: 0.99
- Recall: 0.99
- False Positive Rate: < 0.1% (Critical for user experience)

**Flow Classifier: XGBoost / 1D-CNN**

Target: DDoS, Botnet, Port Scanning

- Dataset: UNSW-NB15 / CSE-CIC-IDS2018
- Accuracy: 98.91%
- Inference Speed: < 5ms per flow
- Key Strength: High detection rate on low-volume DoS attacks (Slowloris)

#### 3. Why We Rejected Traditional Deep Learning (RNNs)

While LSTMs were historically popular for intrusion detection, we moved to Transformers (DistilBERT) for the following reasons:

1. **Contextual Awareness**: SQL injection attacks often rely on syntax context (e.g., 'OR 1=1'). Transformers utilize Self-Attention mechanisms to understand the relationship between tokens better than RNNs.

2. **Parallelization**: Transformers process input sequences in parallel, whereas RNNs process sequentially. This allows for faster training on GPUs.

3. **Transfer Learning**: We leverage a pre-trained language model (trained on English/Code) and fine-tune it. LSTMs require training from scratch, requiring significantly more labeled data to reach comparable accuracy.

#### 4. Current Fine-Tuning Strategy

We are currently applying **Transfer Learning with Full Supervised Fine-Tuning (SFT)**.

**The Technique:**

- Base Model: distilbert-base-uncased (66 Million Parameters)
- Method: We replace the final "Classification Head" (the last layer) with a custom dense layer for binary classification (Safe vs. Malicious vs. Suspicious)
- Weights: We update all weights in the model (we are not currently using PEFT/LoRA, as the model is small enough to fine-tune fully on a T4 GPU)
- Loss Function: Categorical Cross-Entropy
- Optimizer: AdamW (Adam with Weight Decay) to prevent overfitting

**Logic for Fine-Tuning:**

Instead of training a model from scratch to read text, we use DistilBERT's existing knowledge of language syntax and "teach" it to recognize the specific "syntax" of SQL attacks. This results in faster convergence and higher robustness.

*Answers by Ayush*

---

## Question 2: Honeypot Implementation

Thank you for your explanation — I found it very interesting. I would truly appreciate it if you could share the solution architecture or workflow you are using for the Honeypot implementation.

Furthermore, it would be helpful to know which LLM you are leveraging and how you are managing the model's memory.

### Solution Architecture

#### High-Level Workflow

The system implements a 3-layer defense architecture:

1. **Layer 1 - ML Firewall**: Analyzes incoming HTTP requests using a Random Forest classifier to detect malicious patterns (SQLi, XSS, etc.)

2. **Layer 2 - Routing Decision**: Safe traffic is forwarded to the real application, while malicious traffic is routed to the honeypot

3. **Layer 3 - Honeypot Engagement**: AI-generated fake responses trap attackers while logging all interactions for analysis

#### Detailed Workflow

The request processing follows these steps:

1. ML firewall detects malicious request
2. Session Manager creates or retrieves existing attacker session from MongoDB
3. Deception Engine builds context-aware prompt using session history
4. LLM generates realistic fake response (with caching for performance)
5. Response is returned to attacker (appears legitimate)
6. All interaction data is logged to MongoDB for analytics

### LLM Selection & Rationale

#### Model Used

We selected **Groq API with Llama 3.3 70B Versatile** as our LLM provider.

#### Selection Criteria

The decision was based on three primary factors:

**Speed**: Groq's LPU (Language Processing Unit) inference delivers 300+ tokens per second, which is critical for real-time response generation. Traditional GPU-based inference would introduce noticeable latency that could alert sophisticated attackers.

**Quality**: The 70B parameter Llama model provides sufficiently realistic and context-aware responses. We found that larger models offered diminishing returns for our use case, while smaller models occasionally produced responses that felt artificial.

**Cost**: Groq's pricing structure is competitive for production deployment and mostly because it has a generous free tier with a variety of hosted models. Combined with our caching strategy, the per-request cost remains under $0.001.

#### Alternatives Considered

We evaluated OpenAI GPT-4, which offers higher quality responses but at the cost of increased latency and expense. We also considered self-hosted models, which would reduce ongoing costs but require significant infrastructure investment and maintenance overhead.

The Groq solution provides the optimal balance for a honeypot application where speed and believability are paramount.

### Memory Management Strategy

#### Two-Tier Memory System

**1. Short-Term Memory (Session Context)**

Each attacker session maintains state in MongoDB with consistent "fake environment" context that the LLM references when generating responses. This prevents contradictions that might reveal the honeypot's true nature.

**2. Long-Term Memory (MongoDB Persistence)**

We maintain three primary collections:

- `sessions`: Stores attacker session data including IP, user-agent, context, and timestamps
- `interactions`: Records every request/response pair with attack type classification and payload details
- `analytics`: Contains aggregated statistics for threat intelligence and pattern analysis

Data retention is currently set to 90 days, though this is configurable based on storage constraints and compliance requirements.

**3. Response Cache (Performance Layer)**

An in-memory LRU cache stores frequently accessed responses:

- Cache key: Hash of (prompt template + user input)
- Cache value: LLM-generated response
- TTL: 1 hour
- Maximum size: 1000 entries

This caching layer achieves a 60-70% hit rate for repeated attack patterns, reducing LLM API calls by approximately 95% and ensuring consistent responses to identical attacks.

#### LLM Context Window Management

**Challenge:** While Llama 3.3 supports up to 128K tokens, we limit context to approximately 2K tokens for cost efficiency and response speed.

**Sliding Window Approach:**

We implement history pruning by retaining only the most recent 5-10 interactions. For long-lived sessions, older interactions are summarized rather than included verbatim. This prioritizes recent context, which is most relevant for maintaining conversation coherence.

This approach keeps us well within token limits while maintaining sufficient context for realistic responses.

### Key Technical Decisions

| Aspect | Choice | Rationale |
|--------|--------|-----------|
| LLM Provider | Groq | Optimizes for speed and cost |
| Model | Llama 3.3 70B | Balances quality with performance |
| Session Storage | MongoDB | Provides flexible schema and scalability |
| Cache Strategy | LRU in-memory | Enables fast lookups with automatic eviction |
| Context Size | Last 5-10 interactions | Manages token budget while maintaining relevance |

*Answers by Shubhajit*

---