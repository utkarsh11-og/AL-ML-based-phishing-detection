# System Architecture & Technical Specifications

## 1. Overview
The AI/ML-based Phishing Detection and Prevention Platform evaluates URLs and emails through multi-stage analysis: static lexical parsing, machine learning inference, explainability attribution, and security policy enforcement.

---

## 2. Design Principles

1. **Defense in Depth**: Rely neither purely on static rules nor solely on opaque deep neural networks. Combine lexical heuristics, statistical anomaly detection, and supervised classifiers.
2. **Deterministic Preprocessing**: Ensure identical URL normalization and feature extraction logic across training, offline evaluation, and live inference environments.
3. **Decoupled Risk Scoring**: Separate the raw continuous model confidence ($P(\text{Phishing}|x) \in [0, 1]$) from the business/security action layer.
4. **Air-Gapped Static Analysis**: Do not resolve, fetch, or render live untrusted URLs during primary feature extraction to prevent Server-Side Request Forgery (SSRF) and malware infection.

---

## 3. Data Flow Diagram

```
[Raw URL String]
      │
      ▼
[URL Normalizer & Validator]
      │
      ▼
[Feature Extraction Engine] ──────► [Feature Vector: X ∈ ℝⁿ]
                                              │
                                              ▼
                                    [Trained ML Classifier]
                                              │
                                              ▼
                                    [P(phishing), Feature Importances]
                                              │
                                              ▼
                                    [Risk & Decision Engine]
                                              │
                                              ▼
                                    [Verdict: ALLOW / WARN / BLOCK]
```

---

## 4. Feature Taxonomy Preview

| Category | Indicators | Security Rationale |
|---|---|---|
| **Lexical Metrics** | Length, entropy, special char count | Phishing URLs often embed obfuscated or high-entropy tokens. |
| **Host / Domain** | Subdomain depth, IP hostname, TLD type | Attackers abuse deep subdomains or raw IP addresses. |
| **Path / Query** | Token count, sensitive keywords (`login`, `verify`, `bank`) | Phishing campaigns replicate legitimate authentication paths. |
| **Structural** | `@` symbol, double slash `//` redirects | Tricks browsers and users into authenticating to wrong endpoints. |

---

## 5. Security & SSRF Mitigation
During URL inspection, the system treats all inputs as untrusted strings. Live HTTP connections or DNS resolutions are strictly isolated and disabled during basic static feature parsing.
