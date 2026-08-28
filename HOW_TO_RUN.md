# 🛡️ NEXORA PhishGuard — Master Project Guide & Architectural Blueprint

<div align="center">

### **Autonomous AI/ML Phishing Detection & Real-Time Prevention Platform**
*Engineered & Researched by **Team NEXORA** // B.Tech CSE Cybersecurity Defense Lab*

![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue?logo=python)
![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20REST-009688?logo=fastapi)
![Scikit-Learn](https://img.shields.io/badge/ML%20Core-Random%20Forest%20%7C%20Ensemble-F7931E?logo=scikit-learn)
![Manifest V3](https://img.shields.io/badge/Browser%20Extension-Manifest%20V3-brightgreen?logo=googlechrome)
![SQLite](https://img.shields.io/badge/Storage-Persistent%20SQLite3-003B57?logo=sqlite)
![Threat Feeds](https://img.shields.io/badge/Threat%20Intel-OpenPhish%20Live-critical)

</div>

---

## 📑 Table of Contents
1. [🌟 Platform Overview](#1--platform-overview)
2. [🏛️ Complete System Architecture](#2--complete-system-architecture)
3. [🧬 The 22 Extracted Feature Dimensions (Deep Dive)](#3--the-22-extracted-feature-dimensions-deep-dive)
4. [✉️ Email Social Engineering Detection Heuristics](#4--email-social-engineering-detection-heuristics)
5. [🧠 Machine Learning Methodology & Benchmarks](#5--machine-learning-methodology--benchmarks)
6. [⚖️ Security Risk Engine & Policy Matrix](#6--security-risk-engine--policy-matrix)
7. [🛠️ Complete Technology Stack Used](#7--complete-technology-stack-used)
8. [⚡ Quick Start Guide (1-Click & Manual)](#8--quick-start-guide-1-click--manual)
9. [🧪 Complete Command Reference by Lifecycle](#9--complete-command-reference-by-lifecycle)
10. [🌐 Real-Time Browser Extension Integration](#10--real-time-browser-extension-integration)
11. [🧹 Telemetry & Audit Log Management](#11--telemetry--audit-log-management)
12. [🎓 Academic Viva Defense & Research FAQ](#12--academic-viva-defense--research-faq)

---

## 1. 🌟 Platform Overview

**NEXORA PhishGuard** is a defense-in-depth cybersecurity platform that combines **supervised machine learning**, **information theory (Shannon Entropy)**, **lexical heuristics**, and **real-time browser extension monitoring** to detect and neutralize zero-hour phishing attacks before credentials can be stolen.

### Key Capabilities:
- **Zero-Hour Detection**: Does not rely purely on stale static blacklists; generalizes to detect novel attack patterns using trained ensemble models.
- **Air-Gapped Static Analysis**: Extracts 22 mathematical and structural features without initiating dangerous server-side network requests (prevents **Server-Side Request Forgery - SSRF**).
- **Explainable AI (XAI)**: Demystifies model predictions by generating plain-English, prioritized security reasons with severity ratings (`critical`, `warning`, `info`).
- **Decoupled Risk Scoring**: Combines ML probabilities with heuristic red flags to output a calibrated **0–100 Risk Score** and enforce policy actions (`ALLOW`, `WARN`, `STRONG_WARNING`, `BLOCK`).
- **Real-Time Browser Extension**: A Manifest V3 background service worker actively intercepts active tabs and displays on-page warning banners on deceptive domains.
- **Real-Time Threat Intelligence Pipeline**: Ingests live threat feeds from **OpenPhish** and verified domain feeds with on-demand automated retraining.

---

## 2. 🏛️ Complete System Architecture

```
                    ┌──────────────────────────────────────────────────┐
                    │               CLIENT SURFACES                    │
                    │  ┌─────────────────────────┐  ┌───────────────┐  │
                    │  │ Cybersecurity Dashboard │  │ Chrome / Edge │  │
                    │  │ (Dark/Light Cyber UI)   │  │ Extension(V3) │  │
                    │  └────────────┬────────────┘  └───────┬───────┘  │
                    └───────────────┼───────────────────────┼──────────┘
                                    │ HTTP REST (JSON)      │
                                    ▼                       ▼
                    ┌──────────────────────────────────────────────────┐
                    │            FASTAPI BACKEND ENGINE                │
                    │   (Pydantic v2 Validation, CORS, Telemetry)      │
                    └───────────────┬───────────────────────┬──────────┘
                                    │                       │
             ┌──────────────────────┴───────┐       ┌───────┴──────────────────────┐
             ▼                              ▼       ▼                              ▼
    ┌─────────────────┐             ┌───────────────┐                    ┌─────────────────┐
    │   URL Feature   │             │   Email NLP   │                    │ OpenPhish Live  │
    │    Extractor    │             │ Social Engine │                    │ Ingestion Feed  │
    │ (22 Dimensions) │             │ (Urgency/Auth)│                    │  (Auto-Retrain) │
    └────────┬────────┘             └───────┬───────┘                    └────────┬────────┘
             │                              │                                     │
             ▼                              ▼                                     ▼
    ┌───────────────────────────────────────────────┐                    ┌─────────────────┐
    │             ML MODEL REGISTRY                 │                    │ Train/Test Split│
    │  🏆 Champion: Random Forest (100 Trees)       │◄───────────────────┤ & Stratification│
    │  Benchmarked: GradientBoost, DT, LogisticReg  │                    └─────────────────┘
    └───────────────────────┬───────────────────────┘
                            │ Class Probability: P(phishing|x)
                            ▼
    ┌───────────────────────────────────────────────┐
    │     EXPLAINABILITY (XAI) & RISK ENGINE        │
    │  - Hard Red-Flag Modifiers (+35 IP, +35 @)    │
    │  - Calibrated 0–100 Risk Score                │
    │  - Enforced Policy: ALLOW | WARN | BLOCK      │
    └───────────────────────┬───────────────────────┘
                            │
                            ▼
    ┌───────────────────────────────────────────────┐
    │         PERSISTENT AUDIT STORAGE              │
    │             (SQLite: scans.db)                │
    └───────────────────────────────────────────────┘
```

---

## 3. 🧬 The 22 Extracted Feature Dimensions (Deep Dive)

Every target URL is parsed into a **22-dimensional numerical vector** in under **1 millisecond**:

| # | Feature Name | Category | Mathematical / Logic Definition | Security Attack Vector Rationale |
|---|---|---|---|---|
| **1** | `url_length` | Length | $\text{len}(\text{raw\_url})$ | Attackers construct very long URLs (>75 chars) to push malicious domains out of view on mobile address bars. |
| **2** | `hostname_length` | Length | $\text{len}(\text{hostname})$ | Long hostnames often contain nested domain mimicry (e.g. `chase.com.account-update.xyz`). |
| **3** | `path_length` | Length | $\text{len}(\text{path})$ | Complex path trees hide obfuscated redirect scripts and phishing kit endpoints. |
| **4** | `query_length` | Length | $\text{len}(\text{query})$ | Encodes stolen session parameters, Base64 victims' email hashes, or redirect payloads. |
| **5** | `num_dots` | Structural | Count of `.` characters | Phishers create deep subdomain chains (e.g., `paypal.com.verify.identity.evil.com`). |
| **6** | `num_hyphens` | Structural | Count of `-` characters | Attackers use hyphens to mimic legitimate brands (e.g., `pay-pal-secure-login.com`). |
| **7** | `num_underscores` | Structural | Count of `_` characters | Used in dynamic session tokens or script names to evade simple keyword filters. |
| **8** | `num_slashes` | Structural | Count of `/` characters | Excess directory slashes indicate deep file nesting common in unmanaged hacked hosts. |
| **9** | `num_questionmarks`| Structural | Count of `?` characters | Delimits query parameters; multiple question marks indicate URL obfuscation. |
| **10**| `num_equal_signs` | Structural | Count of `=` characters | Multiple parameters indicate credential harvesting forms passing victim variables. |
| **11**| `num_at_symbols` | Deception | Count of `@` characters | **Critical attack pattern**: Browsers ignore everything before `@` (e.g., `paypal.com@evil.com` directs straight to `evil.com`). |
| **12**| `num_percent_signs`| Obfuscation | Count of `%` characters | URL-encoding (e.g. `%20`, `%2F`, `%3D`) used to hide malicious keywords from naive pattern matchers. |
| **13**| `num_ampersands` | Structural | Count of `&` characters | Indicates parameter chaining in phishing session tracking scripts. |
| **14**| `num_digits` | Obfuscation | Total count of `0–9` | Phishing URLs use random numerical tokens to create one-time disposable landing pages. |
| **15**| `digit_ratio` | Statistical | $\frac{\text{num\_digits}}{\text{url\_length}}$ | Elevated digit concentration (>15%) is characteristic of automated domain generation algorithms (DGAs). |
| **16**| `num_subdomains` | DNS / Hierarchy | Count of subdomains via `tldextract` | Isolates true registered domain vs abusive subdomain prefixes. Depth $\ge 3$ indicates subdomain spoofing. |
| **17**| `has_ip_address` | Structural | IPv4 Regex pattern match | **Hard Red Flag**: Legitimate institutions never host public customer login portals on raw IP addresses (e.g. `http://192.168.1.1/login`). |
| **18**| `is_https` | Cryptographic | Scheme == `"https"` | While phishers can obtain free SSL certs, unencrypted HTTP forms for authentication remain inherently dangerous. |
| **19**| `has_double_slash_redirect` | Structural | `"//"` in path past index 7 | Exploits browser URL normalization to trigger open-redirect vulnerabilities. |
| **20**| `keyword_count` | Heuristic | Count of targeted auth terms | Checks for sensitive keywords: `login`, `verify`, `account`, `banking`, `update`, `security`, `wallet`, `admin`. |
| **21**| `url_entropy` | Info Theory | $-\sum P(c) \log_2 P(c)$ on URL | Measures character randomness. High entropy (>4.5) detects randomized hashes and DGA tokens. |
| **22**| `hostname_entropy` | Info Theory | $-\sum P(c) \log_2 P(c)$ on Host | Measures domain randomness. Detects machine-generated disposable domains. |

---

## 4. ✉️ Email Social Engineering Detection Heuristics

The **Email Phishing Analyzer** ([`src/email_analyzer.py`](file:///e:/AL%20ML%20based%20phishing%20detection/src/email_analyzer.py)) protects against social engineering via 4 automated inspection layers:

```
                    ┌─────────────────────────────────────────┐
                    │               EMAIL INPUT               │
                    │   (Sender, Reply-To, Subject, Body)     │
                    └────────────────────┬────────────────────┘
                                         │
        ┌────────────────────────────────┼────────────────────────────────┐
        ▼                                ▼                                ▼
┌───────────────────────┐ ┌─────────────────────────────┐ ┌──────────────────────────────┐
│  Brand Impersonation  │ │  Reply-To Redirection Check │ │ Psychological Urgency Engine │
│  Display: "PayPal"    │ │  Sender: @update-portal.xyz │ │ "Account Suspended Within    │
│  Domain: @evil.xyz    │ │  Reply-To: @attacker-drop.cc│ │  24 Hours - Act Immediately" │
└───────────┬───────────┘ └──────────────┬──────────────┘ └──────────────┬───────────────┘
            │                            │                               │
            └────────────────────────────┼───────────────────────────────┘
                                         ▼
                        ┌─────────────────────────────────┐
                        │   Embedded URL Hyperlink Core   │
                        │ (Extracts & Runs URL Risk Engine│
                        │    on every embedded link)      │
                        └────────────────┬────────────────┘
                                         │
                                         ▼
                        ┌─────────────────────────────────┐
                        │    Aggregated Threat Verdict    │
                        │   Score: 0-100 (ALLOW/WARN/BLOCK│
                        └─────────────────────────────────┘
```

1. **Brand Impersonation & Display Name Spoofing**: Cross-checks sender display names against verified domain whitelists for 17+ targeted institutions (PayPal, Microsoft, Apple, Chase, Google, Binance, DHL, etc.).
2. **Reply-To Address Redirection**: Detects return-path manipulation where replies are silently rerouted to an attacker's drop box.
3. **Psychological Urgency & Coercion Regex**: Identifies social engineering triggers designed to induce panic (`"within 24 hours"`, `"account suspended"`, `"unauthorized login"`, `"tax refund"`, `"wire transfer"`).
4. **Embedded Hyperlink Extraction**: Parses all URLs in the email body and runs each through the full 22-feature ML Risk Engine.

---

## 5. 🧠 Machine Learning Methodology & Benchmarks

### Training & Evaluation Protocol
- **Dataset**: Real-time stream of verified active phishing URLs from **OpenPhish Community Feed** paired with top global legitimate domains from **Tranco/Cisco Umbrella**.
- **Split**: 80% Training ($X_{\text{train}}, y_{\text{train}}$), 20% Testing ($X_{\text{test}}, y_{\text{test}}$) using **Stratified K-Fold splitting** to eliminate data leakage.

### Multi-Model Benchmark Comparison Table:

| Model Candidate | Algorithm Type | Test Accuracy | Precision (Phish) | Recall (Phish) | F1-Score | ROC-AUC | Production Verdict |
|---|---|---|---|---|---|---|---|
| **Random Forest** | Ensemble (100 Trees) | **96.20%** | **95.00%** | **97.44%** | **0.9620** | **0.9974** | 🏆 **Selected Champion** |
| **Gradient Boosting**| Boosting Ensemble | 96.20% | 95.00% | 97.44% | 0.9620 | 0.9968 | Strong Runner-up |
| **Decision Tree** | Single CART Tree | 96.20% | 95.00% | 97.44% | 0.9620 | 0.9503 | High Variance Risk |
| **Logistic Regression**| Linear Classifier | 94.94% | 92.68% | 97.44% | 0.9500 | 0.9923 | Baseline |

### Why Random Forest is the Champion Model:
1. **Low Variance**: A single decision tree is prone to overfitting on specific URL keywords. Random Forest averages predictions across 100 decorrelated trees.
2. **Superior ROC-AUC (0.9974)**: Demonstrates near-perfect class separability across all probabilistic thresholds.
3. **High Recall (97.44%)**: Minimizes False Negatives (the most critical failure mode in cybersecurity).

---

## 6. ⚖️ Security Risk Engine & Policy Matrix

The **Risk Engine** ([`src/risk_engine.py`](file:///e:/AL%20ML%20based%20phishing%20detection/src/risk_engine.py)) calculates a calibrated **0–100 integer score** using defense-in-depth weighting:

$$\text{Final Risk Score} = \min\Big(100, \; \max\big(0, \; (\text{ML\_Probability} \times 100 \times 0.6) + (\text{Heuristic\_Modifiers} \times 0.4)\big)\Big)$$

### Policy Enforcement Tiers:

| Risk Score | Tier | Enforced Action | Description & Recommendation |
|---|---|---|---|
| **0 – 29** | `LOW` | **`ALLOW`** | Safe to access. URL exhibits standard lexical structure and trusted indicators. |
| **30 – 59** | `MEDIUM` | **`WARN`** | Exercise caution. Suspicious structural or lexical anomalies detected. |
| **60 – 79** | `HIGH` | **`STRONG_WARNING`** | High risk of phishing. Do not submit sensitive passwords, MFA tokens, or card details. |
| **80 – 100** | `CRITICAL`| **`BLOCK`** | Critical threat detected. Connection should be blocked to prevent credential theft. |

---

## 7. 🛠️ Complete Technology Stack Used

| Layer | Technology | Version | Specific Purpose in Project |
|---|---|---|---|
| **Core Language** | Python | `3.10+ / 3.12` | End-to-end backend, feature engineering, and ML modeling. |
| **ML & Data Science** | Scikit-Learn | `>=1.3.0` | Random Forest, Gradient Boosting, Decision Tree, Logistic Regression. |
| **Data Manipulation** | Pandas & NumPy | `>=2.0.0` | Dataframe transformations, CSV ingestion, vector calculations. |
| **Domain Parsing** | Tldextract | `>=5.0.0` | Accurate Public Suffix List domain/subdomain extraction. |
| **Backend REST API** | FastAPI | `>=0.100.0` | High-performance asynchronous REST API with OpenAPI Swagger docs. |
| **ASGI Web Server** | Uvicorn | `>=0.23.0` | Production ASGI web server running on port 8000. |
| **Data Validation** | Pydantic | `v2.x` | Strict request/response schema validation and type safety. |
| **Audit Database** | SQLite3 | Native | Zero-configuration persistent telemetry and scan audit logging (`scans.db`). |
| **Model Serialization**| Joblib | `>=1.3.0` | Fast serialization of trained estimator pipelines (`.joblib`). |
| **Automated Testing** | Pytest & HTTPX | `>=7.4.0` | 20 unit and integration tests covering all features and endpoints. |
| **Frontend UI** | HTML5, CSS3, JS | Modern | Responsive cyber glassmorphism dashboard with SVG live risk gauges. |
| **Browser Extension** | Chrome Manifest V3| `v3` | Background service worker and content script domain protection. |

---

## 8. ⚡ Quick Start Guide (1-Click & Manual)

### 🪟 1-Click Launch on Any Windows PC:
1. Copy the project folder to the computer.
2. Double-click:
   👉 **`run_project.bat`**
*The script automatically sets up the environment, installs packages, trains the model, adds a desktop shortcut, and opens the dashboard!*

### 💻 Manual Step-by-Step Setup:
```powershell
# 1. Open Terminal in Project Root
cd "e:/AL ML based phishing detection"

# 2. Create and Activate Virtual Environment
python -m venv venv
.\venv\Scripts\activate       # Windows
# source venv/bin/activate    # Mac/Linux

# 3. Install Dependencies
pip install -r requirements.txt

# 4. Start the AI Server
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

---

## 9. 🧪 Complete Command Reference by Lifecycle

### A. Environment & Package Management
```bash
# Activate venv (Windows)
.\venv\Scripts\activate

# Activate venv (Mac/Linux)
source venv/bin/activate

# Install / update all dependencies
pip install -r requirements.txt
```

### B. Live Threat Feed Ingestion & Retraining
```bash
# Pull fresh OpenPhish threat feeds & retrain champion models
python ml/datasets/fetch_realtime_data.py
```

### C. Manual Model Benchmarking
```bash
# Run multi-model cross-evaluation and save comparison metrics
python ml/training/train_models.py
```

### D. Automated Pytest Test Suite
```bash
# Run all 20 unit and integration tests
pytest tests/

# Run with verbose test-by-test breakdown
pytest -v tests/
```

### E. Server & Dashboard
```bash
# Start FastAPI backend server
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
- **Dashboard**: [http://127.0.0.1:8000/dashboard/](http://127.0.0.1:8000/dashboard/)
- **Swagger Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### F. API Endpoint Testing via cURL / PowerShell

#### Analyze a URL:
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/analyze/url" \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"http://paypal.com@secure-verify-account.xyz/login.php\"}"
```

#### Analyze a Phishing Email:
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/analyze/email" \
  -H "Content-Type: application/json" \
  -d "{
    \"sender\": \"PayPal Support <security@fake-paypal-verify.xyz>\",
    \"subject\": \"URGENT: Your Account Has Been Locked!\",
    \"body\": \"Immediate action required. Verify your identity within 24 hours: http://paypal.com@secure-verify-account.xyz/login.php\",
    \"reply_to\": \"attacker-drop@tempmail.cc\"
  }"
```

---

## 10. 🌐 Real-Time Browser Extension Integration

Located in: [`extension/`](file:///e:/AL%20ML%20based%20phishing%20detection/extension)

### How to Install in Chrome / Edge in 3 Steps:
1. Navigate to `chrome://extensions` or `edge://extensions`.
2. Turn **ON** **Developer mode**.
3. Click **"Load unpacked"** and select:
   ```text
   E:\AL ML based phishing detection\extension
   ```
✅ *The **NEXORA Shield** icon will now appear in your browser toolbar, protecting every website you visit in real time!*

---

## 11. 🧹 Telemetry & Audit Log Management

All scans are permanently recorded in `scans.db`.

### To Clear Logs:
- **Dashboard**: Click **`🗑️ Clear Logs`** on the **Scan Telemetry Log** tab.
- **Terminal**:
  ```bash
  curl -X DELETE "http://127.0.0.1:8000/api/v1/history"
  ```

---

## 12. 🎓 Academic Viva Defense & Research FAQ

### Q1: What problem does this project solve?
> **Answer**: Traditional phishing detection relies on static URL blacklists, which fail against zero-hour phishing attacks, fast-flux DNS, and algorithmically generated domains (DGAs). NEXORA PhishGuard extracts 22 structural, lexical, and information-theory features to detect novel attacks mathematically before they appear on blacklists.

### Q2: Why is Recall prioritized over Accuracy?
> **Answer**: In cybersecurity detection, a **False Negative** (missing an actual phishing attack) leads to credential theft and financial compromise. A **False Positive** (wrongly warning on a safe site) is merely an inconvenience. Prioritizing Recall minimizes dangerous False Negatives.

### Q3: How does Shannon Entropy detect obfuscated phishing?
> **Answer**: Shannon Entropy ($H = -\sum p \log_2 p$) measures character randomness. Standard human-readable domains have low-to-medium entropy (~2.5–3.5), whereas automated DGA domains, base64-encoded strings, and randomized hex tokens exhibit high entropy (>4.5).

### Q4: How is Server-Side Request Forgery (SSRF) prevented?
> **Answer**: The static feature extraction engine operates purely on lexical string decomposition without resolving DNS queries or initiating live HTTP requests to untrusted targets.

---

<div align="center">

**NEXORA PhishGuard Platform**  
*Academic Research & Defensive Cybersecurity System*  
*Engineered by **Team NEXORA***

</div>
