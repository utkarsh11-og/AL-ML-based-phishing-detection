# 🛡️ NEXORA PhishGuard — Master Execution & Command Guide

<div align="center">

### **Autonomous AI/ML Phishing Detection & Prevention Platform**
*Engineered & Researched by **Team NEXORA** // B.Tech CSE Cybersecurity Defense Lab*

![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue?logo=python)
![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20REST-009688?logo=fastapi)
![Scikit-Learn](https://img.shields.io/badge/ML%20Core-Random%20Forest%20%7C%20Ensemble-F7931E?logo=scikit-learn)
![Manifest V3](https://img.shields.io/badge/Browser%20Extension-Manifest%20V3-brightgreen?logo=googlechrome)
![License](https://img.shields.io/badge/Defensive-Cybersecurity%20Lab-red)

</div>

---

## 📑 Table of Contents
1. [⚡ Quick Start (1-Click Launcher)](#1--quick-start-1-click-launcher)
2. [💻 Complete Manual Setup Guide](#2--complete-manual-setup-guide)
3. [🧪 Complete Command Reference by Lifecycle](#3--complete-command-reference-by-lifecycle)
   - [A. Environment & Dependencies](#a-environment--dependencies)
   - [B. Live Real-Time Threat Feed Ingestion & Retraining](#b-live-real-time-threat-feed-ingestion--retraining)
   - [C. Running Model Training & Benchmarks](#c-running-model-training--benchmarks)
   - [D. Running Automated Tests](#d-running-automated-tests)
   - [E. Starting the Server & Dashboard](#e-starting-the-server--dashboard)
   - [F. CLI & API Testing Commands (cURL / PowerShell)](#f-cli--api-testing-commands-curl--powershell)
4. [🌐 Real-Time Browser Extension Setup](#4--real-time-browser-extension-setup)
5. [🧹 Telemetry & Log Management](#5--telemetry--log-management)
6. [🔧 Troubleshooting & Common Fixes](#6--troubleshooting--common-fixes)
7. [🎓 Academic Defense & Viva Quick Reference](#7--academic-defense--viva-quick-reference)

---

## 1. ⚡ Quick Start (1-Click Launcher)

> [!TIP]
> Use this method if you are moving the project to a new laptop and want zero configuration.

### For Windows:
1. Copy the project folder to the new laptop.
2. Double-click:
   ```cmd
   run_project.bat
   ```
*The script automatically configures Python `venv`, installs dependencies, trains/loads the champion model, adds a desktop shortcut, and opens the dashboard at [http://127.0.0.1:8000/dashboard/](http://127.0.0.1:8000/dashboard/).*

### For Linux / macOS:
```bash
chmod +x run_project.sh
./run_project.sh
```

---

## 2. 💻 Complete Manual Setup Guide

```
[Project Root] ──► [Create venv] ──► [Install Requirements] ──► [Run uvicorn Server]
```

### Step 1: Clone or Copy Directory
```bash
cd "e:/AL ML based phishing detection"
```

### Step 2: Create & Activate Virtual Environment

#### 🪟 Windows (PowerShell):
```powershell
python -m venv venv
.\venv\Scripts\activate
```

#### 🪟 Windows (Command Prompt `cmd.exe`):
```cmd
python -m venv venv
venv\Scripts\activate.bat
```

#### 🍎 macOS / 🐧 Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Core Dependencies
```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

## 3. 🧪 Complete Command Reference by Lifecycle

### A. Environment & Dependencies

| Task | Command |
|---|---|
| **Activate Environment (Windows)** | `.\venv\Scripts\activate` |
| **Activate Environment (Mac/Linux)** | `source venv/bin/activate` |
| **Deactivate Environment** | `deactivate` |
| **Check Installed Packages** | `pip list` |
| **Reinstall Clean Dependencies** | `pip install --force-reinstall -r requirements.txt` |

---

### B. Live Real-Time Threat Feed Ingestion & Retraining

Fetches fresh, unmitigated live phishing URLs from **OpenPhish** (`openphish.com/feed.txt`) and top global legitimate domains, re-extracts 22 feature dimensions, and retrains all 4 classifiers:

```bash
# Pull live feeds & retrain champion models
python ml/datasets/fetch_realtime_data.py
```

---

### C. Running Model Training & Benchmarks

Trains and cross-evaluates **Logistic Regression**, **Decision Tree**, **Random Forest**, and **Gradient Boosting**, generating `model_metadata.json` and serializing the champion to `ml/models/phishing_model_v1.joblib`:

```bash
# Train and generate model comparison table
python ml/training/train_models.py
```

#### Expected Benchmark Matrix:
```text
=============================================
        MODEL BENCHMARK COMPARISON          
=============================================
                    accuracy precision  recall f1_score roc_auc
Decision Tree          0.962      0.95  0.9744    0.962  0.9503
Random Forest          0.962      0.95  0.9744    0.962  0.9974 (🏆 Champion)
Gradient Boosting      0.962      0.95  0.9744    0.962  0.9968
Logistic Regression   0.9494    0.9268  0.9744     0.95  0.9923
=============================================
```

---

### D. Running Automated Tests

Run the complete 20-test suite verifying Feature Extraction, Model Inference, Risk Engine, Email Analyzer, SQLite Storage, and FastAPI REST endpoints:

```bash
# Run full pytest test suite
pytest tests/

# Run with verbose output and timing
pytest -v tests/

# Run tests for a specific module
pytest tests/test_risk_engine.py
pytest tests/test_api.py
```

---

### E. Starting the Server & Dashboard

Launch the high-performance asynchronous **FastAPI** server:

```bash
# Standard local start (Host: 127.0.0.1, Port: 8000)
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

# To make accessible across your local Wi-Fi / LAN network:
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

#### 🌐 Active Service URLs:
- 🖥️ **Interactive Web Dashboard**: [http://127.0.0.1:8000/dashboard/](http://127.0.0.1:8000/dashboard/)
- 📖 **Interactive Swagger API Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- 🩺 **Health Check API**: [http://127.0.0.1:8000/api/v1/health](http://127.0.0.1:8000/api/v1/health)
- 📊 **Telemetry Statistics**: [http://127.0.0.1:8000/api/v1/stats](http://127.0.0.1:8000/api/v1/stats)

---

### F. CLI & API Testing Commands (cURL / PowerShell)

#### 1. Analyze an Untrusted URL:
##### 🪟 PowerShell:
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/analyze/url" `
  -Method POST `
  -Headers @{"Content-Type"="application/json"} `
  -Body '{"url": "http://paypal.com@secure-verify-account.xyz/login.php"}' | ConvertTo-Json -Depth 5
```

##### 🐧 cURL (Bash / CMD):
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/analyze/url" \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"http://paypal.com@secure-verify-account.xyz/login.php\"}"
```

#### 2. Analyze a Suspicious Social Engineering Email:
##### 🪟 PowerShell:
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/analyze/email" `
  -Method POST `
  -Headers @{"Content-Type"="application/json"} `
  -Body '{
    "sender": "PayPal Support <security@fake-paypal-verify.xyz>",
    "subject": "URGENT: Your Account Has Been Locked!",
    "body": "Immediate action required. Verify your identity within 24 hours: http://paypal.com@secure-verify-account.xyz/login.php",
    "reply_to": "attacker-drop@tempmail.cc"
  }' | ConvertTo-Json -Depth 5
```

#### 3. Trigger Live Threat Feed Retraining via API:
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/dataset/refresh"
```

---

## 4. 🌐 Real-Time Browser Extension Setup

> [!IMPORTANT]
> The **NEXORA PhishGuard Extension (Manifest V3)** automatically scans active tabs in real-time and warns you before you enter credentials on deceptive sites.

```
                  ┌───────────────────────────────┐
                  │   Chrome / Edge Active Tab    │
                  └───────────────┬───────────────┘
                                  │ (Real-Time URL Check)
                                  ▼
                  ┌───────────────────────────────┐
                  │ NEXORA Background Worker (V3) │
                  └───────────────┬───────────────┘
                                  │ POST /api/v1/analyze/url
                                  ▼
                  ┌───────────────────────────────┐
                  │ Local AI Risk Engine (Port 8000)│
                  └───────────────┬───────────────┘
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
   [Toolbar Badge: OK / WARN / BLOCK]       [On-Page Red Warning Banner]
```

### 3-Step Setup:
1. Open your browser:
   - **Google Chrome / Brave**: `chrome://extensions`
   - **Microsoft Edge**: `edge://extensions`
2. Turn **ON** **"Developer mode"** toggle.
3. Click **"Load unpacked"** and select:
   ```text
   E:\AL ML based phishing detection\extension
   ```

---

## 5. 🧹 Telemetry & Log Management

All scans performed via the Web Dashboard, REST API, or Browser Extension are permanently logged in `scans.db` (SQLite).

### How to Clear All Audit Logs:
1. **Via UI**: Go to the **Scan Telemetry Log** tab and click **`🗑️ Clear Logs`**.
2. **Via Terminal / cURL**:
   ```bash
   curl -X DELETE "http://127.0.0.1:8000/api/v1/history"
   ```
3. **Via PowerShell**:
   ```powershell
   Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/history" -Method DELETE
   ```

---

## 6. 🔧 Troubleshooting & Common Fixes

### Issue 1: `Port 8000 is already in use`
#### Fix (Windows PowerShell):
```powershell
# Find process using port 8000
netstat -ano | findstr :8000

# Kill the process (replace <PID> with number in rightmost column)
taskkill /F /PID <PID>
```

### Issue 2: `ModuleNotFoundError: No module named 'fastapi'`
#### Fix:
Ensure you activated your virtual environment before running the server:
```powershell
.\venv\Scripts\activate
pip install -r requirements.txt
```

### Issue 3: `Extension shows OFFLINE in popup`
#### Fix:
Ensure your backend AI engine server is running in terminal:
```bash
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

---

## 7. 🎓 Academic Defense & Viva Quick Reference

| Defense Question | Technical Explanation |
|---|---|
| **Why use Machine Learning over static blacklists?** | Blacklists fail against zero-hour attacks, algorithmically generated domains (DGAs), and fast-flux infrastructure. ML generalizes by recognizing lexical and structural anomalies. |
| **Why is Recall prioritized over Accuracy?** | In cybersecurity, a **False Negative** (missing a phishing URL) leads to credential theft. A **False Positive** (wrongly flagging a safe site) is merely an inconvenience. High recall minimizes false negatives. |
| **How does Shannon Entropy detect attacks?** | Phishing kits and DGAs produce randomized hex/base64 strings. Shannon entropy mathematically quantifies string uncertainty ($-\sum p \log_2 p$). |
| **What is the role of the Risk Engine?** | Decouples raw probabilistic model outputs from actionable security policies (`ALLOW` <30, `WARN` 30–59, `STRONG_WARNING` 60–79, `BLOCK` 80–100). |
| **How is SSRF prevented during analysis?** | The feature extraction engine operates in an air-gapped static mode without performing live HTTP resolution or executing untrusted payloads. |

---

<div align="center">

**NEXORA PhishGuard Platform**  
*Built for Academic Excellence & Defensive Cybersecurity*  
*Developed by Team NEXORA*

</div>
