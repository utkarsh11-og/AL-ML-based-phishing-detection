# AI/ML-Based Phishing Detection & Prevention Platform

A modular, explainable, and multi-layered cybersecurity defense system designed to detect, analyze, and mitigate malicious URLs and social engineering attacks using machine learning and heuristic intelligence.

---

## 🎯 Project Overview

Phishing remains one of the primary attack vectors in modern cybersecurity breaches. Traditional signature and blacklist-based approaches fail against zero-day phishing sites, algorithmically generated domains, and fast-flux infrastructure.

This platform bridges the gap between raw machine learning classification and actionable security operations by providing:
1. **Multi-Feature Heuristic Extraction**: Synthesizing lexical, structural, and domain-level signals.
2. **Transparent ML Classification**: Comparing classical and ensemble classifiers with a heavy emphasis on recall and low false-negative rates.
3. **Explainable AI (XAI)**: Providing clear security rationales behind each flagged indicator.
4. **Risk Scoring Engine**: Decoupling raw probabilistic predictions from policy-driven prevention actions (`ALLOW`, `WARN`, `BLOCK`).

---

## 🏛️ System Architecture

```
                    ┌─────────────────────────┐
                    │     Input Vector        │
                    │      (URL / Email)      │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │   Lexical & Structural  │
                    │    Feature Extractor    │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │   Supervised ML Model   │
                    │   (Trained Classifiers) │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │   Explainability (XAI)  │
                    │   & Feature Importance  │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │  Security Risk Engine   │
                    │   (Score: 0 - 100)      │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │    Prevention Action    │
                    │   ALLOW | WARN | BLOCK  │
                    └─────────────────────────┘
```

---

## 📁 Repository Structure

```
phishing-detection-platform/
│
├── .gitignore                  # Ignore caches, virtual environments, datasets & binaries
├── README.md                   # Project documentation
├── requirements.txt            # Python dependencies
│
├── docs/                       # Architectural and technical documentation
│   └── architecture.md         # Detailed system design
│
├── ml/                         # Machine learning pipelines
│   ├── datasets/               # Raw and processed datasets (gitignored)
│   │   ├── raw/
│   │   └── processed/
│   ├── features/               # URL and email feature extractors
│   ├── training/               # Training, validation & evaluation scripts
│   ├── models/                 # Serialized model weights (gitignored)
│   └── notebooks/              # Exploratory data analysis & experiments
│
├── src/                        # Core backend utilities & application logic
│
└── tests/                      # Unit, integration, and security edge-case tests
```

---

## 🚀 Getting Started

### 1. Prerequisites
- Python 3.10+
- Git

### 2. Setup Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 🔬 Academic Defense & Research Objectives
- **Why ML?** To generalize beyond static blacklists and catch zero-hour phishing campaigns.
- **Why Recall Matters:** In cybersecurity detection, missing a true phishing attempt (False Negative) can lead to credential theft and infrastructure compromise.
- **Explainability:** Security analysts need to know *why* a domain was blocked to mitigate false positive alert fatigue.

---

## ⚖️ Ethical & Defensive Use Notice
This tool is built strictly for defensive cybersecurity, academic research, and threat mitigation. It must not be utilized for malicious weaponization or reconnaissance.
