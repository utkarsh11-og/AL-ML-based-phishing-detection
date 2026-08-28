# Stage 0 — Project Foundation

Welcome to building your AI/ML-based Phishing Detection & Prevention Platform. Before we write a single line of code, let's make sure you deeply understand **what** we're building, **why** each piece exists, and **how** it all fits together.

---

## 1. Project Architecture — In Simple Terms

Think of the final system as a **security checkpoint** at an airport. When a URL (or later, an email) arrives, it goes through multiple screening layers before a final verdict is given.

```
                    USER
                      │
                      ▼
            ┌──────────────────┐
            │    Frontend      │  ← The "ticket counter" — where a user submits a URL
            │  (Next.js/React) │
            └────────┬─────────┘
                     │
                     ▼
            ┌──────────────────┐
            │    Backend API   │  ← The "security desk" — receives the URL, orchestrates analysis
            │    (FastAPI)     │
            └────────┬─────────┘
                     │
      ┌──────────────┼──────────────┐
      ▼              ▼              ▼
┌────────────┐ ┌────────────┐ ┌──────────────┐
│Feature     │ │ ML Model   │ │Threat Intel  │
│Extraction  │ │ Engine     │ │(Optional)    │
└─────┬──────┘ └─────┬──────┘ └──────┬───────┘
      │              │               │
      └──────────────┼───────────────┘
                     ▼
            ┌──────────────────┐
            │   Risk Engine    │  ← Combines all signals into a risk score
            └────────┬─────────┘
                     ▼
            ┌──────────────────┐
            │Prevention Layer  │  ← Makes the ALLOW / WARN / BLOCK decision
            └────────┬─────────┘
                     ▼
            ┌──────────────────┐
            │   Database       │  ← Stores scan history and results
            │  (PostgreSQL)    │
            └──────────────────┘
```

### What each layer does:

| Layer | Analogy | What It Does |
|---|---|---|
| **Frontend** | Ticket counter | User types a URL, sees results on a dashboard |
| **Backend API** | Security desk | Receives the URL, calls the right services, returns the verdict |
| **Feature Extraction** | X-ray scanner | Breaks the URL into measurable properties (length, special characters, etc.) |
| **ML Model** | Trained security officer | Looks at the features and predicts: phishing or legitimate? |
| **Threat Intelligence** | Watchlist database | Checks if the domain is already known to be malicious |
| **Risk Engine** | Risk assessor | Combines ML prediction + feature signals + threat intel into a 0–100 risk score |
| **Prevention Layer** | Gate decision | Based on the risk score, decides: allow, warn, or block |
| **Database** | Log book | Records every scan for history, analytics, and auditing |

> [!IMPORTANT]
> We are **NOT** building all of this on day one. We start with the smallest working piece and grow outward. The first version is just: **URL → Features → ML Model → Prediction**.

---

## 2. Development Roadmap

Here's our build order, starting from the simplest piece:

### Phase 1 — The Core ML Pipeline (Stages 0–5)
```
Week 1-2:   Understand phishing, ML concepts, set up project
Week 3-4:   Get dataset, clean it, explore it
Week 5-6:   Extract URL features
Week 7-8:   Train baseline models, evaluate, compare
Week 9:     Select best model, document experiments
```

### Phase 2 — Making It Usable (Stages 6–9)
```
Week 10:    Add model explainability (why is this URL suspicious?)
Week 11:    Build risk engine (convert probability → risk score)
Week 12-13: Build backend API (FastAPI)
Week 14-16: Build frontend dashboard (Next.js)
```

### Phase 3 — Making It Robust (Stages 10–16)
```
Week 17:    Add database (PostgreSQL)
Week 18-19: Email phishing detection
Week 20:    Advanced ML/NLP (only if baseline needs improvement)
Week 21:    Threat intelligence layer
Week 22:    Prevention logic
Week 23:    Security hardening
Week 24:    Testing
```

### Phase 4 — Making It Professional (Stages 17–19)
```
Week 25:    MLOps (versioning, tracking)
Week 26:    Docker + deployment
Week 27:    Final architecture, documentation, polish
```

> [!NOTE]
> These weeks are estimates. Some stages will take longer, some shorter. The key is: **never skip a stage**. Each stage builds understanding for the next.

---

## 3. Minimum Technologies You Need to Learn

You don't need to master everything before starting. Here's what you need **per phase**:

### Phase 1 (Start here)
| Technology | Why |
|---|---|
| **Python 3.10+** | Core language for ML, data science, and backend |
| **Virtual environments** (`venv`) | Isolate project dependencies |
| **pip** | Install Python packages |
| **pandas** | Load, inspect, and clean datasets |
| **NumPy** | Numerical operations behind the scenes |
| **matplotlib / seaborn** | Visualize data distributions and results |
| **scikit-learn** | Train and evaluate ML models |
| **Git** | Version control your work |
| **Jupyter Notebook** (optional) | Explore data interactively |

### Phase 2 (After ML works)
| Technology | Why |
|---|---|
| **FastAPI** | Build the backend REST API |
| **Pydantic** | Validate API inputs/outputs |
| **SHAP** | Explain model predictions |
| **Next.js + React + TypeScript** | Build the frontend dashboard |
| **Tailwind CSS** | Style the frontend |

### Phase 3–4 (After the app works)
| Technology | Why |
|---|---|
| **PostgreSQL** | Persistent storage |
| **SQLAlchemy** | Python ORM for database |
| **Docker** | Containerize for deployment |
| **pytest** | Automated testing |

> [!TIP]
> I will teach you each technology **when we need it**, not before. You don't need to go learn Next.js right now.

---

## 4. What We Will Build in Version 1

**Version 1 (V1)** is the **Minimum Viable Detector**. It proves the core concept works.

### V1 Scope:
```
Input:  A URL string (e.g., "http://paypa1-secure.login.com/verify?id=12345")
          │
          ▼
    Feature Extraction
    (URL length, number of dots, has IP address, etc.)
          │
          ▼
    ML Model (e.g., Random Forest)
          │
          ▼
Output: { classification: "phishing", confidence: 0.93 }
```

### V1 delivers:
- ✅ A cleaned, validated dataset
- ✅ A feature extraction module that breaks URLs into numeric features
- ✅ Multiple trained ML models compared fairly
- ✅ Proper evaluation metrics (not just accuracy)
- ✅ A selected baseline model with documented reasoning
- ✅ A simple script: give it a URL, get a prediction

### V1 does NOT include:
- ❌ No web interface (yet)
- ❌ No API (yet)
- ❌ No database (yet)
- ❌ No email analysis (yet)
- ❌ No threat intelligence (yet)
- ❌ No deployment (yet)

This is deliberate. We prove the ML core works before adding layers around it.

---

## 5. Rule-Based vs. ML-Based Phishing Detection

This is a critical concept to understand before we write any code.

### Rule-Based Detection (Traditional)

A human security analyst writes explicit rules:

```
IF url contains "login" AND url contains "paypal" AND domain is NOT "paypal.com"
    THEN mark as phishing

IF url uses IP address instead of domain name
    THEN mark as suspicious

IF url length > 75 characters
    THEN flag for review
```

**Strengths:**
- Easy to understand and audit
- No training data needed
- Deterministic (same input → same output every time)

**Weaknesses:**
- Attackers read the same rules and craft URLs to bypass them
- Requires constant manual updates
- Cannot generalize — a rule for PayPal doesn't help detect a fake Amazon URL
- Doesn't scale — thousands of rules become unmaintainable
- Cannot detect **novel** attacks it hasn't seen before

### ML-Based Detection (Our Approach)

Instead of writing rules manually, we show the model **thousands of examples** of phishing URLs and legitimate URLs. The model **learns patterns** from the data.

```
Training:
    Phishing URLs    →  ┌──────────┐
                        │ ML Model │  ← learns patterns automatically
    Legitimate URLs  →  └──────────┘

Prediction:
    New unknown URL  →  ┌──────────┐  → "phishing" (87% confidence)
                        │ ML Model │
                        └──────────┘
```

**Strengths:**
- Generalizes to new, unseen attacks
- Can detect subtle patterns humans might miss
- Scales — one model handles millions of URLs
- Improves as you feed it more data

**Weaknesses:**
- Requires quality training data
- Can produce false positives (blocking legitimate URLs)
- Can produce false negatives (missing actual phishing)
- Less interpretable — harder to explain *why* a URL was flagged
- Can be fooled by **adversarial** inputs designed to trick the model

### What We'll Actually Do

We'll use **ML as the core** but with **rule-like feature engineering**. This gives us the best of both worlds:

1. We manually design features that capture security-relevant properties of URLs (this is our domain expertise)
2. We let the ML model learn which combinations of features indicate phishing (this is what ML is good at)
3. We add explainability so we can understand and audit the model's decisions

---

## 6. ML Classification Concepts — Applied to Our Project

### What is Classification?

Classification is a type of ML problem where the model assigns an input to one of several **predefined categories**.

In our case, it's **binary classification** — exactly two categories:
- **Class 0**: Legitimate (safe URL)
- **Class 1**: Phishing (malicious URL)

### Features (What the model sees)

A **feature** is a measurable property of the input. The model doesn't "see" the URL as text. We convert the URL into numbers.

Example — for the URL `http://paypa1-secure.login.com/verify?id=12345`:

| Feature | Value |
|---|---|
| url_length | 47 |
| hostname_length | 24 |
| num_dots | 3 |
| num_hyphens | 1 |
| num_digits | 6 |
| has_https | 0 (no) |
| has_ip_address | 0 (no) |
| num_subdomains | 2 |
| has_at_symbol | 0 |
| url_entropy | 3.82 |

The ML model receives this row of numbers, **not** the original URL string.

### Labels (What the model predicts)

A **label** is the correct answer. In our dataset, each URL has a label:
- `0` = legitimate
- `1` = phishing

During training, the model sees both features and labels. During prediction, it sees only features and must guess the label.

### Training, Validation, and Testing

This is one of the most important concepts. We split our data into three parts:

```
Full Dataset (e.g., 100,000 URLs)
    │
    ├── Training Set (70%)    → Model learns from this
    │
    ├── Validation Set (15%)  → We tune the model using this
    │
    └── Test Set (15%)        → We evaluate FINAL performance on this
```

**Why three sets?**

| Set | Purpose | Analogy |
|---|---|---|
| Training | Model learns patterns | Studying textbook problems |
| Validation | We adjust model settings | Solving practice exams |
| Test | Final, unbiased evaluation | The actual exam |

> [!CAUTION]
> **Data Leakage**: If the model ever "sees" test data during training (even indirectly), your evaluation is invalid. The test set must remain completely untouched until final evaluation. This is the #1 mistake in student ML projects.

### Why Accuracy Alone Is Insufficient

Suppose our dataset has 9,000 legitimate URLs and 1,000 phishing URLs (90/10 split).

A completely useless model that **always predicts "legitimate"** would achieve:

```
Accuracy = 9,000 correct / 10,000 total = 90% ✨
```

90% accuracy! Sounds great, right? But it **misses every single phishing URL**. That's catastrophic for a security tool.

This is why we need multiple metrics:

### The Metrics We'll Use

| Metric | What it measures | In our context |
|---|---|---|
| **Precision** | Of all URLs we flagged as phishing, how many actually were? | "When we say phishing, are we right?" |
| **Recall** | Of all actual phishing URLs, how many did we catch? | "Are we catching all the phishing?" |
| **F1-Score** | Harmonic mean of precision and recall | Balance between catching phishing and not over-flagging |
| **Confusion Matrix** | Table showing all 4 outcomes (TP, FP, TN, FN) | Complete picture of model performance |
| **ROC-AUC** | How well the model separates the two classes across all thresholds | Overall discriminative ability |

### The Confusion Matrix — Explained for Phishing

```
                        Predicted
                    Legit    Phishing
               ┌──────────┬──────────┐
Actual Legit   │   TN     │   FP     │
               │ (Correct)│ (Annoying│
               │          │  but safe)│
               ├──────────┼──────────┤
Actual Phish   │   FN     │   TP     │
               │(DANGEROUS│ (Correct)│
               │  miss!)  │          │
               └──────────┴──────────┘
```

- **True Positive (TP)**: We correctly flagged a phishing URL ✅
- **True Negative (TN)**: We correctly allowed a legitimate URL ✅
- **False Positive (FP)**: We flagged a legitimate URL as phishing ⚠️ (annoying, user can't access a safe site)
- **False Negative (FN)**: We missed a phishing URL 🚨 (dangerous — user visits a malicious site)

> [!IMPORTANT]
> **For phishing detection, False Negatives are more dangerous than False Positives.** Missing a phishing URL can lead to credential theft, financial loss, or malware infection. Wrongly blocking a legitimate URL is inconvenient but safe. This means we generally want **high recall** — catch as many phishing URLs as possible, even at the cost of some false alarms.

### Precision and Recall — Formulas

```
Precision = TP / (TP + FP)
            "Of everything we called phishing, how much actually was?"

Recall    = TP / (TP + FN)
            "Of all actual phishing, how much did we catch?"

F1-Score  = 2 × (Precision × Recall) / (Precision + Recall)
            "A single number that balances both"
```

### Real Example

Suppose our model analyzes 1,000 URLs (200 are actually phishing):

| | Predicted Legit | Predicted Phishing |
|---|---|---|
| **Actually Legit** (800) | 750 (TN) | 50 (FP) |
| **Actually Phishing** (200) | 20 (FN) | 180 (TP) |

```
Accuracy  = (750 + 180) / 1000 = 93.0%
Precision = 180 / (180 + 50)   = 78.3%  ← "When we say phishing, we're right 78% of the time"
Recall    = 180 / (180 + 20)   = 90.0%  ← "We catch 90% of phishing URLs"
F1-Score  = 2 × (0.783 × 0.90) / (0.783 + 0.90) = 83.7%
```

We missed 20 phishing URLs (FN = 20). In a security context, those 20 could mean 20 users who had their credentials stolen.

---

## 7. Recommended Initial Dataset

For URL phishing detection, I recommend starting with one of these well-known, publicly available datasets:

### Primary Recommendation: UCI Phishing Websites Dataset

- **Source**: UCI Machine Learning Repository
- **URL**: https://archive.ics.uci.edu/dataset/327/phishing+websites
- **Size**: ~11,055 instances
- **Features**: 30 pre-extracted features
- **Labels**: Binary (-1 = phishing, 1 = legitimate)
- **Why**: Well-documented, academically cited, good starting size

### Alternative: Kaggle Phishing URL Datasets

Several community-contributed datasets on Kaggle contain raw URLs with labels. These are useful because we can practice **feature extraction ourselves** rather than using pre-extracted features.

Search for: "phishing URL dataset" on Kaggle.

Notable options:
- **"Malicious URLs Dataset"** (~650K URLs with types)
- **"Phishing Site URLs"** (~550K URLs with labels)

### What to Look For in a Dataset

| Property | What to check | Why it matters |
|---|---|---|
| **Size** | At least 5,000–10,000 samples | Too small → model can't learn; too large → slow to start |
| **Balance** | Roughly equal phishing and legitimate | Heavily imbalanced data needs special handling |
| **Labels** | Binary (phishing/legitimate) | Must have ground truth labels |
| **Recency** | How old is the data? | Phishing evolves; very old data may not represent current attacks |
| **Source credibility** | Who collected it? How? | Determines whether labels are trustworthy |
| **License** | Can you use it for a project? | Legal and ethical requirement |

> [!WARNING]
> **Do NOT fabricate data.** Do NOT manually create a CSV of "phishing URLs" from your imagination. Real datasets have real-world noise, edge cases, and class distributions that fabricated data doesn't capture. Using fabricated data would make your model evaluation meaningless and your project academically indefensible.

### Our Strategy

We'll start with a **raw URL dataset** (not pre-extracted features) so that we can:
1. Practice building the feature extraction pipeline ourselves
2. Understand what each feature means
3. Control the feature engineering process
4. Add new features later

I'll help you find and download the specific dataset when we start Stage 2.

---

## 8. Initial Repository Structure

We'll start with a **minimal** structure and grow it as we add components. Here's what we create on Day 1:

```
phishing-detection-platform/
│
├── README.md                  ← Project overview
├── .gitignore                 ← Files Git should ignore
├── requirements.txt           ← Python dependencies (will grow)
│
├── docs/                      ← Documentation
│   └── architecture.md        ← System architecture doc
│
├── ml/                        ← Machine learning pipeline
│   ├── datasets/              ← Where we'll store data (gitignored)
│   │   └── .gitkeep
│   ├── notebooks/             ← Jupyter notebooks for exploration
│   │   └── .gitkeep
│   ├── features/              ← Feature extraction code
│   │   └── __init__.py
│   └── training/              ← Model training code
│       └── __init__.py
│
├── src/                       ← Source code (will hold shared utilities)
│   └── __init__.py
│
└── tests/                     ← Tests
    └── __init__.py
```

> [!NOTE]
> We do NOT create `backend/`, `frontend/`, `docker/`, etc. yet. Those come in later stages. **Create files only when you need them.**

---

## 9. Learning Roadmap Tied to Project Milestones

| Milestone | What You Build | What You Learn |
|---|---|---|
| **M0: Foundation** *(this stage)* | Project structure, README | Phishing concepts, ML fundamentals, Git basics |
| **M1: Data Pipeline** | Dataset loader + cleaner | pandas, data inspection, class balance, train/test split |
| **M2: Feature Engineering** | URL feature extractor | String parsing, domain knowledge, feature design |
| **M3: Baseline Model** | Logistic Regression + Decision Tree | Supervised learning, overfitting, metrics |
| **M4: Model Comparison** | Random Forest, XGBoost | Ensemble methods, hyperparameters, experiment tracking |
| **M5: Model Selection** | Experiment table, chosen model | Evaluation methodology, scientific reasoning |
| **M6: Explainability** | Feature importance + SHAP | Why the model made a decision, XAI |
| **M7: Risk Engine** | Score calculator + thresholds | Turning ML output into security decisions |
| **M8: Backend API** | FastAPI endpoints | REST APIs, request validation, error handling |
| **M9: Frontend** | Next.js dashboard | React, TypeScript, API integration, UI/UX |
| **M10: Database** | PostgreSQL integration | SQL, ORM, schema design, migrations |
| **M11: Email Detection** | Email analyzer + NLP | Text preprocessing, TF-IDF, NLP classification |
| **M12: Advanced ML** | Embeddings / transformers | Deep learning (only if justified by data) |
| **M13: Threat Intel** | External API integrations | API design, adapter pattern, environment variables |
| **M14: Prevention** | ALLOW/WARN/BLOCK logic | Policy engine, configurable thresholds |
| **M15: Security** | Security review + hardening | SSRF, input validation, secure coding |
| **M16: Testing** | Unit + integration + ML tests | pytest, test design, edge cases |
| **M17: MLOps** | Model versioning + tracking | Reproducibility, model registry |
| **M18: Deployment** | Docker + compose | Containers, networking, environment config |

---

## 10. What Happens Next

I've covered all 10 points from your first task. Here's where we stand:

### ✅ Completed
- [x] Project architecture explained
- [x] Development roadmap laid out
- [x] Minimum technologies identified
- [x] Version 1 scope defined
- [x] Rule-based vs ML-based detection explained
- [x] Classification, features, labels, training/validation/testing explained
- [x] Dataset recommendations given
- [x] Initial repository structure designed
- [x] Learning roadmap created

### 🔜 Next Step (When You're Ready)

**Milestone M0 — Set Up the Project:**
1. Create the repository structure
2. Initialize Git
3. Write the README
4. Create the `.gitignore`
5. Set up Python virtual environment
6. Install initial dependencies

Then we move to **Milestone M1 — The Data Pipeline**.

---

## Quick Self-Check Questions

Before we proceed, make sure you can answer these. Don't look up the answers — think about them:

1. **What is the difference between a feature and a label?**
2. **Why do we split data into train/validation/test sets instead of just train/test?**
3. **A phishing detector has 95% accuracy. Is it definitely good? Why or why not?**
4. **What is more dangerous in phishing detection — a false positive or a false negative? Why?**
5. **Why can't we just write a list of rules to detect phishing URLs?**

You don't need to answer these to me right now — but if any of them feel unclear, tell me and I'll explain further before we start coding.

---

> **I am now waiting for your go-ahead.** When you're ready, say something like:
> - *"Let's set up the project"*
> - *"I have a question about [topic]"*
> - *"Explain [concept] more"*
> - *"Let's start with M0"*
