#!/bin/bash
echo "====================================================================="
echo "      NEXORA PhishGuard - AI/ML Phishing Detection Platform"
echo "                    Engineered by Team NEXORA"
echo "====================================================================="
echo ""

# 1. Check Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed. Please install Python 3.10+."
    exit 1
fi

# 2. Virtual Environment
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment (venv)..."
    python3 -m venv venv
fi

# 3. Dependencies
source venv/bin/activate
echo "[*] Installing dependencies..."
pip install -r requirements.txt --quiet

# 4. Train Model if missing
if [ ! -f "ml/models/phishing_model_v1.joblib" ]; then
    echo "[*] Training initial champion ML models..."
    python3 ml/datasets/fetch_realtime_data.py
fi

# 5. Launch
echo ""
echo "====================================================================="
echo " [SUCCESS] Starting NEXORA AI Engine on http://127.0.0.1:8000"
echo " [INFO] Dashboard URL: http://127.0.0.1:8000/dashboard/"
echo " [INFO] API Docs URL : http://127.0.0.1:8000/docs"
echo "====================================================================="
echo ""

# Open browser if possible
if command -v xdg-open &> /dev/null; then
    xdg-open "http://127.0.0.1:8000/dashboard/" &
elif command -v open &> /dev/null; then
    open "http://127.0.0.1:8000/dashboard/" &
fi

uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
