# HOW TO RUN NEXORA PhishGuard ON ANY LAPTOP / PC

A complete, foolproof guide to running the **NEXORA AI/ML Phishing Detection & Prevention Platform** on any Windows, macOS, or Linux machine.

---

## ⚡ Method 1: The 1-Click Automatic Way (Recommended for Windows)

### Step 1: Copy the Project Folder
Copy the entire project folder:
📁 `e:\AL ML based phishing detection`  
*(via USB Pen Drive, Google Drive, or Git Clone)* onto the new laptop.

### Step 2: Double-Click the Launcher
On the new laptop, open the project folder and simply **double-click**:
👉 **`run_project.bat`**

That's it! The script will automatically:
1. Detect Python 3.10+ installation.
2. Create the isolated virtual environment (`venv`).
3. Install all required dependencies (`pip install -r requirements.txt`).
4. Verify/load the trained champion **Random Forest** ML model.
5. Create a **"NEXORA PhishGuard"** desktop shortcut on the new laptop.
6. Start the FastAPI backend server and automatically open the **Cybersecurity Dashboard** in your default web browser!

---

## 💻 Method 2: Manual Terminal Commands (Windows / Mac / Linux)

If you prefer to run it step-by-step using your terminal:

### 1. Open Terminal in the Project Directory
Open Command Prompt, PowerShell, or macOS/Linux Terminal inside the project folder.

### 2. Create and Activate the Virtual Environment

#### Windows (PowerShell):
```powershell
python -m venv venv
.\venv\Scripts\activate
```

#### macOS / Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Start the Backend AI Engine Server
```bash
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 5. Access the Platform
Open your browser and navigate to:
- **Interactive Dashboard**: [http://127.0.0.1:8000/dashboard/](http://127.0.0.1:8000/dashboard/)
- **FastAPI OpenAPI Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Engine Health Endpoint**: [http://127.0.0.1:8000/api/v1/health](http://127.0.0.1:8000/api/v1/health)

---

## 🌐 How to Add the Browser Extension on the New Laptop

To enable real-time active tab protection on Google Chrome, Microsoft Edge, or Brave:

1. Open your browser and navigate to:
   - **Chrome**: `chrome://extensions`
   - **Edge**: `edge://extensions`
2. Turn **ON** the **Developer mode** toggle (top-right corner in Chrome, bottom-left in Edge).
3. Click the **"Load unpacked"** button.
4. Select the `extension` folder inside your project:
   ```text
   E:\AL ML based phishing detection\extension
   ```
5. Click **"Select Folder"**.

✅ *The **NEXORA Shield** icon will now appear in your browser extensions toolbar, actively scanning every website you visit in real time!*

---

## 🧪 How to Run Automated Unit & Integration Tests

To verify all system modules on the new laptop:
```bash
.\venv\Scripts\pytest.exe tests/
```

---

*Project Developed & Researched by **Team NEXORA** // B.Tech CSE Cybersecurity Lab*
