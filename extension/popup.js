/**
 * NEXORA PhishGuard Extension Popup Controller
 */

const API_BASE = "http://127.0.0.1:8000";

document.addEventListener("DOMContentLoaded", () => {
    scanActiveTab();

    document.getElementById("reScanBtn").addEventListener("click", scanActiveTab);
    document.getElementById("openDashBtn").addEventListener("click", () => {
        if (chrome && chrome.tabs) {
            chrome.tabs.create({ url: `${API_BASE}/dashboard/` });
        } else {
            window.open(`${API_BASE}/dashboard/`, "_blank");
        }
    });
});

async function scanActiveTab() {
    const urlEl = document.getElementById("activeUrlText");
    const scoreEl = document.getElementById("riskScoreNum");
    const badgeEl = document.getElementById("verdictBadge");
    const actionEl = document.getElementById("actionText");
    const reasonsEl = document.getElementById("reasonsList");
    const gaugeEl = document.querySelector(".mini-gauge");

    // 1. Get active tab URL
    let currentUrl = "http://example.com";
    try {
        if (chrome && chrome.tabs) {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab && tab.url) {
                currentUrl = tab.url;
            }
        }
    } catch (e) {
        console.warn("Could not query active tab:", e);
    }

    urlEl.innerText = currentUrl;
    badgeEl.innerText = "ANALYZING...";
    badgeEl.style.color = "var(--cyan)";

    // 2. Query NEXORA Backend Engine
    try {
        const response = await fetch(`${API_BASE}/api/v1/analyze/url`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: currentUrl })
        });

        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();

        // Update UI
        scoreEl.innerText = data.risk_score;
        badgeEl.innerText = `${data.action} (${data.risk_level.toUpperCase()})`;
        actionEl.innerText = data.recommendation;

        let color = "var(--green)";
        if (data.risk_score >= 80) color = "var(--red)";
        else if (data.risk_score >= 60) color = "#ea580c";
        else if (data.risk_score >= 30) color = "var(--amber)";

        gaugeEl.style.borderColor = color;
        scoreEl.style.color = color;
        badgeEl.style.color = color;
        badgeEl.style.borderColor = color;

        // Render reasons
        if (data.reasons && data.reasons.length > 0) {
            reasonsEl.innerHTML = data.reasons.map(r => `
                <div class="signal-item ${r.severity}">
                    <strong>${r.title}</strong>: ${r.description}
                </div>
            `).join("");
        } else {
            reasonsEl.innerHTML = `<div class="signal-item info">No anomalous threat vectors detected.</div>`;
        }

    } catch (err) {
        badgeEl.innerText = "OFFLINE";
        badgeEl.style.color = "var(--red)";
        actionEl.innerText = "Could not connect to local NEXORA engine on " + API_BASE;
        reasonsEl.innerHTML = `<div class="signal-item critical">Ensure backend server is running: <code>uvicorn backend.app.main:app</code></div>`;
    }
}
