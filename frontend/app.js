/**
 * AegisGuard AI Phishing Detection & Prevention Platform
 * Client-side Controller & Telemetry Engine
 */

const API_BASE = window.location.origin.includes(":8000") || window.location.origin.includes(":3000")
    ? window.location.origin 
    : "http://localhost:8000";

const CIRCUMFERENCE = 2 * Math.PI * 80; // 502.65 for r=80

let deferredPrompt = null;

// Initialize on DOM Ready
document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    checkSystemHealth();
    loadModelIntelligence();
    fetchScanHistory();
    registerServiceWorker();
});

// PWA Service Worker & Install Prompt
function registerServiceWorker() {
    if ("serviceWorker" in navigator) {
        navigator.serviceWorker.register("/dashboard/sw.js").catch(err => {
            console.log("SW register note:", err);
        });
    }

    window.addEventListener("beforeinstallprompt", (e) => {
        e.preventDefault();
        deferredPrompt = e;
        const pwaBtn = document.getElementById("pwaInstallBtn");
        if (pwaBtn) pwaBtn.classList.remove("hidden");
    });
}

function triggerPwaInstall() {
    if (deferredPrompt) {
        deferredPrompt.prompt();
        deferredPrompt.userChoice.then((choiceResult) => {
            if (choiceResult.outcome === "accepted") {
                console.log("User accepted the PWA install");
            }
            deferredPrompt = null;
        });
    } else {
        alert("To install as a Desktop App:\nClick the 'Install App' icon (computer/download symbol) located on the right side of your browser's address bar!");
    }
}

function triggerOneClickBrowserLaunch() {
    const btn = document.getElementById("oneClickLaunchBtn");
    const originalText = btn.innerHTML;
    btn.innerHTML = `<span>⏳ Launching Browser with Shield...</span>`;
    btn.disabled = true;

    fetch(`${API_BASE}/api/v1/extension/launch`, { method: "POST" })
        .then(res => res.json())
        .then(data => {
            btn.innerHTML = `<span>✅ Launched Successfully!</span>`;
            setTimeout(() => {
                btn.innerHTML = originalText;
                btn.disabled = false;
                closeExtensionModal();
            }, 2000);
        })
        .catch(err => {
            alert("Could not launch browser automatically: " + err.message + "\nYou can run create_desktop_shortcut.bat or load extension folder manually.");
            btn.innerHTML = originalText;
            btn.disabled = false;
        });
}

// Extension Modal Handlers
function openExtensionModal() {
    const modal = document.getElementById("extensionModal");
    if (modal) modal.classList.remove("hidden");
}

function closeExtensionModal() {
    const modal = document.getElementById("extensionModal");
    if (modal) modal.classList.add("hidden");
}

function handleModalBackdropClick(e) {
    if (e.target.id === "extensionModal") {
        closeExtensionModal();
    }
}

function switchModalTab(type) {
    document.getElementById("mTabExt").classList.toggle("active", type === "ext");
    document.getElementById("mTabDesktop").classList.toggle("active", type === "desktop");
    document.getElementById("modalContentExt").classList.toggle("active", type === "ext");
    document.getElementById("modalContentDesktop").classList.toggle("active", type === "desktop");
}

function copyExtensionPath() {
    const pathText = document.getElementById("extensionFolderPath").innerText;
    navigator.clipboard.writeText(pathText).then(() => {
        const copyBtn = document.querySelector(".copy-btn");
        const original = copyBtn.innerText;
        copyBtn.innerText = "Copied! ✅";
        setTimeout(() => copyBtn.innerText = original, 2000);
    }).catch(() => {
        alert("Path: " + pathText);
    });
}

// Theme Toggle (Dark & Light Mode)
function initTheme() {
    const savedTheme = localStorage.getItem("nexora_theme") || "dark";
    applyTheme(savedTheme);
}

function toggleTheme() {
    const isLight = document.body.classList.contains("light-theme");
    const newTheme = isLight ? "dark" : "light";
    applyTheme(newTheme);
    localStorage.setItem("nexora_theme", newTheme);
}

function applyTheme(theme) {
    const icon = document.getElementById("themeIcon");
    const text = document.getElementById("themeText");

    if (theme === "light") {
        document.body.classList.add("light-theme");
        if (icon) icon.innerText = "🌙";
        if (text) text.innerText = "Dark";
    } else {
        document.body.classList.remove("light-theme");
        if (icon) icon.innerText = "☀️";
        if (text) text.innerText = "Light";
    }
}

// Tab Switching
function switchTab(tabName) {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

    const btnId = `tab${tabName.charAt(0).toUpperCase() + tabName.slice(1)}Btn`;
    const tabId = `${tabName}Tab`;

    const btn = document.getElementById(btnId);
    const content = document.getElementById(tabId);

    if (btn) btn.classList.add("active");
    if (content) content.classList.add("active");

    if (tabName === "history") fetchScanHistory();
    if (tabName === "model") loadModelIntelligence();
}

// System Health Check
async function checkSystemHealth() {
    const pill = document.getElementById("systemStatusPill");
    const text = document.getElementById("systemStatusText");

    try {
        const res = await fetch(`${API_BASE}/api/v1/health`);
        const data = await res.json();

        if (data.status === "healthy") {
            text.innerText = `ML Engine Online // ${data.model_name} v${data.model_version}`;
            pill.style.borderColor = "rgba(16, 185, 129, 0.4)";
            pill.style.color = "var(--neon-green)";
        } else {
            text.innerText = "System Degraded (Fallback Mode)";
            pill.style.color = "var(--neon-amber)";
        }
    } catch (e) {
        text.innerText = "API Offline (Start Backend)";
        pill.style.color = "var(--neon-red)";
    }
}

// Quick Sample Loader
function loadSampleUrl(url) {
    document.getElementById("urlInput").value = url;
    document.getElementById("urlScanForm").dispatchEvent(new Event("submit"));
}

function loadSampleEmail() {
    document.getElementById("emailSender").value = '"PayPal Security Alert" <security@update-portal-paypal.xyz>';
    document.getElementById("emailReplyTo").value = 'attacker-drop@tempmail.cc';
    document.getElementById("emailSubject").value = 'URGENT: Your PayPal Account Has Been Suspended!';
    document.getElementById("emailBody").value = 'Dear customer, unauthorized activity was detected on your account. Your account is locked within 24 hours unless you verify your identity now: http://paypal.com@secure-verify-account.xyz/login.php';
}

// Update Circular Gauge
function updateGauge(gaugeBarId, scoreValId, levelBadgeId, score) {
    const bar = document.getElementById(gaugeBarId);
    const valEl = document.getElementById(scoreValId);
    const badgeEl = document.getElementById(levelBadgeId);

    const offset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
    bar.style.strokeDashoffset = offset;

    // Color logic
    let color = "var(--neon-green)";
    let level = "LOW RISK";

    if (score >= 80) {
        color = "var(--neon-red)";
        level = "CRITICAL RISK";
    } else if (score >= 60) {
        color = "#ea580c"; // Dark orange
        level = "HIGH RISK";
    } else if (score >= 30) {
        color = "var(--neon-amber)";
        level = "MEDIUM RISK";
    }

    bar.style.stroke = color;
    valEl.style.color = color;
    valEl.innerText = score;
    badgeEl.innerText = level;
    badgeEl.style.color = color;
    badgeEl.style.borderColor = color;
}

// URL Submit Handler
async function handleUrlSubmit(e) {
    e.preventDefault();
    const url = document.getElementById("urlInput").value.trim();
    if (!url) return;

    const btn = document.getElementById("urlScanBtn");
    btn.disabled = true;

    try {
        const res = await fetch(`${API_BASE}/api/v1/analyze/url`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        if (!res.ok) throw new Error(`Server returned ${res.status}`);
        const data = await res.json();

        renderUrlResults(data);
    } catch (err) {
        alert("Failed to analyze URL: " + err.message + "\nMake sure backend server is running on " + API_BASE);
    } finally {
        btn.disabled = false;
    }
}

function renderUrlResults(data) {
    const sec = document.getElementById("urlResultSection");
    sec.classList.remove("hidden");

    // Gauge
    updateGauge("urlGaugeBar", "urlScoreVal", "urlLevelBadge", data.risk_score);

    // Policy Box
    const pBox = document.getElementById("urlPolicyBox");
    const aText = document.getElementById("urlActionText");
    const aDesc = document.getElementById("urlActionDesc");

    aText.innerText = `ENFORCED ACTION: ${data.action}`;
    aDesc.innerText = data.recommendation;

    pBox.className = "policy-action-box";
    if (data.action === "BLOCK") {
        pBox.style.borderColor = "var(--neon-red)";
        aText.style.color = "var(--neon-red)";
    } else if (data.action === "WARN" || data.action === "STRONG_WARNING") {
        pBox.style.borderColor = "var(--neon-amber)";
        aText.style.color = "var(--neon-amber)";
    } else {
        pBox.style.borderColor = "var(--neon-green)";
        aText.style.color = "var(--neon-green)";
    }

    // Meta
    document.getElementById("urlConfidenceVal").innerText = `${(data.model_confidence * 100).toFixed(1)}%`;
    document.getElementById("urlModelVal").innerText = data.model_name;

    // Reasons
    const rList = document.getElementById("urlReasonsList");
    rList.innerHTML = data.reasons.map(r => `
        <div class="reason-item ${r.severity}">
            <div class="reason-icon">${r.severity === "critical" ? "🚨" : (r.severity === "warning" ? "⚠️" : "ℹ️")}</div>
            <div class="reason-content">
                <h4>${r.title}</h4>
                <p>${r.description}</p>
            </div>
        </div>
    `).join("");

    // Features Table
    const tbody = document.querySelector("#urlFeatureTable tbody");
    tbody.innerHTML = Object.entries(data.features).map(([k, v]) => `
        <tr>
            <td><code>${k}</code></td>
            <td><strong>${typeof v === "number" && !Number.isInteger(v) ? v.toFixed(4) : v}</strong></td>
        </tr>
    `).join("");

    sec.scrollIntoView({ behavior: "smooth", block: "start" });
}

function toggleFeatureTable() {
    const cont = document.getElementById("featureTableContainer");
    const icon = document.getElementById("collapseIcon");
    cont.classList.toggle("hidden");
    icon.innerText = cont.classList.contains("hidden") ? "▼" : "▲";
}

// Email Submit Handler
async function handleEmailSubmit(e) {
    e.preventDefault();
    const sender = document.getElementById("emailSender").value.trim();
    const reply_to = document.getElementById("emailReplyTo").value.trim() || null;
    const subject = document.getElementById("emailSubject").value.trim();
    const body = document.getElementById("emailBody").value.trim();

    const btn = document.getElementById("emailScanBtn");
    btn.disabled = true;

    try {
        const res = await fetch(`${API_BASE}/api/v1/analyze/email`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ sender, reply_to, subject, body })
        });

        if (!res.ok) throw new Error(`Server returned ${res.status}`);
        const data = await res.json();

        renderEmailResults(data);
    } catch (err) {
        alert("Failed to analyze Email: " + err.message);
    } finally {
        btn.disabled = false;
    }
}

function renderEmailResults(data) {
    const sec = document.getElementById("emailResultSection");
    sec.classList.remove("hidden");

    // Gauge
    updateGauge("emailGaugeBar", "emailScoreVal", "emailLevelBadge", data.risk_score);

    // Policy
    const aText = document.getElementById("emailActionText");
    const aDesc = document.getElementById("emailActionDesc");
    aText.innerText = `ENFORCED ACTION: ${data.action}`;
    aDesc.innerText = data.recommendation;

    // Threat Signals
    const sList = document.getElementById("emailSignalsList");
    if (data.threat_signals.length === 0) {
        sList.innerHTML = `<div class="reason-item info"><p>No deceptive social engineering signals detected.</p></div>`;
    } else {
        sList.innerHTML = data.threat_signals.map(s => `
            <div class="reason-item ${s.severity}">
                <div class="reason-icon">${s.severity === "critical" ? "🚨" : "⚠️"}</div>
                <div class="reason-content">
                    <h4>${s.title}</h4>
                    <p>${s.description}</p>
                </div>
            </div>
        `).join("");
    }

    // Embedded URLs
    document.getElementById("emailUrlCount").innerText = data.embedded_urls_count;
    const uList = document.getElementById("emailUrlsList");
    if (data.embedded_urls_analysis.length === 0) {
        uList.innerHTML = `<p class="text-muted" style="font-size:0.8rem;">No hyperlinks detected in email body.</p>`;
    } else {
        uList.innerHTML = data.embedded_urls_analysis.map(u => `
            <div class="embedded-card">
                <span style="max-width:70%; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${u.url}</span>
                <span class="badge-status ${u.action.toLowerCase()}">${u.action} (Risk: ${u.risk_score})</span>
            </div>
        `).join("");
    }

    sec.scrollIntoView({ behavior: "smooth", block: "start" });
}

// Load Model Intelligence Tab Data
async function loadModelIntelligence() {
    try {
        const res = await fetch(`${API_BASE}/api/v1/model/info`);
        if (!res.ok) return;
        const data = await res.json();

        // Champion Metrics
        const m = data.test_metrics;
        document.getElementById("metricAccuracy").innerText = `${(m.accuracy * 100).toFixed(1)}%`;
        document.getElementById("metricPrecision").innerText = `${(m.precision * 100).toFixed(1)}%`;
        document.getElementById("metricRecall").innerText = `${(m.recall * 100).toFixed(1)}%`;
        document.getElementById("metricF1").innerText = `${(m.f1_score * 100).toFixed(1)}%`;

        // Comparison Table
        const tbody = document.querySelector("#comparisonTable tbody");
        tbody.innerHTML = Object.entries(data.all_model_results).map(([name, metrics]) => `
            <tr>
                <td><strong>${name} ${name === data.champion_model ? '<span class="badge-status allow">Champion</span>' : ''}</strong></td>
                <td>${(metrics.accuracy * 100).toFixed(1)}%</td>
                <td>${(metrics.precision * 100).toFixed(1)}%</td>
                <td>${(metrics.recall * 100).toFixed(1)}%</td>
                <td>${(metrics.f1_score * 100).toFixed(1)}%</td>
                <td>${(metrics.roc_auc * 100).toFixed(1)}%</td>
            </tr>
        `).join("");

        // Feature Importance Bars
        const impContainer = document.getElementById("featureImportanceBars");
        const topFeatures = Object.entries(data.feature_importances).slice(0, 10);
        const maxVal = topFeatures.length > 0 ? topFeatures[0][1] : 1.0;

        impContainer.innerHTML = topFeatures.map(([feat, val]) => `
            <div class="imp-row">
                <div class="imp-label-val">
                    <span>${feat}</span>
                    <span>${(val * 100).toFixed(2)}%</span>
                </div>
                <div class="imp-bar-bg">
                    <div class="imp-bar-fill" style="width: ${(val / maxVal) * 100}%"></div>
                </div>
            </div>
        `).join("");

    } catch (e) {
        console.warn("Could not fetch model metadata", e);
    }
}

// Fetch Scan History
async function fetchScanHistory() {
    try {
        const res = await fetch(`${API_BASE}/api/v1/history`);
        if (!res.ok) return;
        const scans = await res.json();

        const tbody = document.getElementById("historyTableBody");
        if (!scans || scans.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center" style="padding:1.5rem;">No scans executed yet. Submit a URL or email above.</td></tr>`;
            return;
        }

        tbody.innerHTML = scans.map(s => {
            const target = s.type === "url" ? s.url : `${s.subject} (${s.sender})`;
            const actionClass = s.action.toLowerCase();
            return `
                <tr>
                    <td><code>${s.scan_id}</code></td>
                    <td>${new Date(s.timestamp).toLocaleTimeString()}</td>
                    <td><span class="badge-status info">${s.type.toUpperCase()}</span></td>
                    <td style="max-width:320px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${target}</td>
                    <td><strong>${s.risk_score}</strong>/100</td>
                    <td><span class="badge-status ${s.classification}">${s.classification.toUpperCase()}</span></td>
                    <td><span class="badge-status ${actionClass}">${s.action}</span></td>
                </tr>
            `;
        }).join("");
    } catch (e) {
        console.warn("Could not fetch scan history", e);
    }
}

// Clear Scan History
async function clearScanHistory() {
    if (!confirm("Are you sure you want to clear all telemetry audit logs?")) return;

    try {
        const res = await fetch(`${API_BASE}/api/v1/history`, { method: "DELETE" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        fetchScanHistory();
    } catch (err) {
        alert("Could not clear audit logs: " + err.message);
    }
}
