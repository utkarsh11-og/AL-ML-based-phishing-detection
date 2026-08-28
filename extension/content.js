/**
 * NEXORA PhishGuard Content Script
 * Injects on-page warning alerts when visiting verified phishing domains.
 */

const API_BASE = "http://127.0.0.1:8000";

(async function () {
    const currentUrl = window.location.href;
    if (!currentUrl.startsWith("http")) return;

    try {
        const response = await fetch(`${API_BASE}/api/v1/analyze/url`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: currentUrl })
        });

        if (!response.ok) return;
        const data = await response.json();

        // Inject warning banner for HIGH or CRITICAL threats
        if (data.risk_score >= 60) {
            injectWarningBanner(data);
        }
    } catch (e) {
        // Backend not running, skip injection
    }
})();

function injectWarningBanner(data) {
    if (document.getElementById("nexora-phish-shield-banner")) return;

    const banner = document.createElement("div");
    banner.id = "nexora-phish-shield-banner";
    banner.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        z-index: 2147483647;
        background: linear-gradient(90deg, #7f1d1d, #991b1b);
        color: #ffffff;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        padding: 12px 20px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        display: flex;
        align-items: center;
        justify-content: space-between;
        font-size: 13px;
        border-bottom: 2px solid #ef4444;
    `;

    banner.innerHTML = `
        <div style="display:flex; align-items:center; gap:12px;">
            <span style="font-size:22px;">🚨</span>
            <div>
                <strong>NEXORA PhishGuard Warning:</strong> Suspicious / Phishing Indicators Detected on this site! (Risk: ${data.risk_score}/100 - ${data.action})
                <div style="font-size:11px; opacity:0.9; margin-top:2px;">${data.recommendation}</div>
            </div>
        </div>
        <button id="nexora-dismiss-btn" style="
            background: rgba(255,255,255,0.2);
            color: #fff;
            border: 1px solid rgba(255,255,255,0.4);
            border-radius: 4px;
            padding: 4px 12px;
            cursor: pointer;
            font-size: 11px;
            font-weight: 600;
        ">Dismiss</button>
    `;

    document.body.prepend(banner);

    document.getElementById("nexora-dismiss-btn").addEventListener("click", () => {
        banner.remove();
    });
}
