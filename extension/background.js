/**
 * NEXORA PhishGuard Background Service Worker (Manifest V3)
 * Monitors active tab navigation in real-time and updates extension badge indicators.
 */

const API_BASE = "http://127.0.0.1:8000";

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url && tab.url.startsWith("http")) {
        checkUrlSafety(tabId, tab.url);
    }
});

async function checkUrlSafety(tabId, url) {
    try {
        const response = await fetch(`${API_BASE}/api/v1/analyze/url`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        if (!response.ok) return;
        const data = await response.json();

        // Update badge text and background color based on risk
        if (data.risk_score >= 80) {
            chrome.action.setBadgeText({ tabId, text: "BLOCK" });
            chrome.action.setBadgeBackgroundColor({ tabId, color: "#ef4444" });
        } else if (data.risk_score >= 60) {
            chrome.action.setBadgeText({ tabId, text: "WARN" });
            chrome.action.setBadgeBackgroundColor({ tabId, color: "#f59e0b" });
        } else if (data.risk_score >= 30) {
            chrome.action.setBadgeText({ tabId, text: "!" });
            chrome.action.setBadgeBackgroundColor({ tabId, color: "#eab308" });
        } else {
            chrome.action.setBadgeText({ tabId, text: "OK" });
            chrome.action.setBadgeBackgroundColor({ tabId, color: "#10b981" });
        }
    } catch (err) {
        // Backend offline or unreachable
        chrome.action.setBadgeText({ tabId, text: "" });
    }
}
