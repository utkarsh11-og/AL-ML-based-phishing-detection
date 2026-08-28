/**
 * NEXORA PhishGuard Service Worker
 */

const CACHE_NAME = "nexora-pwa-v1";

self.addEventListener("install", (e) => {
    self.skipWaiting();
});

self.addEventListener("activate", (e) => {
    e.waitUntil(clients.claim());
});

self.addEventListener("fetch", (e) => {
    // Network-first strategy
    e.respondWith(
        fetch(e.request).catch(() => caches.match(e.request))
    );
});
