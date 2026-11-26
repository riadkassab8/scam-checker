// Minimal service worker: makes the app installable (share target needs it).
// Pass-through only - every request goes to the network, nothing is cached.
self.addEventListener("install", (e) => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(clients.claim()));
self.addEventListener("fetch", (e) => e.respondWith(fetch(e.request)));
