
// Simple app-shell cache for PWA
const CACHE = 'estoque-clinica-v1';
const ASSETS = [
  './',
  './index.html',
  './manifest.webmanifest'
];
self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
  self.skipWaiting();
});
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k!==CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  // Network-first for API/data requests to stay "100% online"
  if (url.origin !== location.origin) {
    e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
    return;
  }
  // App shell: try cache first, then network
  e.respondWith(caches.match(e.request).then(r => r || fetch(e.request)));
});
