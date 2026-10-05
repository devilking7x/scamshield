/* ScamShield service worker — cache-first for static assets.
 * The scam pattern library (/api/scam-patterns) is cached at runtime so the
 * library page keeps working offline. Analysis endpoints always go to network.
 */
const CACHE = 'scamshield-v2';
const PRECACHE = ['./', './manifest.json', './icons/icon-192.png', './icons/icon-512.png'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(PRECACHE)).then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))),
    ).then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  // Only handle same-origin http(s) requests. Blob:/data: URLs (used by
  // Tesseract.js web workers) must bypass the SW — caches.match() rejects them.
  if (url.origin !== self.location.origin) return;
  if (!url.protocol.startsWith('http')) return;

  // Analysis endpoints: network only (always fresh)
  if (url.pathname.startsWith('/api/analyze')) {
    return;
  }

  // Everything else (pages, assets, pattern library): cache-first
  event.respondWith(
    caches.match(request).then((cached) => {
      if (cached) return cached;
      return fetch(request).then((resp) => {
        if (resp.ok) {
          const copy = resp.clone();
          caches.open(CACHE).then((cache) => cache.put(request, copy));
        }
        return resp;
      }).catch(() => caches.match('./'));
    }),
  );
});
