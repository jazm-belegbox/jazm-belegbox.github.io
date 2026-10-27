// Belegbox Service Worker – nur App-Dateien werden gecacht, nie Nutzerdaten.
const CACHE = 'belegbox-0.6.6.3';
const FILES = ['./', 'index.html', 'app.js', 'manifest.webmanifest',
  'icons/icon-192.png', 'icons/icon-512.png', 'icons/maskable-512.png', 'icons/icon-180.png', 'icons/badge-96.png',
  'vendor/pdfjs/pdf.min.mjs', 'vendor/pdfjs/pdf.worker.min.mjs'];

self.addEventListener('install', e => {
  // cache: 'reload' umgeht den HTTP-Zwischenspeicher des Browsers – sonst könnte eine neue Version
  // mit alten Dateien (GitHub Pages erlaubt 10 Min. Caching) installiert werden.
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(FILES.map(u => new Request(u, { cache: 'reload' })))));
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys()
    .then(keys => Promise.all(keys.filter(k => k.startsWith('belegbox-') && k !== CACHE).map(k => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener('message', e => { if (e.data === 'SKIP_WAITING') self.skipWaiting(); });

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== location.origin) return;
  // Alles aus dem Cache des aktuellen Stands, damit Seite und Skript immer zusammenpassen.
  // Neue Versionen kommen über eine geänderte CACHE-Nummer (Hinweis „Neue Version verfügbar“).
  if (req.mode === 'navigate') {
    e.respondWith(caches.match('index.html').then(r => r || fetch(req)));
    return;
  }
  e.respondWith(caches.match(req, { ignoreSearch: true }).then(r => r || fetch(req)));
});
