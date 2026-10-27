// Belegbox Service Worker – nur App-Dateien werden gecacht, nie Nutzerdaten.
// Ausnahmen: aus anderen Apps geteilte Dateien liegen kurz im Eingangsfach (bis die App entsperrt ist und sie
// verschlüsselt), und bei eingeschalteten Erinnerungen eine Liste von Terminen ohne Namen oder Beträge.
const CACHE = 'belegbox-0.7.0.5';
const INBOX = 'inbox-belegbox', SCHED = 'sched-belegbox';
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

self.addEventListener('message', e => {
  if (e.data === 'SKIP_WAITING') self.skipWaiting();
  else if (e.data && e.data.type === 'REMIND') e.waitUntil(remind(!!e.data.force));
});

self.addEventListener('fetch', e => {
  const req = e.request, url = new URL(req.url);
  if (url.origin !== location.origin) return;
  // Teilen aus anderen Apps: Dateien ins Eingangsfach, dann die App öffnen
  if (req.method === 'POST' && url.searchParams.has('teilen')) {
    e.respondWith((async () => {
      try {
        const fd = await req.formData(), c = await caches.open(INBOX);
        let i = 0;
        for (const f of fd.getAll('files')) {
          if (!f || !f.size || f.size > 25e6) continue;
          await c.put(new Request('./__inbox/' + Date.now() + '-' + (i++)),
            new Response(f, { headers: { 'content-type': f.type || 'application/octet-stream', 'x-name': encodeURIComponent(f.name || 'Datei') } }));
        }
      } catch (x) {}
      return Response.redirect('./?geteilt=1', 303);
    })());
    return;
  }
  if (req.method !== 'GET') return;
  // Alles aus dem Cache des aktuellen Stands, damit Seite und Skript immer zusammenpassen.
  // Neue Versionen kommen über eine geänderte CACHE-Nummer (Hinweis „Neue Version verfügbar“).
  if (req.mode === 'navigate') {
    e.respondWith(caches.match('index.html').then(r => r || fetch(req)));
    return;
  }
  e.respondWith(caches.match(req, { ignoreSearch: true }).then(r => r || fetch(req)));
});

/* ---------- Erinnerungen ohne Server ---------- */
self.addEventListener('periodicsync', e => { if (e.tag === 'belegbox-fristen') e.waitUntil(remind(false)); });

const LABEL = { k: 'eine Kündigungsfrist', g: 'eine Garantie', p: 'ein Preis' };
const VERB = { k: 'endet', g: 'läuft ab', p: 'ändert sich' };
function dayIso(d) { return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); }
function diffDays(s, today) { const p = s.split('-').map(Number); return Math.round((new Date(p[0], p[1] - 1, p[2]) - today) / 864e5); }
const when = n => n === 0 ? 'heute' : n === 1 ? 'morgen' : 'in ' + n + ' Tagen';

async function remind(force) {
  const c = await caches.open(SCHED), r = await c.match('./__sched');
  const old = await self.registration.getNotifications({ tag: 'belegbox-fristen' });
  if (!r) { old.forEach(n => n.close()); return; }
  const { items = [] } = await r.json().catch(() => ({}));
  const t = new Date(); const today = new Date(t.getFullYear(), t.getMonth(), t.getDate());
  const soon = items.map(x => ({ t: x.t, n: diffDays(x.d, today) })).filter(x => x.n >= 0 && x.n <= 14).sort((a, b) => a.n - b.n);
  if (!soon.length) { old.forEach(n => n.close()); await c.delete('./__last'); return; }
  const last = await c.match('./__last').then(x => x && x.json()).catch(() => null);
  const key = dayIso(today) + '|' + soon.length + '|' + soon[0].n;
  if (!force && last && last.key === key) return;
  const f = soon[0];
  const body = soon.length === 1
    ? (LABEL[f.t] || 'eine Frist').replace(/^./, m => m.toUpperCase()) + ' ' + (VERB[f.t] || 'endet') + ' ' + when(f.n) + '.'
    : soon.length + ' Fristen in den nächsten 14 Tagen – die nächste ' + when(f.n) + '.';
  await self.registration.showNotification('Belegbox', {
    body, tag: 'belegbox-fristen', renotify: false, icon: 'icons/icon-192.png', badge: 'icons/badge-96.png', data: { url: './' }
  });
  await c.put('./__last', new Response(JSON.stringify({ key })));
}

self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(cs => {
    const w = cs.find(x => new URL(x.url).origin === location.origin);
    return w ? w.focus() : self.clients.openWindow('./');
  }));
});
