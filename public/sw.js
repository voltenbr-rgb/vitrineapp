// Vitrine App — service worker do painel (só /dashboard; as vitrines /s/... não são afetadas).
// Estratégia: rede primeiro; sem internet, abre a última versão salva do painel.
const CACHE = 'vitrine-painel-v1';
const SHELL = ['/dashboard.html', '/config.js', '/icons/icon-192.png', '/manifest.webmanifest'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);
  // API, outras origens e qualquer coisa que não seja GET passam direto (sempre dados frescos).
  if (req.method !== 'GET' || url.origin !== self.location.origin || url.pathname.startsWith('/api/')) return;
  if (req.mode === 'navigate' || SHELL.includes(url.pathname)) {
    event.respondWith(
      fetch(req)
        .then((res) => {
          if (res.ok) {
            const copy = res.clone();
            caches.open(CACHE).then((c) => c.put(req.mode === 'navigate' ? '/dashboard.html' : req, copy));
          }
          return res;
        })
        .catch(() => caches.match(req.mode === 'navigate' ? '/dashboard.html' : req)),
    );
  }
});
