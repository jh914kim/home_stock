// Service Worker for Integrated Stock Portfolio PWA
const CACHE_NAME = 'stock-pwa-v6';
const PRECACHE_URLS = [
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png',
  '/icon-maskable-192.png',
  '/icon-maskable-512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(PRECACHE_URLS);
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // 1. Never cache live financial API endpoints or HTML pages
  if (url.pathname.startsWith('/api/') || url.pathname === '/mobile' || url.pathname === '/' || url.pathname.endsWith('.html')) {
    event.respondWith(fetch(event.request));
    return;
  }

  // 2. Navigation requests: Network-first, fallback to cache
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request)
        .catch(() => {
          return caches.match(event.request).then((cached) => {
            if (cached) return cached;
            if (url.pathname.startsWith('/mobile')) {
              return caches.match('/mobile');
            }
            return caches.match('/');
          });
        })
    );
    return;
  }

  // 3. Static assets: Network-first with cache fallback
  event.respondWith(
    fetch(event.request)
      .then((networkResponse) => {
        if (networkResponse && networkResponse.status === 200 && event.request.method === 'GET') {
          const resClone = networkResponse.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, resClone);
          });
        }
        return networkResponse;
      })
      .catch(() => {
        return caches.match(event.request);
      })
  );
});
