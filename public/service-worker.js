// Yenllet PWA Service Worker - v2
// Bumping version forces ALL old caches (vtu-giprince-cache-v4 etc.) to be deleted
// so users get the new splash-first behavior on next visit.
//
// ✅ v2 CHANGE: Added Firebase Cloud Messaging (FCM) push event handlers so
// push notifications work. The previous version was caching-only and threw
// "Failed to execute 'subscribe' on 'PushManager': Subscription failed -
// no active Service Worker" when the user tried to toggle push ON.
const CACHE_NAME = 'yenllet-cache-v10';
const ASSETS_TO_CACHE = [
  '/',
  '/index.html',
  '/splash.html',
  '/login.html',
  '/register.html',
  '/dashboard.html',
  '/forgot-password.html',
  '/terms.html',
  '/privacy.html',
  '/manifest.json',
  '/service-worker.js',
  '/Yenllet.png',
  '/Yenllet1.png'
];

// ✅ Import Firebase SDK so this SW can handle push events.
// Uses Gustmii's Firebase project (tokens isolated per domain — no clash).
importScripts("https://www.gstatic.com/firebasejs/10.7.1/firebase-app-compat.js");
importScripts("https://www.gstatic.com/firebasejs/10.7.1/firebase-messaging-compat.js");

firebase.initializeApp({
  apiKey: "AIzaSyC55H9A30BBMYlXZNxMQLYzndVwa--njHM",
  authDomain: "gustmii.firebaseapp.com",
  projectId: "gustmii",
  storageBucket: "gustmii.firebasestorage.app",
  messagingSenderId: "264078463676",
  appId: "1:264078463676:web:61e455ae7333c61f1a76b9",
  measurementId: "G-M604Y353FB"
});

const messaging = firebase.messaging();

// ✅ Background message handler (for data-only messages from server)
messaging.onBackgroundMessage((payload) => {
  console.log('[SW] Yenllet background message received:', payload);
  const title = (payload.notification && payload.notification.title) || (payload.data && payload.data.title) || 'Yenllet';
  const body = (payload.notification && payload.notification.body) || (payload.data && payload.data.body) || '';
  const clickAction = (payload.data && payload.data.click_action) || '/dashboard.html';
  const options = {
    body: body,
    icon: 'https://res.cloudinary.com/x9cnhu3z/image/upload/v1792062220/Yenllet_Blue_Ribbon_Logo_ltmv0i.png',
    badge: 'https://res.cloudinary.com/x9cnhu3z/image/upload/v1792062220/Yenllet_Blue_Ribbon_Logo_ltmv0i.png',
    data: { click_action: clickAction },
    tag: 'yenllet-push',
    renotify: true,
    requireInteraction: false
  };
  return self.registration.showNotification(title, options);
});

// ✅ Handle notification click — open Yenllet dashboard
self.addEventListener('notificationclick', (event) => {
  console.log('[SW] Notification clicked:', event.notification);
  event.notification.close();
  const targetUrl = (event.notification.data && event.notification.data.click_action) || '/dashboard.html';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windowClients) => {
      for (let i = 0; i < windowClients.length; i++) {
        const client = windowClients[i];
        if (client.url.includes(targetUrl) && 'focus' in client) {
          return client.focus();
        }
      }
      if (clients.openWindow) {
        return clients.openWindow(targetUrl);
      }
    })
  );
});

// ✅ Handle push events directly (fallback if Firebase SDK fails to load)
self.addEventListener('push', (event) => {
  console.log('[SW] Push event received:', event);
  let payload = {};
  try { payload = event.data ? event.data.json() : {}; } catch (e) {
    try { payload = { notification: { title: 'Yenllet', body: event.data ? event.data.text() : '' } }; } catch (e2) { payload = {}; }
  }
  const title = (payload.notification && payload.notification.title) || (payload.data && payload.data.title) || 'Yenllet';
  const body = (payload.notification && payload.notification.body) || (payload.data && payload.data.body) || '';
  const clickAction = (payload.data && payload.data.click_action) || '/dashboard.html';
  const options = {
    body: body,
    icon: 'https://res.cloudinary.com/x9cnhu3z/image/upload/v1792062220/Yenllet_Blue_Ribbon_Logo_ltmv0i.png',
    data: { click_action: clickAction },
    tag: 'yenllet-push'
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

// Install: pre-cache vital assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return Promise.allSettled(
        ASSETS_TO_CACHE.map(url => cache.add(url))
      );
    })
  );
  self.skipWaiting(); // activate new SW immediately
});

// Activate: delete ALL old caches (including the legacy giprince one)
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cache) => {
          if (cache !== CACHE_NAME) {
            console.log('[SW] Deleting old cache:', cache);
            return caches.delete(cache);
          }
        })
      );
    }).then(() => self.clients.claim()) // take control of all open tabs immediately
  );
});

// Fetch handler: network-first, fall back to cache
self.addEventListener('fetch', (event) => {
  const requestUrl = new URL(event.request.url);

  // Only handle same-origin GET requests
  if (requestUrl.origin !== self.location.origin || event.request.method !== 'GET') {
    return;
  }

  // IMPORTANT: When user opens the PWA from home screen and the start_url is "/",
  // serve splash.html instead of index.html so the splash screen shows first.
  if (event.request.mode === 'navigate' &&
      (requestUrl.pathname === '/' || requestUrl.pathname === '/index.html')) {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          if (response.status === 200) {
            const responseClone = response.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(event.request, responseClone);
            });
          }
          return response;
        })
        .catch(() => {
          return caches.match('/splash.html').then((splash) => {
            return splash || caches.match(event.request);
          });
        })
    );
    return;
  }

  // Default: network-first, fall back to cache
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        if (response.status === 200) {
          const responseClone = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseClone);
          });
        }
        return response;
      })
      .catch(() => {
        return caches.match(event.request).then((cachedResponse) => {
          if (cachedResponse) return cachedResponse;
          if (event.request.mode === 'navigate') {
            return caches.match('/splash.html');
          }
        });
      })
  );
});
