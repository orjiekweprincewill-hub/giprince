// public/firebase-messaging-sw.js — Yenllet
// ✅ Uses Gustmii's Firebase project (same API keys) — tokens are isolated per domain
// so there's NO clash between Gustmii and Yenllet notifications.
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

messaging.onBackgroundMessage((payload) => {
    console.log('Yenllet background message received:', payload);

    // ✅ Use Yenllet logo (not Gustmii's) for push notification icons
    if (payload.data && !payload.notification) {
        const title = payload.data.title || "Yenllet Notification";
        const options = {
            body: payload.data.body || "",
            icon: 'https://res.cloudinary.com/x9cnhu3z/image/upload/v1792062220/Yenllet_Blue_Ribbon_Logo_ltmv0i.png',
            data: { click_action: payload.data.click_action || '/dashboard.html' }
        };
        return self.registration.showNotification(title, options);
    }
});

// ✅ Handle notification click — open Yenllet dashboard
self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    const targetUrl = event.notification.data?.click_action || '/dashboard.html';

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
