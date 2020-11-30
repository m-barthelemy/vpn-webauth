
self.addEventListener('activate', async () => {
    console.log('service worker activated');
    /*self.clients.matchAll({includeUncontrolled: true}).then(clients => {
        clients.forEach(client => client.postMessage({msg: 'Hello from SW'}));
    });*/
    

    // Worker activation can happen when the user starts their browser after a reboot or 
    // at the begining or their work day.
    // If we still have a valid session, notify the backend so that VPN connection is seamlessly accepted.
    const authResponse = await fetch(`/user/auth/refresh?source=workerstart`, {
        method: "POST",
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
    });
    if (authResponse.status !== 200) {
        console.warn(authResponse);
        return;
    }
});

/*self.addEventListener('message', async event => {
    console.log(`Received client message: ${event.data}`);
    event.source.postMessage("ok");
});*/

self.addEventListener('push', async function(event) {
    var data = {};
    // nonce
    if (event.data) {
        data = event.data.json();
    }
    console.log(`Received push notification: ${JSON.stringify(data)}`);
    const updateAuthResponse = await fetch(`/user/auth/refresh?source=workerpush`, {
        method: "POST",
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    });
    if (updateAuthResponse.status == 401) {
        await self.registration.showNotification(`VPN: authentication required`, {
            body: "Click to authenticate",
            //requireInteraction: true,
        });
        const notifications = await self.registration.getNotifications();
        console.log(`found ${notifications.length} notifications from Service Worker`);
        /*notifications.forEach(function(notification) {
            notification.onclick = async function(){
                await self.clients.openWindow("/");
            }
        });*/
    }
});

self.addEventListener('notificationclick', function(event) {
    console.log('Notification clicked: ', event);
    event.notification.close();
    // Get all the Window clients
    event.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true })).then(function(existingTabs) {
        console.log(`existingTabs: ${JSON.stringify(existingTabs)}`);
        if (existingTabs.length > 0 && 'focus' in existingTabs[0]){
            existingTabs[0].focus();
            existingTabs[0].postMessage("login");
        }
        else {
            self.clients.openWindow("/");
        }
    });
});