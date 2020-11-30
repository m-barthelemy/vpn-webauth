
self.addEventListener('activate', async (event) => {
    console.log('service worker activated');
    event.waitUntil(clients.claim());
    /*self.clients.matchAll({includeUncontrolled: true}).then(clients => {
        clients.forEach(client => client.postMessage({msg: 'Hello from SW'}));
    });*/
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
        await self.registration.showNotification(`${data.Issuer}: authentication required`, {
            body: "Click to authenticate",
            //requireInteraction: true,
        });
    }
});

self.addEventListener('notificationclick', function (e) {
    e.notification.close();
    var redirectUrl = "/";
    e.waitUntil(
        clients.matchAll({includeUncontrolled: true, type: 'window'}).then(function(clients) {
            if (clients && clients.length > 0) {
                clients[0].navigate(redirectUrl);
                clients[0].focus();
            }
            else {
                self.clients.openWindow("/");
            }
        })
    );
});