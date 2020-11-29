



self.addEventListener('activate', async () => {
    console.log('Launching service worker');
    // This will be called only once when the service worker is activated.

    console.log('service worker activated');
    /*self.clients.matchAll({includeUncontrolled: true}).then(clients => {
        clients.forEach(client => client.postMessage({msg: 'Hello from SW'}));
    });*/
    /*await self.registration.showNotification("Ascenda VPN: authentication required", {
        body: "Click to authenticate",
        icon:  null
      });*/

    // Worker activation can happen when the user starts their browser after a reboot or 
    // at the begining or their work day.
    // If we still have a valid session, notify the backend so that VPN connection is seamlessly accepted.
    const authResponse = await fetch(`/user//auth/refresh?source=workerstart`, {
        method: "POST",
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
    });
    if (authResponse.status !== 200) {
        //clients.openWindow('https://example.blog.com/2015/03/04/something-new.html');
        console.warn(authResponse);
        return;
    }
});

// This is to notify the worker that the web page has successfully authenticated
// and that worker should now connect to the server/backend app SSE events endpoints.
self.addEventListener('message', async event => {
    console.log(`Received client message: ${event.data}`);
    event.source.postMessage("ok");
  });

self.addEventListener('push', async function(event) {
    console.log(`Received push notification: ${event.data}`);
    const updateAuthResponse = await fetch(`/user/auth/refresh?source=workerpush`, {
        method: "POST",
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
    });
    if (updateAuthResponse.status !== 200) {
        await self.registration.showNotification("Ascenda VPN: authentication required", {
            body: "Click to authenticate",
        });
        const notifications = await self.registration.getNotifications();
        notifications.forEach(function(entry) {
    
        });
    }
    


});

