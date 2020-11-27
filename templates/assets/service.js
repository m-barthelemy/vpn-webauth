self.addEventListener('activate', async () => {
    console.log('Launching service worker');
    // This will be called only once when the service worker is activated.
    if (self.registration.pushManager) {
        try {
            const applicationServerKey = Uint8Array.from(atob('BJ5IxJBWdeqFDJTvrZ4wNRu7UY2XigDXjgiUBYEYVXDudxhEs0ReOJRBcBHsPYgZ5dyV8VjyqzbQKS8V7bUAglk'), c => c.charCodeAt(0))
            const options = { applicationServerKey, userVisibleOnly: true }
            const subscription = await self.registration.pushManager.subscribe(options);
            console.log(JSON.stringify(subscription));
        } catch (err) {
            console.log('Error', err);
        }
    }
    else {
        console.warn("pushManager not available");
    }
    console.log('service worker activated');
    self.clients.matchAll({includeUncontrolled: true}).then(clients => {
        clients.forEach(client => client.postMessage({msg: 'Hello from SW'}));
    });
});

// This is to notify the worker that the web page has successfully authenticated
// and that worker should now connect to the server/backend app SSE events endpoints.
self.addEventListener('message', event => {
    console.log(`Received client message: ${event.data}`);
    // TODO: Connect to SSE endpoint

    event.source.postMessage("ok");
  });