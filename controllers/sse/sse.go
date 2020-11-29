package sse

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/m-barthelemy/vpn-webauth/models"
	"github.com/m-barthelemy/vpn-webauth/utils"
	"gorm.io/gorm"
)

// Inspired by https://github.com/kljensen/golang-html5-sse-example/blob/master/server.go
//  and https://gist.github.com/maestre3d/4a42e8fa552694f7c97c4811ce913e23

// This creates a permanent connection between the authenticated client browsers and the app.
// They would reconnect automatically if they get disconnected, change network or IP.
// This way the app can get authenticated clients current IP and compare with any VPN server connection request
// If browser and VPN IPs match, we can transparently allow the connection as long as the user still has
// a valid authenticated session with this app.
// On the client side, a Service Worker is in charge of keeping the connection with the below SSE endpoint,
// meaning that it can be fully transparent for the end user, not needing a permanently open tab or window once they have signed in.
// Another use case is notifying the user that his VPN connection attempt has failed because he needs to re-authenticate using this app:
// VPN connection attempt => /vpn/check fails and no user session detected => client browser IP matches VPN connection attempt source IP
//   ==> send desktop notification to user that they need to authenticate before connecting to VPN.

type ClientAuthorizationStatus struct {
	userID     string
	sourceIP   string
	hasSession bool      // whether the User is authorized or only has an identity cookie for notifications
	expires    time.Time // Expiry of the session or identification cookie
}

// Broker keeps track of the connected clients
/*type SSEBroker struct {
	clients map[chan string]bool

	// Channel into which new clients can be pushed
	newClients chan chan string

	// Channel into which disconnected clients should be pushed
	defunctClients chan chan string

	// Channel into which messages are pushed to be broadcast out
	// to attahed clients.
	messages chan string

	// ID, sourceIP list of authenticated and connected users
	//identities map[string][]string
	identities chan map[string][]ClientAuthorizationStatus
}*/

type SSEBroker struct {
	clientsChannels map[chan string]ClientAuthorizationStatus
	clientsMutex    *sync.Mutex
}

type SSEController struct {
	db     *gorm.DB
	config *models.Config
	broker *SSEBroker
}

// New creates an instance of the controller and sets its DB handle
func New(db *gorm.DB, config *models.Config) *SSEController {
	return &SSEController{
		db:     db,
		config: config,
		broker: &SSEBroker{
			clientsChannels: make(map[chan string]ClientAuthorizationStatus),
			clientsMutex:    new(sync.Mutex),
		},
	}
}

func (b *SSEBroker) Subscribe(clientStatus ClientAuthorizationStatus) chan string {
	b.clientsMutex.Lock()
	defer b.clientsMutex.Unlock()

	channel := make(chan string)
	b.clientsChannels[channel] = clientStatus

	return channel
}

// Unsubscribe removes a client from the broker pool
func (b *SSEBroker) Unsubscribe(channel chan string) {
	b.clientsMutex.Lock()
	defer b.clientsMutex.Unlock()

	//id := b.clientsChannels[channel]
	close(channel)
	delete(b.clientsChannels, channel)
}

func (b *SSEBroker) Publish(clientId string, message string, all bool) {
	b.clientsMutex.Lock()
	defer b.clientsMutex.Unlock()

	for s, clientStatus := range b.clientsChannels {
		if !all {
			// Push to specific client
			if clientStatus.userID == clientId {
				s <- message
				break
			}
		} else { // Push to every client
			s <- message
		}
	}
}

// Start ensures each client receives a periodic ping to maintain the connection
// This signals the app that the connection shouldn't be closes
// Also aims at signalling potential corporate proxies that they should not close the connection.
func (s *SSEController) Start() {
	go func() {
		pingMsg := fmt.Sprintf("%v", time.Now())
		for {
			// Try keeping the connection alive by sending a periodic message
			s.broker.Publish("", pingMsg, true)
			time.Sleep(28e9) // 28s
		}
	}()
}

func (s *SSEController) HandleEvents(w http.ResponseWriter, r *http.Request) {
	var identity = r.Context().Value("identity").(string)
	/*var sessionHasMFA = r.Context().Value("hasMfa").(bool)

	// Check if user is fully logged in
	/f s.config.EnforceMFA && !sessionHasMFA {
		// Notify user to re-authenticate
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}*/

	// Make sure that the writer supports flushing.
	flusher, ok := w.(http.Flusher)
	if !ok {
		log.Println("SSEController: HTTP streaming unsupported")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	sourceIP := utils.New(s.config).GetClientIP(r)
	clientStatus := ClientAuthorizationStatus{userID: identity, sourceIP: sourceIP, hasSession: true, expires: time.Now()}
	channel := s.broker.Subscribe(clientStatus)
	defer s.broker.Unsubscribe(channel)
	log.Printf("Added new SSE client %s connecting from from %s", identity, sourceIP)

	// Set the headers related to event streaming.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Transfer-Encoding", "chunked")

	for {
		select {
		case msg := <-channel:
			_, _ = fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}

	log.Printf("Removed SSE client %s connecting from from %s", identity, sourceIP)
}
