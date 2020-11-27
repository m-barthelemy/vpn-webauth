package sse

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/m-barthelemy/vpn-webauth/models"
	"github.com/m-barthelemy/vpn-webauth/utils"
	"gorm.io/gorm"
)

// Inspired by https://github.com/kljensen/golang-html5-sse-example/blob/master/server.go

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

// Broker keeps track of the connected clients
type SSEBroker struct {
	clients map[chan string]bool

	// Channel into which new clients can be pushed
	newClients chan chan string

	// Channel into which disconnected clients should be pushed
	defunctClients chan chan string

	// Channel into which messages are pushed to be broadcast out
	// to attahed clients.
	messages chan string

	// email, sourceIP list of authenticated and connected users
	identities map[string][]string
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
			make(map[chan string]bool),
			make(chan (chan string)),
			make(chan (chan string)),
			make(chan string),
			make(map[string][]string),
		},
	}
}

// Start manages addition and removal of clients, and broadcasts messages to them.
func (s *SSEController) Start() {
	go func() {
		for {
			// Block until we receive from one of the three following channels.
			select {

			case evt := <-s.broker.newClients:

				// There is a new client attached and we want to start sending them messages.
				s.broker.clients[evt] = true
				log.Println("Added new client")

			case evt := <-s.broker.defunctClients:

				// A client has detached and we want to stop sending them messages.
				delete(s.broker.clients, evt)
				close(evt)

				log.Println("Removed client")

			case msg := <-s.broker.messages:

				// There is a new message to send.  For each attached client, push the new message
				// into the client's message channel.
				for s := range s.broker.clients {
					s <- msg
				}
				log.Printf("Broadcast message to %d active clients, %d defuncts, %d identities", len(s.broker.clients), len(s.broker.defunctClients), len(s.broker.identities))
			}
		}
	}()

	go func() {
		for i := 0; ; i++ {
			// Try keeping the connection alive by sending a periodic message
			s.broker.messages <- fmt.Sprintf("%v", time.Now())
			time.Sleep(55e9) // 55s
		}
	}()
}

func (s *SSEController) HandleEvents(w http.ResponseWriter, r *http.Request) {
	var identity = r.Context().Value("identity").(string)
	var sessionHasMFA = r.Context().Value("hasMfa").(bool)

	// Ensure user is fully logged in
	if s.config.EnforceMFA && !sessionHasMFA {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// Make sure that the writer supports flushing.
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	// Create a new channel, over which the broker can send this client messages.
	messageChan := make(chan string)

	// Add this client to the map of those that should receive updates
	s.broker.newClients <- messageChan

	// Listen to the closing of the http connection via the CloseNotifier
	notify := w.(http.CloseNotifier).CloseNotify()
	go func() {
		<-notify
		// Remove this client from the map of attached clients
		// when `EventHandler` exits.
		s.broker.defunctClients <- messageChan
		log.Println("HTTP connection just closed.")
	}()

	// Set the headers related to event streaming.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Transfer-Encoding", "chunked")

	sourceIP := utils.New(s.config).GetClientIP(r)
	if s.broker.identities[identity] == nil {
		s.broker.identities[identity] = []string{}
	}
	exists := false
	for _, ip := range s.broker.identities[identity] {
		if ip == sourceIP {
			exists = true
			break
		}
	}
	if !exists {
		s.broker.identities[identity] = append(s.broker.identities[identity], sourceIP)
	}

	// Don't close the connection, instead loop endlessly.
	for {
		// Read from the messageChan.
		msg, open := <-messageChan

		if !open {
			// If the messageChan was closed, the client has disconnected.
			break
		}

		fmt.Fprintf(w, "data: Message: %s\n\n", msg)

		// Immediately send data to client
		flusher.Flush()
	}

	// Done or client disconnected
	delete(s.broker.identities, identity)
}
