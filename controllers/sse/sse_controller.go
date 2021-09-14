package sse

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/asaskevich/EventBus"
	"github.com/gofrs/uuid"
	"github.com/m-barthelemy/vpn-webauth/models"
	"github.com/m-barthelemy/vpn-webauth/utils"
	"gorm.io/gorm"
)

// Inspired by https://github.com/kljensen/golang-html5-sse-example/blob/master/server.go
//  and https://gist.github.com/maestre3d/4a42e8fa552694f7c97c4811ce913e23

// This creates a permanent connection between the authenticated client browsers and the app.
// They would reconnect automatically if they get disconnected, change network or IP.
// This is intended to be a fallback mode if Browser push notifications is not available (Hello Safari)
// In that case the user has to keep a tab opened.

type ClientAuthorizationStatus struct {
	userID     string
	sourceIP   string
	hasSession bool      // whether the User is authorized or only has an identity cookie for notifications
	expires    time.Time // Expiry of the session or identification cookie
}

type SSEMessage struct {
	Action string
	Nonce  string
	Issuer string
}

type SSEAuthRequestMessage struct {
	UserId uuid.UUID
	//SourceIP string
	Message SSEMessage
}

type SSEBroker struct {
	clientsChannels map[chan []byte]ClientAuthorizationStatus
	clientsMutex    *sync.Mutex
	bus             *EventBus.Bus
}

var sseEnd = []byte("\n\n")

func (b *SSEBroker) publish(clientId string, message SSEMessage) bool {
	b.clientsMutex.Lock()
	defer b.clientsMutex.Unlock()
	found := false
	data, _ := json.Marshal(&message)
	for s, clientStatus := range b.clientsChannels {
		if clientId != "" {
			// Push to specific client
			if clientStatus.userID == clientId { //&& clientStatus.sourceIP == sourceIP {
				s <- data
				s <- sseEnd
				found = true
			}
		} else { // Push to every client
			s <- data
			found = true
		}
	}
	return found
}

func (b *SSEBroker) eventBusPublishMessage(authRequest SSEAuthRequestMessage) {
	b.publish(authRequest.UserId.String(), authRequest.Message)
}

func (b *SSEBroker) subscribe(clientStatus ClientAuthorizationStatus) chan []byte {
	b.clientsMutex.Lock()
	defer b.clientsMutex.Unlock()

	channel := make(chan []byte)
	b.clientsChannels[channel] = clientStatus

	return channel
}

// Unsubscribe removes a client from the broker pool
func (b *SSEBroker) unsubscribe(channel chan []byte) {
	b.clientsMutex.Lock()
	defer b.clientsMutex.Unlock()

	close(channel)
	delete(b.clientsChannels, channel)
}

type SSEController struct {
	db     *gorm.DB
	config *models.Config
	broker *SSEBroker
}

// New creates an instance of the controller and sets its DB handle
func New(db *gorm.DB, config *models.Config, bus *EventBus.Bus) *SSEController {
	return &SSEController{
		db:     db,
		config: config,
		broker: &SSEBroker{
			clientsChannels: make(map[chan []byte]ClientAuthorizationStatus),
			clientsMutex:    new(sync.Mutex),
			bus:             bus,
		},
	}
}

// Start ensures each client receives a periodic ping to maintain the connection
// This signals the app that the connection shouldn't be closes
// Also aims at signalling potential corporate proxies that they should not close the connection.
func (s *SSEController) Start() {
	go func() {
		eventBus := *s.broker.bus
		eventBus.Subscribe("sse", s.broker.eventBusPublishMessage)
		for {
			// Try keeping the connection alive by sending a periodic message
			s.broker.publish("", SSEMessage{Action: "ping"})
			time.Sleep(28e9) // 28s
		}
	}()
}

func (s *SSEController) HandleEvents(w http.ResponseWriter, r *http.Request) {
	var identity = r.Context().Value("identity").(string)

	// Make sure that the writer supports flushing.
	flusher, ok := w.(http.Flusher)
	if !ok {
		log.Println("SSEController: HTTP streaming unsupported")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	sourceIP := utils.New(s.config).GetClientIP(r)
	clientStatus := ClientAuthorizationStatus{userID: identity, sourceIP: sourceIP, hasSession: true, expires: time.Now()}
	channel := s.broker.subscribe(clientStatus)
	defer s.broker.unsubscribe(channel)
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
			log.Printf("Removed SSE client %s connecting from from %s", identity, sourceIP)
			return
		}
	}
}
