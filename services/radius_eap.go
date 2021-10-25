package services

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/ReneKroon/ttlcache/v2"
	"github.com/bronze1man/radius"
	"github.com/dreadl0ck/tlsx"
	"github.com/m-barthelemy/vpn-webauth/MSCHAPV2"
	"github.com/m-barthelemy/vpn-webauth/models"
	"github.com/m-barthelemy/vpn-webauth/utils"
)

// Identifies an EAP-TLS message
const EapTypeTLS = 13

// [rfc3579] 4.3.3.  Dictionary Attacks: secret should be at least 16 characters
const minRadiusSecretLength = 16

// This is the maximum time a client has to complete the EAP authentication phase.
const eapSessionTimeout = 5 * time.Second

// Protect ourselves against suspicously big records
const maxTlsRecordSize = 64 * 1024
const eapHeaderSize = 5

// If the TLS server successfully authenticates the client, it will write some random data.
// A failed TLs auth will return a much smaller value. This is for now the fastest and simplest way of getting the TLS handshake status from the TLS server/proxy
const dummyTlsOkDataSize = 1024

type RadiusSession struct {
	Challenge   [16]byte
	NTResponse  [24]byte
	EapTlsState EapTlsState
}

type EapTlsState struct {
	Step            EapTlsStep
	TlsAuthResultCh chan bool
	TlsServerConn   net.Conn
	TlsBuffer       []byte
	BufferPos       int
}

// EapTlsStep keeps track of the current step during the EAP-TLS exchanges between the Radius client and us
type EapTlsStep uint

const (
	TlsStart             EapTlsStep = 0
	TlsServerHello       EapTlsStep = 1
	TlsClientKeyExchange EapTlsStep = 2
	TlsAuthentication    EapTlsStep = 3
)

// EAP-TLS optional Fragment byte.
// Fragments are used when sending ServerHello to client, and when receiving cert from client
// Also when asking the client to initiale the TLS handshake (TLS Start bit)
type EapTlsFragment byte

const (
	MoreToCome          EapTlsFragment = (1 << 6)
	LengthIncluded      EapTlsFragment = (1 << 7)
	LengthAndMoreToCome EapTlsFragment = (1 << 7) | (1 << 6)
	TlsStartFlag        EapTlsFragment = (1 << 5)
)

var sessions ttlcache.Cache

type RadiusService struct {
	handshakeSocketPath string
	handshakeServer     net.Listener
	config              *models.Config
	userManager         *UserManager
	webSessManager      *WebSessionManager
}

func NewRadiusServer(config *models.Config, userManager *UserManager, webSessManager *WebSessionManager) *RadiusService {
	// For security reasons we require the Radius secret to have a min length (which is still weak)
	if len(config.RadiusSecret) < minRadiusSecretLength {
		log.Fatalf("[RADIUS] secret must be at least %d characters", minRadiusSecretLength)
	}
	sessions = *ttlcache.NewCache()
	sessions.SetCacheSizeLimit(2000)
	sessions.SetTTL(eapSessionTimeout)
	sessions.SkipTTLExtensionOnHit(true)
	// Ensure we close the connection to the TLS handshake server when the session expires.
	sessions.SetExpirationCallback(func(key string, value interface{}) {
		session, _ := getSession(key)
		if session != nil {
			log.Debugf("[EAP] deleting expired session %s", key)
			if session.EapTlsState.TlsServerConn != nil {
				session.EapTlsState.TlsServerConn.Close()
			}
		}
	})

	// TLS server used for EAP-TLS handshake
	tmpfile, err := ioutil.TempFile("", "eap-tls-handshake")
	if err != nil {
		log.Fatalf("[EAP-TLS] failed to create temporary file for handshake server: %v", err)
	}
	handshakeSocketPath := tmpfile.Name()
	os.Remove(handshakeSocketPath)

	return &RadiusService{
		config:              config,
		handshakeSocketPath: handshakeSocketPath,
		userManager:         userManager,
		webSessManager:      webSessManager,
	}
}

func (r *RadiusService) Start() {
	// Start the "TLS handshake proxy" in charge of EAP-TLS connections
	log.Infof("[EAP-TLS] starting TLS handshake service...")
	tlsConfig := r.getTLSServerConfig()
	handshakeServer, err := tls.Listen("unix", r.handshakeSocketPath, tlsConfig)
	if err != nil {
		log.Fatalf("[TLS] failed to bind unix socket %q for TLS handshake server: %v", r.handshakeSocketPath, err)
	}
	r.handshakeServer = handshakeServer

	radiusAddr := fmt.Sprintf("0.0.0.0:%d", r.config.RadiusPort)
	s := radius.NewServer(radiusAddr, r.config.RadiusSecret, r)

	go func() {
		log.Infof("[RADIUS] starting listener (%s)...", radiusAddr)
		err := s.ListenAndServe()
		if err != nil {
			log.Fatalf("[RADIUS] unable to start listener: %s", err)
		}
	}()
}

// Check https://github.com/keysonZZZ/kmg/blob/master/third/kmgRadius/Auth.go
// for EAP and MSCHAP challenge response
func (r *RadiusService) RadiusHandle(request *radius.Packet) *radius.Packet {
	npac := request.Reply()
	npac.Code = radius.AccessReject

	if allowed := r.isNasAllowed(request); !allowed {
		log.Errorf("[RADIUS] NAS %s IP %s is not in ALLOWEDVPNGWIPS list", request.GetNASIdentifier(), request.ClientAddr)
		return npac
	}

	if request.HasAVP(radius.FramedMTU) {
		log.Warn("[RADIUS] received packet has Framed MTU attribute, this is not supported")
	}

	userName := request.GetUsername()
	if userName == "" {
		npac.AddAVP(radius.AVP{Type: radius.ReplyMessage, Value: []byte("Username attribute is required")})
		return radiusError("[RADIUS] Username is required but got empty/null value", "", npac)
	}

	/*clientIP := net.ParseIP(request.Ge())
	if clientIP == nil {
		msg := "[RADIUS] attribute %s value '%s' is not a valid IP address."
		msg += "If using Strongswan, make sure you set `station_id_with_port = no` under the `eap-radius` config section."
		return radiusError(fmt.Sprintf(msg, radius.CallingStationId.String(), request.GetCallingStationId()), "", npac)
	}*/
	log := utils.ConfigureLogger(userName, request.GetCallingStationId())

	switch request.Code {
	case radius.AccessRequest:
		if !request.HasAVP(radius.EAPMessage) {
			npac.AddAVP(radius.AVP{Type: radius.ReplyMessage, Value: []byte("only EAP is supported")})
			return radiusError("[RADIUS] request doesn't contain any EAP message", "", npac)
		}

		eap, err := r.getEAPPacket(request)
		if err != nil {
			return radiusError(err.Error(), "", npac)
		}

		if eap == nil {
			npac.AddAVP(radius.AVP{Type: radius.ReplyMessage, Value: []byte("only EAP is supported")})
			return radiusError(
				fmt.Sprintf("[EAP] received non-EAP request from %s (%s). Only EAP is supported.", request.ClientAddr, request.GetNASIdentifier()),
				"",
				npac,
			)
		}
		log.Debugf("[EAP] received message kind is EAP, type %s, code %s, identifier %d, data size %d", eap.Type.String(), eap.Code.String(), eap.Identifier, len(eap.Data))

		// [rfc3579] 3.1. Message-Authenticator is Required for EAP.
		// Access-Request packets including EAP-Message attribute(s) without a Message-Authenticator attribute SHOULD be silently discarded
		messageAuthenticator := request.GetAVP(radius.MessageAuthenticator)
		if messageAuthenticator.Value == nil {
			return radiusError(fmt.Sprintf("[RADIUS] received EAP packet without %s attribute, discarding", radius.MessageAuthenticator.String()), "", npac)
		}
		// Else, if we have a Message-Authenticator, it is automatically validated before service.RadiusHandle is called.

		// [rfc3579] 2.6.2. Role Reversal
		if eap.Code == radius.EapCodeRequest {
			log.Errorf("[EAP] received unsupported packet type '%s', rejecting", eap.Code.String())
			rejectResponseEAPPacket := radius.EapPacket{
				Identifier: eap.Identifier,
				Code:       radius.EapCodeRequest,
				Type:       radius.EapTypeNak,
			}

			npac.AddAVP(radius.AVP{
				Type:  radius.AttributeType(radius.EAPMessage),
				Value: rejectResponseEAPPacket.Encode(),
			})
			return npac
		}

		switch eap.Type {
		case radius.EapTypeIdentity:
			var currentRequest string
			if r.config.EAPMode == "mschapv2" {
				sendMSCHAPv2Challenge(userName, eap, npac)
				currentRequest = "MSCHAPv2"
			} else if r.config.EAPMode == "tls" {
				sendTLSRequest(userName, eap, npac, request)
				currentRequest = "TLS-Start"
			}
			log.Debugf("[EAP] sending %s request as a response to EAP identity request", currentRequest)
			return npac

		case radius.EapTypeMSCHAPV2:
			if r.config.EAPMode != "mschapv2" {
				return radiusError(fmt.Sprintf("[RADIUS] received EAP-MSCHAPv2 packet but configured EAPMODE is %s", r.config.EAPMode), "", npac)
			}
			return r.handleMSCHAPv2(eap, request)

		case EapTypeTLS:
			if r.config.EAPMode != "tls" {
				return radiusError(fmt.Sprintf("[RADIUS] received EAP-TLS packet but configured EAPMODE is %s", r.config.EAPMode), "", npac)
			}
			return r.handleTLS(eap, request)

		default:
			return radiusError(fmt.Sprintf("[RADIUS] received unsupported EAP packet type %s", eap.Type.String()), "", npac)
		}

	case radius.AccountingRequest:
		// accounting start or end
		fmt.Printf("********>>>>>>> Received AccountingRequest")
		npac.Code = radius.AccountingResponse
	default:
		npac.AddAVP(radius.AVP{
			Type:  radius.ReplyMessage,
			Value: []byte(fmt.Sprintf("Unsupported message type '%s'", request.Code.String())),
		})
		return radiusError(fmt.Sprintf("[RADIUS] received unsupported message type '%s'", request.Code.String()), "", npac)
	}
	return npac
}

func (r *RadiusService) isNasAllowed(request *radius.Packet) bool {
	nasIPRaw := strings.Split(request.ClientAddr, ":")[0]
	nasIP := net.ParseIP(nasIPRaw)
	for _, allowedNet := range r.config.AllowedVPNGwIPs {
		ipNet := net.IPNet(allowedNet)
		if ipNet.Contains(nasIP) {
			return true
		}
	}
	return false
}

// Returns the full EAP packet contained in the Radius packet, reassembled if split across multiple Radius AVPs
func (r *RadiusService) getEAPPacket(request *radius.Packet) (*radius.EapPacket, error) {
	// `request.GetEAPMessage()` crashes
	// - if there's no valid EAP message
	// - if the EAP message is fragmented (length > current AVP length)
	// so we need to guard against that.
	checkEapAvp := request.GetAVP(radius.EAPMessage)
	var eap *radius.EapPacket
	if len(checkEapAvp.Value) < 5 {
		return nil, errors.New("[RADIUS] request contains an invalid EAP message (length < 5)")
	} else if len(checkEapAvp.Value) == 253 {
		// We may have a big EAP packet split into multiple AVPs
		totalEapMsgSize := binary.BigEndian.Uint16(checkEapAvp.Value[2:4])
		log.Debugf("[EAP] received EAP message (%d total length) split into multiple Radius AVPs", totalEapMsgSize)
		// We need to set the EAP packet size to the current AVP's max size instead of the total fragmented packet size other we cannot parse it
		binary.BigEndian.PutUint16(checkEapAvp.Value[2:4], uint16(253))
		var err error
		// The first AVP contains the EAP packet header
		eap, err = radius.EapDecode(checkEapAvp.Value)
		if err != nil {
			return nil, fmt.Errorf("[EAP] unable to parse first EAP fragment: %s", err)
		}
		eapAVPStarted := false
		for _, avp := range request.AVPs {
			if avp.Type == radius.EAPMessage {
				if !eapAVPStarted {
					eapAVPStarted = true
				} else {
					// Subsequent EAP AVPs contain raw data to be concatenated to the first AVP
					eap.Data = append(eap.Data, avp.Value...)
				}
			}
		}
		log.Debugf("[EAP-TLS] packet flags = %08b, reported size %d bytes, found %d bytes of data", eap.Data[0], totalEapMsgSize, len(eap.Data))
	} else {
		eap = request.GetEAPMessage()
	}
	return eap, nil
}

func (r *RadiusService) handleMSCHAPv2(eap *radius.EapPacket, request *radius.Packet) *radius.Packet {
	log := utils.ConfigureLogger(request.GetUsername(), request.GetCallingStationId())
	npac := request.Reply()
	npac.Code = radius.AccessReject

	msChapV2Packet, err := MSCHAPV2.Decode(eap.Data)
	if err != nil {
		return radiusError(fmt.Sprintf("[EAP-MsCHAPv2] unable to decode received packet: %s", err), "", npac)
	}
	log.Debugf("[EAP-MsCHAPv2] received request with OpCode %s", msChapV2Packet.OpCode().String())

	sessionId, session, err := checkRadiusSession(request)
	if err != nil {
		return radiusError(fmt.Sprintf("Invalid State/Session ID %s", sessionId), "", npac)
	}

	switch msChapV2Packet.OpCode() {
	case MSCHAPV2.OpCodeResponse:
		session.NTResponse = msChapV2Packet.(*MSCHAPV2.ResponsePacket).NTResponse

		npac.SetAVP(radius.AVP{
			Type:  radius.State,
			Value: []byte(sessionId),
		})

		successPacket := MSCHAPV2.ReplySuccessPacket(&MSCHAPV2.ReplySuccessPacketRequest{
			AuthenticatorChallenge: session.Challenge,
			Response:               msChapV2Packet.(*MSCHAPV2.ResponsePacket),
			Username:               []byte(request.GetUsername()),
			Password:               []byte(r.config.EAPMSCHAPv2Password),
			//Message:                "Success",
		})

		challengeResponseEAPPacket := radius.EapPacket{
			Identifier: eap.Identifier,
			Code:       radius.EapCodeRequest,
			Type:       radius.EapTypeMSCHAPV2,
			Data:       successPacket.Encode(),
		}

		npac.AddAVP(radius.AVP{
			Type:  radius.AttributeType(radius.EAPMessage),
			Value: challengeResponseEAPPacket.Encode(),
		})

		log.Infof("[RADIUS] sending Access-Challenge again in response to %s", MSCHAPV2.OpCodeResponse.String())
		npac.Code = radius.AccessChallenge
		return npac

	case MSCHAPV2.OpCodeSuccess:

		npac.AddAVP(radius.AVP{
			Type:  radius.AttributeType(radius.UserName),
			Value: []byte(request.GetUsername()),
		})

		// MS-MPPE-Encryption-Policy: Encryption-Allowed (1)
		npac.AddAVP(radius.AVP{
			Type:  radius.AttributeType(radius.VendorSpecific),
			Value: []byte{0x00, 0x00, 0x01, 0x37, 0x07, 0x06, 0, 0, 0, 1},
		})

		// MS-MPPE-Encryption-Types: RC4-40-128 (6)
		npac.AddAVP(radius.AVP{
			Type:  radius.AttributeType(radius.VendorSpecific),
			Value: []byte{0x00, 0x00, 0x01, 0x37, 0x08, 0x06, 0, 0, 0, 6},
		})

		sendkey, recvKey := MSCHAPV2.MsCHAPV2GetSendAndRecvKey([]byte(r.config.EAPMSCHAPv2Password), session.NTResponse)
		sendKeyMsmpp, err := MSCHAPV2.NewMSMPPESendOrRecvKeyVSA(request, MSCHAPV2.VendorTypeMSMPPESendKey, sendkey).Encode()
		if err != nil {
			return radiusError(fmt.Sprintf("[EAP-MsCHAPv2] unable to generate sendkey: %s", err), sessionId, npac)
		}
		recvKeyMsmpp, err := MSCHAPV2.NewMSMPPESendOrRecvKeyVSA(request, MSCHAPV2.VendorTypeMSMPPERecvKey, recvKey).Encode()
		if err != nil {
			return radiusError(fmt.Sprintf("[EAP-MsCHAPv2] unable to generate recvKey: %s", err), sessionId, npac)
		}
		npac.AddAVP(radius.AVP{
			Type:  radius.AttributeType(radius.VendorSpecific),
			Value: sendKeyMsmpp,
		})
		npac.AddAVP(radius.AVP{
			Type:  radius.AttributeType(radius.VendorSpecific),
			Value: recvKeyMsmpp,
		})

		statusPacket := radius.EapPacket{
			Identifier: eap.Identifier + 1,
			Type:       radius.EapTypeMSCHAPV2,
			Code:       radius.EapCodeFailure,
			Data:       []byte{0},
		}
		if r.checkWebSession(request.GetUsername(), request.GetCallingStationId(), string(request.GetNasIpAddress())) {
			statusPacket.Code = radius.EapCodeSuccess
			npac.Code = radius.AccessAccept
		}

		npac.AddAVP(radius.AVP{
			Type:  radius.AttributeType(radius.EAPMessage),
			Value: statusPacket.Encode(),
		})
		sessions.Remove(sessionId)
		log.Infof("[RADIUS] sending %s response to NAS '%s'", npac.Code.String(), request.GetNASIdentifier())
		return npac

	default:
		return radiusError(fmt.Sprintf("[EAP-MsCHAPv2] invalid request OpCode %s", msChapV2Packet.OpCode().String()), sessionId, npac)
	}
}

func (r *RadiusService) handleTLS(eap *radius.EapPacket, request *radius.Packet) *radius.Packet {
	log := utils.ConfigureLogger(request.GetUsername(), request.GetCallingStationId())
	npac := request.Reply()
	npac.Code = radius.AccessReject

	sessionId, session, err := checkRadiusSession(request)
	if err != nil {
		return radiusError(fmt.Sprintf("[RADIUS] error checking client session: %s", err), "", npac)
	}
	eapState := session.EapTlsState

	isAck := false
	var tlsPacket []byte
	if len(eap.Data) == 1 && eap.Data[0] == 0 {
		isAck = true
		log.Debugf("[EAP-TLS] received ACK")
	} else if len(eap.Data) < 5 {
		return radiusError(fmt.Sprintf("[EAP-TLS] received invalid record: too small (%d bytes), value %b", len(eap.Data), eap.Data), "", npac)
	} else {
		tlsPacket = eap.Data[5:]
	}

	if eapState.Step == TlsStart && !isAck {
		eapState.TlsAuthResultCh = make(chan bool)
		go func() {
			listenerConn, err := r.handshakeServer.Accept()
			if err != nil {
				log.Errorf("[EAP-TLS] unable to accept handshake server client connection: %s", err)
			}
			go tlsClientAuth(eapState.TlsAuthResultCh, listenerConn, r.getTLSServerConfig(), request.GetUsername())
		}()
		conn, err := net.Dial("unix", r.handshakeServer.Addr().String())
		if err != nil {
			return radiusError(fmt.Sprintf("[EAP-TLS] unable to connect to TLS handshake server: %s", err), sessionId, npac)
		}

		written, err := conn.Write(tlsPacket)
		if err != nil {
			return radiusError(fmt.Sprintf("[EAP-TLS] unable to send ClientHello: %s", err), sessionId, npac)
		}
		if written != len(tlsPacket) {
			return radiusError(fmt.Sprintf("[EAP-TLS] unable to write ClientHello to TLS server: only %d/%d written", written, len(tlsPacket)), sessionId, npac)
		}
		log.Debugf("[EAP-TLS] step %v: received ClientHello, %d bytes", eapState.Step, written)

		reply := make([]byte, maxTlsRecordSize)
		read, err := conn.Read(reply)
		if err != nil {
			return radiusError(fmt.Sprintf("[EAP-TLS] unable to read ServerHello: %s", err), sessionId, npac)
		}
		if read == len(reply) {
			return radiusError(
				fmt.Sprintf("[EAP-TLS] TLS ServerHello was %d bytes or greater. This is not supported. Your certificate chain might be too long", read),
				sessionId,
				npac,
			)
		}
		log.Debugf("[EAP-TLS] ServerHello is %d bytes", read)

		eapState.TlsBuffer = reply[:read]
		eapState.BufferPos = 0
		eapState.TlsServerConn = conn
		serverHello := tlsx.ServerHello{}
		err = serverHello.Unmarshal(eapState.TlsBuffer)
		if err != nil {
			log.Errorf("[EAP-TLS] bogus ServerHello: %s", err)
		}
		cipher := serverHello.CipherSuite
		tlsVersion := tlsx.Version(serverHello.Vers).String()
		log.Infof("[EAP-TLS] ServerHello: selected %s, Cipher suite %s", tlsVersion, tlsx.CipherSuite(cipher).String())
	}

	if eapState.BufferPos == 0 || isAck {
		log.Debugf("[EAP-TLS] current position in cached buffer of data waiting to be sent to client: %d/%d", eapState.BufferPos, len(eapState.TlsBuffer))
		npac.Code = radius.AccessChallenge
		npac.SetAVP(radius.AVP{
			Type:  radius.State,
			Value: []byte(sessionId),
		})

		maxAttrSize := 248 // max size of a Radius attribute data
		// The ServerHello is assumed to be too big to be sent in a single Radius packet due to the MTU size limit.
		// We'll split it into chunks of 1024 bytes.
		eapPacketMaxSize := 1024
		// Size of the data in the current EAP packet
		thisEapPacketSize := eapPacketMaxSize
		if len(eapState.TlsBuffer)-eapState.BufferPos < eapPacketMaxSize {
			thisEapPacketSize = len(eapState.TlsBuffer) - eapState.BufferPos
		}
		eapId := eap.Identifier + 1
		var data []byte
		packetRead := 0
		addFragmentBit := (thisEapPacketSize == eapPacketMaxSize)
		for pos := eapState.BufferPos; pos < eapState.BufferPos+thisEapPacketSize; {
			if eapState.BufferPos == 0 && packetRead == 0 {
				maxAttrSize = 243
			} else if packetRead == 0 {
				maxAttrSize = 247
			} else if thisEapPacketSize-packetRead < maxAttrSize {
				maxAttrSize = thisEapPacketSize - packetRead
			} else {
				maxAttrSize = 253
			}

			var eapResponseData []byte
			if eapState.BufferPos == 0 && packetRead == 0 {
				log.Debugf("[EAP-TLS] Setting TLS record size of %d on first Radius EAP AVP", len(eapState.TlsBuffer))
				data = make([]byte, maxAttrSize+5)
				data[0] = byte(LengthAndMoreToCome)
				binary.BigEndian.PutUint32(data[1:5], uint32(len(eapState.TlsBuffer)))
				copy(data[5:], eapState.TlsBuffer[pos:(pos+maxAttrSize)])

				radiusServHelloPacket := radius.EapPacket{
					Identifier: eapId,
					Code:       radius.EapCodeRequest,
					Type:       EapTypeTLS,
					Data:       data,
				}
				eapResponseData = radiusServHelloPacket.Encode()
				binary.BigEndian.PutUint16(eapResponseData[2:4], uint16(thisEapPacketSize+eapHeaderSize+5))
			} else if packetRead == 0 {
				data = make([]byte, maxAttrSize+1)
				if addFragmentBit {
					data[0] = byte(MoreToCome)
				} else {
					data[0] = 0
				}
				binary.BigEndian.PutUint32(data[1:5], uint32(thisEapPacketSize))
				copy(data[1:], eapState.TlsBuffer[pos:(pos+maxAttrSize)])

				radiusServHelloPacket := radius.EapPacket{
					Identifier: eapId,
					Code:       radius.EapCodeRequest,
					Type:       EapTypeTLS,
					Data:       data,
				}
				eapResponseData = radiusServHelloPacket.Encode()
				binary.BigEndian.PutUint16(eapResponseData[2:4], uint16(thisEapPacketSize+eapHeaderSize+1))
			} else {
				data = make([]byte, maxAttrSize)
				copy(data, eapState.TlsBuffer[pos:(pos+maxAttrSize)])
				eapResponseData = data
			}

			npac.AddAVP(radius.AVP{
				Type:  radius.AttributeType(radius.EAPMessage),
				Value: eapResponseData,
			})
			pos = pos + maxAttrSize
			packetRead = packetRead + maxAttrSize
		}
		eapState.BufferPos += thisEapPacketSize
		if eapState.BufferPos == len(eapState.TlsBuffer) {
			eapState.Step = TlsServerHello
			log.Debug("[EAP-TLS] finished splitting ServerHello")
		}
		session.EapTlsState = eapState
		log.Debugf("[EAP-TLS] step %v: sending ServerHello fragment, %d bytes", eapState.Step, thisEapPacketSize)
		return npac
	}

	tlsDataPos := 0

	// After sending the TLS ServerHello.
	// We should now have received either an error, or the client response including the client cert.
	if eapState.Step == TlsServerHello || eapState.Step == TlsClientKeyExchange {
		lengthIncluded := (eap.Data[0] & byte(LengthIncluded)) != 0
		hasMoreFragments := (eap.Data[0] & byte(MoreToCome)) != 0

		if lengthIncluded && eapState.Step == TlsClientKeyExchange {
			return radiusError("[EAP-TLS] client wants to send a new TLS record while we are already waiting for one", sessionId, npac)
		}
		if lengthIncluded {
			tlsDataPos += 4
			tlsRecordSize := binary.BigEndian.Uint32(eap.Data[1:5])
			log.Debugf("[EAP-TLS] DEBUG: client wants to send a client_key_exchange TLS record of %d bytes", tlsRecordSize)
			if tlsRecordSize > maxTlsRecordSize {
				return radiusError(fmt.Sprintf("[EAP-TLS] client wants to send a TLS record of %d bytes, too big, rejecting", tlsRecordSize), sessionId, npac)
			}
			eapState.TlsBuffer = make([]byte, tlsRecordSize)

		} else if eapState.Step != TlsClientKeyExchange {
			eapState.TlsBuffer = make([]byte, len(eap.Data))
		}

		if eapState.Step == TlsServerHello {
			eapState.Step = TlsClientKeyExchange
			eapState.BufferPos = 0
		}

		// We assume that if we have lengthIncluded or hasMoreFragments or both, then the first byte is an EAP-TLS fragmentation header
		// Otherwise we assume that the is no fragmentation byte and that the TLS record starts at pos 0. But is that correct?
		if lengthIncluded || hasMoreFragments || eap.Data[0] == 0 {
			tlsDataPos += 1
		}
	}

	if eapState.Step == TlsClientKeyExchange {
		copied := copy(eapState.TlsBuffer[eapState.BufferPos:], eap.Data[tlsDataPos:])
		eapState.BufferPos += copied
		session.EapTlsState = eapState

		hasMoreFragments := (eap.Data[0] & byte(MoreToCome)) != 0
		if hasMoreFragments {
			if eapState.BufferPos >= len(eapState.TlsBuffer) {
				return radiusError("[EAP-TLS] client wants to send more TLS data than announced, rejecting", sessionId, npac)
			}
			npac.SetAVP(radius.AVP{
				Type:  radius.State,
				Value: []byte(sessionId),
			})

			ackPacket := radius.EapPacket{
				Identifier: eap.Identifier + 1,
				Code:       radius.EapCodeRequest,
				Type:       EapTypeTLS,
				Data:       []byte{0},
			}
			npac.Code = radius.AccessChallenge
			npac.AddAVP(radius.AVP{
				Type:  radius.AttributeType(radius.EAPMessage),
				Value: ackPacket.Encode(),
			})
			log.Debug("[EAP-TLS] more EAP fragments expected from client, sending ACK")
			return npac
		} else {
			log.Debugf("[EAP-TLS] no more EAP fragments expected from client, received client_key_exchange, %d/%d bytes", eapState.BufferPos, len(eapState.TlsBuffer))
		}

		tlsPacket = eapState.TlsBuffer
		written, err := eapState.TlsServerConn.Write(tlsPacket)
		if err != nil {
			return radiusError(fmt.Sprintf("[EAP-TLS] unable to send client_key_exchange: %s", err), sessionId, npac)
		}
		if written != len(tlsPacket) {
			return radiusError(
				fmt.Sprintf("[EAP-TLS] error sending client_key_exchange to TLS server: data size %d, but only wrote %d", len(tlsPacket), written),
				sessionId,
				npac,
			)
		}
		reply := make([]byte, 4*1024)
		read, err := eapState.TlsServerConn.Read(reply)
		if err != nil {
			return radiusError(fmt.Sprintf("[EAP-TLS] unable to read TLS server response to client_key_exchange : %s", err), sessionId, npac)
		}

		log.Debugf("[EAP-TLS] received client_key_exchange was %d bytes, TLS server response was %d bytes", written, read)
		npac.Code = radius.AccessChallenge
		npac.SetAVP(radius.AVP{
			Type:  radius.State,
			Value: []byte(sessionId),
		})
		const maxAttrSize = 248 // max size of a Radius attribute data
		for pos := 0; pos < read; pos = pos + maxAttrSize {
			until := pos + maxAttrSize
			if read-pos < maxAttrSize {
				until = read
			}
			radiusServHelloPacket := radius.EapPacket{
				Identifier: eap.Identifier + 1,
				Code:       radius.EapCodeRequest,
				Type:       EapTypeTLS,
				Data:       reply[pos:until],
			}
			npac.AddAVP(radius.AVP{
				Type:  radius.AttributeType(radius.EAPMessage),
				Value: radiusServHelloPacket.Encode(),
			})
		}
		log.Debugf("[EAP-TLS] sending TLS finished, %d bytes", read)
		eapState.Step = TlsAuthentication
		session.EapTlsState = eapState
		sessions.SetWithTTL(sessionId, session, eapSessionTimeout)

	} else if eapState.Step == TlsAuthentication {
		acceptRejectPacket := radius.EapPacket{
			Identifier: eap.Identifier + 1,
			Type:       EapTypeTLS,
			Code:       radius.EapCodeFailure,
			Data:       []byte{0},
		}
		tlsAuthSuccess := <-eapState.TlsAuthResultCh
		if !tlsAuthSuccess {
			log.Errorf("[EAP-TLS] client rejected")
		} else {
			log.Info("[EAP-TLS] client accepted")
			if r.checkWebSession(request.GetUsername(), request.GetCallingStationId(), string(request.GetNasIpAddress())) {
				npac.Code = radius.AccessAccept
				acceptRejectPacket.Code = radius.EapCodeSuccess
			}
		}
		npac.AddAVP(radius.AVP{
			Type:  radius.AttributeType(radius.EAPMessage),
			Value: acceptRejectPacket.Encode(),
		})
		eapState.TlsServerConn.Close()
		sessions.Remove(sessionId)
		log.Infof("[RADIUS] sending %s response to NAS '%s'", npac.Code.String(), request.GetNASIdentifier())
	}

	return npac
}

func (r *RadiusService) checkWebSession(identity string, sourceIP string, nasIP string) bool {
	log := utils.ConfigureLogger(identity, sourceIP)
	err := r.webSessManager.CheckSession(identity, sourceIP, nasIP)
	if err != nil {
		log.Errorf("unable to authenticate client via web: %s", err)
		return false
	}
	log.Infof("client %s successfully authenticated", identity)
	return true
}

func (r *RadiusService) getTLSServerConfig() *tls.Config {
	serverCert, err := tls.LoadX509KeyPair(r.config.EAPTLSCertificatePath, r.config.EAPTLSKeyPath)
	if err != nil {
		log.Fatalf("[EAP-TLS] error getting VPN server certificate or key: %s", err)
	}
	for _, certBytes := range serverCert.Certificate {
		serverCert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			log.Fatalf("[EAP-TLS] failed to parse clients CA certificate: " + err.Error())
		}
		validityDays := int(math.Round(serverCert.NotAfter.Sub(time.Now()).Hours() / 24))
		if validityDays < 0 {
			log.Fatalf("[EAP-TLS] server certificate %s has expired", serverCert.Subject.String())
		} else if validityDays < 7 {
			log.Warnf("[EAP-TLS] server certificate %s expires in %d days", serverCert.Subject.String(), validityDays)
		}
	}

	var clientCertCAs *x509.CertPool
	clientCertCAs = x509.NewCertPool()
	clientsCaBytes, err := ioutil.ReadFile(r.config.EAPTLSClientCAPath)
	if err != nil {
		log.Fatalf("[EAP-TLS] error reading VPN clients CA file: %s", err)
	}

	if ok := clientCertCAs.AppendCertsFromPEM(clientsCaBytes); !ok {
		log.Fatalf("[EAP-TLS] error getting VPN clients CA certificate")
	}

	block, _ := pem.Decode(clientsCaBytes)
	if block == nil {
		log.Fatal("[EAP-TLS] failed to parse clients CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("[EAP-TLS] failed to parse clients CA certificate: " + err.Error())
	}
	log.Infof("[EAP-TLS] will accept client certificates signed by CA %s", cert.Subject.String())
	validityDays := cert.NotAfter.Sub(time.Now()).Hours() / 24
	if validityDays < 30 {
		log.Warnf("[EAP-TLS] clients CA certificate expires in %f days", math.Round(validityDays))
	}

	return &tls.Config{
		MinVersion:                  tls.VersionTLS12,
		PreferServerCipherSuites:    true,
		CurvePreferences:            []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		Certificates:                []tls.Certificate{serverCert},
		ClientAuth:                  tls.RequireAnyClientCert,
		ClientCAs:                   clientCertCAs,
		DynamicRecordSizingDisabled: true,
		//RootCAs: ,
	}
}

func sendMSCHAPv2Challenge(userName string, eap *radius.EapPacket, npac *radius.Packet) {
	mschapV2Challenge := [16]byte{}
	_, err := rand.Read(mschapV2Challenge[:])
	if err != nil {
		log.Errorf("unable to generate random data for MS-CHAPv2 challenge: %s", err)
		npac.Code = radius.AccessReject
		return
	}

	sessionId, err := createSessionId()
	if err != nil {
		log.Errorf("[EAP-MSCHAPv2] unable to generate session ID: %s", err)
		npac.Code = radius.AccessReject
		return
	}
	session := &RadiusSession{Challenge: mschapV2Challenge}

	npac.Code = radius.AccessChallenge
	npac.SetAVP(radius.AVP{
		Type:  radius.State,
		Value: []byte(sessionId),
	})

	challengeP := MSCHAPV2.ChallengePacket{
		Identifier: eap.Identifier,
		Challenge:  mschapV2Challenge,
		Name:       userName,
	}

	challengeEAPPacket := radius.EapPacket{
		Identifier: eap.Identifier,
		Code:       radius.EapCodeRequest,
		Type:       radius.EapTypeMSCHAPV2,
		Data:       challengeP.Encode(),
	}

	npac.AddAVP(radius.AVP{
		Type:  radius.AttributeType(radius.EAPMessage),
		Value: challengeEAPPacket.Encode(),
	})

	sessions.Set(sessionId, session)
}

func sendTLSRequest(userName string, eap *radius.EapPacket, npac *radius.Packet, request *radius.Packet) {
	npac.Code = radius.AccessChallenge

	// Session is not supposed to exist at this point
	sessionId, err := createSessionId()
	if err != nil {
		log.Errorf("[EAP-TLS] unable to generate session ID: %s", err)
		npac.Code = radius.AccessReject
		return
	}
	session := &RadiusSession{}

	npac.SetAVP(radius.AVP{
		Type:  radius.State,
		Value: []byte(sessionId),
	})

	eapTlsInitResponse := radius.EapPacket{
		Identifier: eap.Identifier + 1,
		Code:       radius.EapCodeRequest,
		Type:       EapTypeTLS,
		Data:       []byte{byte(TlsStartFlag)},
	}
	npac.AddAVP(radius.AVP{
		Type:  radius.AttributeType(radius.EAPMessage),
		Value: eapTlsInitResponse.Encode(),
	})
	session.EapTlsState = EapTlsState{
		Step: TlsStart,
	}
	sessions.Set(sessionId, session)
	return
}

func tlsClientAuth(ch chan<- bool, conn net.Conn, tlsConfig *tls.Config, userName string) {
	defer conn.Close()
	conn.Write([]byte{}) // Without a write, conn hangs and we're unable to get the state and client cert.
	tlscon, ok := conn.(*tls.Conn)
	if ok {
		state := tlscon.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			log.Error("[TLS] client did not send any certificate")
			ch <- false
			return
		}
		clientCert := state.PeerCertificates[0]
		log.Infof("[TLS] received client certificate %s valid until %s", clientCert.Subject, clientCert.NotAfter.String())
		if clientCert.NotAfter.Before(time.Now()) {
			log.Errorf("[TLS] client certificate %s is expired", clientCert.Subject)
			ch <- false
			return
		}
		log.Debugf("[TLS] client cert alt names: dns=%v, email=%v, ips=%v, extranames=%v", clientCert.DNSNames, clientCert.EmailAddresses, clientCert.IPAddresses, clientCert.Subject.ExtraNames)

		opts := x509.VerifyOptions{
			Roots:     tlsConfig.ClientCAs,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			//Intermediates: x509.NewCertPool(),
		}
		_, err := clientCert.Verify(opts)

		if err != nil {
			log.Errorf("[TLS] unable to verify client certificate %s: %s", clientCert.Subject, err)
			ch <- false
			return
		}

		// [rfc5216] 5.2. Peer identity
		// We closely follow Strongswan here: the claimed identity (EAP identity) must be present in the client certificate
		// An exception is that we also allow the identity to only match the CN field of the subject
		var certIdentities []string
		certIdentities = append(certIdentities, clientCert.Subject.String())
		certIdentities = append(certIdentities, clientCert.Subject.CommonName)
		certIdentities = append(certIdentities, clientCert.DNSNames...)
		certIdentities = append(certIdentities, clientCert.EmailAddresses...)
		for _, ip := range clientCert.IPAddresses {
			certIdentities = append(certIdentities, ip.String())
		}
		identityFound := false
		for _, identity := range certIdentities {
			if identity == userName {
				identityFound = true
				break
			}
		}
		if !identityFound {
			log.Errorf("[TLS] client EAP identity %s is not present in any of the client certificate fields (%s)", userName, certIdentities)
			ch <- false
			return
		}

		// Successful client authentication
		ch <- true
	}
}

func createSessionId() (string, error) {
	sessionId := make([]byte, 32)
	_, err := rand.Read(sessionId[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sessionId), nil
}

func getSession(id string) (*RadiusSession, error) {
	rawSession, err := sessions.Get(id)
	if err != nil {
		return nil, err
	}
	session := rawSession.(*RadiusSession)
	return session, nil
}

func checkRadiusSession(request *radius.Packet) (string, *RadiusSession, error) {
	stateAVP := request.GetAVP(radius.State)
	if stateAVP != nil {
		sessionId := string(stateAVP.Value)
		log.Debugf("[RADIUS] received State/Session ID %v", sessionId)
		session, err := getSession(sessionId)
		return sessionId, session, err
	} else {
		return "", nil, fmt.Errorf("No State/Session ID")
	}
}

// Prepares an AccessReject packet, and delete the current session if exists.
func radiusError(message string, sessionId string, npac *radius.Packet) *radius.Packet {
	log.Errorf(message)
	npac.Code = radius.AccessReject
	if sessionId != "" {
		npac.SetAVP(radius.AVP{
			Type:  radius.State,
			Value: []byte(sessionId),
		})
		session, _ := getSession(sessionId)
		if session != nil {
			if session.EapTlsState.TlsServerConn != nil {
				session.EapTlsState.TlsServerConn.Close()
			}
			sessions.Remove(sessionId)
		}
	}
	return npac
}
