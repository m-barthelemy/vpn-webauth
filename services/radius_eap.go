package services

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/ReneKroon/ttlcache/v2"
	"github.com/bronze1man/radius"
	"github.com/dreadl0ck/tlsx"
	"github.com/m-barthelemy/vpn-webauth/MSCHAPV2"
	"github.com/m-barthelemy/vpn-webauth/models"
)

// [rfc3579] 4.3.3.  Dictionary Attacks: secret should be at least 16 characters
const minRadiusSecretLength = 16

// This is the maximum time a client has to complete the full authentication
const sessionTimeout = 64 * time.Second

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
	Step          EapTlsStep
	TlsServerConn net.Conn
	TlsBuffer     []byte
	BufferPos     int
}

// Communication between EAP and the TLS handshake proxy
type TLSAuthInfo struct {
	Authorized bool
	Identity   string
}

type EapTlsStep uint

const (
	TlsStart             EapTlsStep = 0
	TlsServerHello       EapTlsStep = 1
	TlsClientKeyExchange EapTlsStep = 2
	TlsAuthentication    EapTlsStep = 3
)

var sessions ttlcache.Cache

type RadiusService struct {
	handshakeSocketPath string
	config              *models.Config
}

func NewRadiusServer(config *models.Config) *RadiusService {
	// For security reasons we require the Radius secret to have a min length (which is still weak)
	if len(config.RadiusSecret) < minRadiusSecretLength {
		log.Fatalf("[RADIUS] secret must be at least %d characters", minRadiusSecretLength)
	}
	sessions = *ttlcache.NewCache()
	sessions.SetTTL(sessionTimeout)
	sessions.SkipTTLExtensionOnHit(true)

	return &RadiusService{
		config: config,
	}
}

func (r *RadiusService) Start() {
	// TLS "proxy" used for EAP-TLS handshake
	tmpfile, err := ioutil.TempFile("", "eap-tls-handshake")
	if err != nil {
		log.Fatalf("[EAP-TLS] failed to create temporary file for handshake server: %v", err)
	}
	r.handshakeSocketPath = tmpfile.Name()
	os.Remove(r.handshakeSocketPath)

	// Start the "TLS handshake proxy" in charge of EAP-TLS connections
	log.Println("starting TLS handshake service...")
	tlsConfig := getTLSServerConfig()
	handshakeServer, err := tls.Listen("unix", r.handshakeSocketPath, tlsConfig)
	if err != nil {
		log.Fatalf("[TLS] failed to bind unix socket %q for TLS handshake server: %v", r.handshakeSocketPath, err)
	}

	// Start a background thread reading the conn
	// NOTE: currently the client certificate validation only checks the following:
	// - signed by an allowed CA
	// - not expired
	go func() {
		for {
			conn, err := handshakeServer.Accept()
			if err != nil {
				log.Printf("[EAP-TLS] unable to accept handshake server client connection: %s", err)
				return
			}
			go handleTlsConnection(conn, tlsConfig)
		}
	}()

	radiusAddr := fmt.Sprintf("0.0.0.0:%d", r.config.RadiusPort)
	s := radius.NewServer(radiusAddr, r.config.RadiusSecret, r)

	go func() {
		log.Printf("[RADIUS] Starting listener (%s)...", radiusAddr)
		err := s.ListenAndServe()
		if err != nil {
			log.Fatalf("[RADIUS] 💥 Unable to start listener: %s", err)
		}
	}()
}

func handleTlsConnection(conn net.Conn, tlsConfig *tls.Config) {
	defer conn.Close()
	conn.Write([]byte{}) // without a write, conn hangs and we're unable to get the state and client cert.
	tlscon, ok := conn.(*tls.Conn)
	if ok {
		state := tlscon.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			log.Println("[TLS] 💥 client did not send any certificate")
			conn.Close()
			return
		}
		clientCert := state.PeerCertificates[0]
		log.Printf("[TLS] received client certificate %s valid until %s", clientCert.Subject, clientCert.NotAfter.String())
		if clientCert.NotAfter.Before(time.Now()) {
			log.Printf("[TLS] 💥 client certificate %s is expired", clientCert.Subject)
			conn.Close()
			return
		}
		log.Printf(">>>>>>>>>> client cert alt names: dns=%s, email=%s, ips=%s, extranames=%s", clientCert.DNSNames, clientCert.EmailAddresses, clientCert.IPAddresses, clientCert.Subject.ExtraNames)
		// TODO: here we need to get the client identity received by Radius and check if it's present in any of the cert subject fields
		// While not required strictly speaking, this is what Strongswan does, as it ensures the user is who they pretent to be.
		// This becomes necessary if the VPN has different connections per user (different allowed subnets...)

		opts := x509.VerifyOptions{
			Roots:     tlsConfig.ClientCAs,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			//DNSName:       serverName,
			//Intermediates: x509.NewCertPool(),
		}
		_, err := clientCert.Verify(opts)
		// TODO: https://datatracker.ietf.org/doc/html/rfc5216#section-5.2 (peer identity)
		if err != nil {
			log.Printf("[TLS] 💥 unable to verify client certificate %s: %s", clientCert.Subject, err)
			conn.Close()
			return
		}

		// Successful client authentication
		dummyData := make([]byte, dummyTlsOkDataSize)
		conn.Write(dummyData)
	}
}

// Check https://github.com/keysonZZZ/kmg/blob/master/third/kmgRadius/Auth.go
// for EAP and MSCHAP challenge response
func (r *RadiusService) RadiusHandle(request *radius.Packet) *radius.Packet {
	fmt.Println("---------------------------------------------------------")
	// TODO: this crashes when receiving the final EAP response after sending change_cipher_spec
	/*
		EapDecode fail  [EapDecode] protocol error input too small 2
		panic: runtime error: slice bounds out of range [5:3]

		goroutine 119 [running]:
		github.com/bronze1man/radius.EapDecode(0xc0004f4c00, 0xfd, 0x100, 0x0, 0xc0002ed628, 0x405596f)
			/Users/matthieubarthelemy/go/pkg/mod/github.com/bronze1man/radius@v0.0.0-20190516032554-afd8baec892d/eap.go:132 +0x189
		github.com/bronze1man/radius.avpEapMessaget.Value(0xc00025efa0, 0xc00042af4f, 0xc0004f4c00, 0xfd, 0x100, 0x4054e5e, 0xc00042b0dc)
			/Users/matthieubarthelemy/go/pkg/mod/github.com/bronze1man/radius@v0.0.0-20190516032554-afd8baec892d/avp.go:174 +0x4c
		github.com/bronze1man/radius.avpEapMessaget.String(0xc00025efa0, 0xc00042af4f, 0xc0004f4c00, 0xfd, 0x100, 0x1dd, 0x1)
			/Users/matthieubarthelemy/go/pkg/mod/github.com/bronze1man/radius@v0.0.0-20190516032554-afd8baec892d/avp.go:184 +0x56
		github.com/bronze1man/radius.AVP.StringWithPacket(0x4f, 0xc0004f4c00, 0xfd, 0x100, 0xc00025efa0, 0x4ae3ee8, 0x1)
			/Users/matthieubarthelemy/go/pkg/mod/github.com/bronze1man/radius@v0.0.0-20190516032554-afd8baec892d/avp.go:47 +0xa2
		github.com/bronze1man/radius.(*Packet).String(0xc00025efa0, 0xc000134008, 0xc0008e8b48)
			/Users/matthieubarthelemy/go/pkg/mod/github.com/bronze1man/radius@v0.0.0-20190516032554-afd8baec892d/packet.go:264 +0x29f
		main.(*RadiusService).RadiusHandle(0xc000518440, 0xc00025efa0, 0x13)
			/Users/matthieubarthelemy/Projects/vpn-webauth/main.go:226 +0xa7
		github.com/bronze1man/radius.(*Server).ListenAndServe.func1(0xc00025e5f0, 0xc000010ba8, 0xc0004cd000, 0x4d1, 0x1000, 0x4b9e490, 0xc00051b920)
			/Users/matthieubarthelemy/go/pkg/mod/github.com/bronze1man/radius@v0.0.0-20190516032554-afd8baec892d/server.go:108 +0x1d7
		created by github.com/bronze1man/radius.(*Server).ListenAndServe
			/Users/matthieubarthelemy/go/pkg/mod/github.com/bronze1man/radius@v0.0.0-20190516032554-afd8baec892d/server.go:86 +0x2e8
	*/
	//log.Printf("[RADIUS] received packet: \n%s\n", request.String())
	if request.HasAVP(radius.FramedMTU) {
		log.Printf("[RADIUS] !!!!! FRAMED MTU SHIT CAREFUL DO NOT SEND SHIT BIGGER THAN THE VALUE IN THIS ATTRIBUTE BUTE BUTE")
	}

	npac := request.Reply()

	userName := request.GetUsername()
	if userName == "" {
		npac.AddAVP(radius.AVP{Type: radius.ReplyMessage, Value: []byte("only EAP is supported")})
		npac.Code = radius.AccessReject
		log.Printf("[Radius] Username is required but got empty/null value")
		return npac
	}

	switch request.Code {
	case radius.AccessRequest:
		if !request.HasAVP(radius.EAPMessage) {
			log.Printf("[RADIUS] request doesn't contain any EAP message")
			npac.Code = radius.AccessReject
			npac.AddAVP(radius.AVP{Type: radius.ReplyMessage, Value: []byte("only EAP is supported")})
			return npac
		}

		var eap *radius.EapPacket
		// `request.GetEAPMessage()` crashes
		// - if there's no valid EAP message
		// - if the EAP message is fragmented (length > current AVP length)
		// so we need to guard against that
		checkEapAvp := request.GetAVP(radius.EAPMessage)
		if len(checkEapAvp.Value) < 5 {
			log.Printf("[RADIUS] request contains an invalid EAP message (length < 5)")
			npac.Code = radius.AccessReject
			return npac
		} else if len(checkEapAvp.Value) == 253 {
			// We may have a big EAP packet split into multiple AVPs
			totalEapMsgSize := binary.BigEndian.Uint16(checkEapAvp.Value[2:4])
			log.Printf("[EAP] DEBUG: received EAP message (%d total length) split into multiple Radius AVPs", totalEapMsgSize)
			binary.BigEndian.PutUint16(checkEapAvp.Value[2:4], uint16(253))
			var err error
			// The first AVP contains the EAP packet header
			eap, err = radius.EapDecode(checkEapAvp.Value)
			if err != nil {
				log.Printf("[EAP] unable to parse first EAP fragment: %s", err)
				npac.Code = radius.AccessReject
				return npac
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
			log.Printf("[EAP-TLS] DEBUG: packet flags = %08b, reported size %d bytes, found %d bytes of data", eap.Data[0], totalEapMsgSize, len(eap.Data))

		} else {
			eap = request.GetEAPMessage()
		}

		if eap == nil {
			log.Printf("[EAP] Received non-EAP request from %s (%s). Only EAP is supported.", request.ClientAddr, request.GetNASIdentifier())
			npac.Code = radius.AccessReject
			npac.AddAVP(radius.AVP{Type: radius.ReplyMessage, Value: []byte("only EAP is supported")})
			return npac
		}

		log.Printf("[EAP] Received message kind is EAP, type %s, code %s, identifier %d, data size %d", eap.Type.String(), eap.Code.String(), eap.Identifier, len(eap.Data))

		// [rfc3579] 3.1. Message-Authenticator is Required for EAP.
		// Access-Request packets including EAP-Message attribute(s) without a Message-Authenticator attribute SHOULD be silently discarded
		messageAuthenticator := request.GetAVP(radius.MessageAuthenticator)
		if messageAuthenticator.Value == nil {
			log.Printf("[Radius] Received EAP packet without %s attribute, discarding", radius.MessageAuthenticator.String())
			return npac
		}
		// Else, if we have a Message-Authenticator, it is automatically validated before service.RadiusHandle is called.

		// [rfc3579] 2.6.2. Role Reversal
		if eap.Code == radius.EapCodeRequest {
			log.Printf("[EAP] Received unsupported packet type '%s', rejecting", eap.Code.String())
			npac.Code = radius.AccessReject
			rejectResponseEAPPacket := radius.EapPacket{
				Identifier: eap.Identifier,
				Code:       radius.EapCodeResponse,
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
			if r.config.EAPMode == "mschapv2" {
				sendMSCHAPv2Challenge(userName, eap, npac)
			} else if r.config.EAPMode == "tls" {
				sendTLSRequest(userName, eap, npac, request)
			}

			log.Printf("[EAP] Sending MSCHAPv2 or TLS-Start request as a response to EAP identity request")
			return npac

		case radius.EapTypeMSCHAPV2:
			msChapV2Packet, err := MSCHAPV2.Decode(eap.Data)
			if err != nil {
				log.Printf("[MsCHAPv2] 💥 unable to decode received packet: %s", err)
				npac.Code = radius.AccessReject
				return npac
			}
			log.Printf("[MsCHAPv2] Received request with OpCode %s", msChapV2Packet.OpCode().String())

			sessionId, session, err := checkRadiusSession(request)
			if err != nil {
				log.Printf("Invalid State/Session ID %s", sessionId)
				npac.Code = radius.AccessReject
				return npac
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

				log.Printf("[Radius] Sending Access-Challenge again in response to %s", MSCHAPV2.OpCodeResponse.String())
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
					log.Printf("[MsCHAPv2] Unable to generate ???? for sendkey")
					npac.Code = radius.AccessReject
					return npac
				}
				recvKeyMsmpp, err := MSCHAPV2.NewMSMPPESendOrRecvKeyVSA(request, MSCHAPV2.VendorTypeMSMPPERecvKey, recvKey).Encode()
				if err != nil {
					log.Printf("[MsCHAPv2] Unable to generate ???? for recvKey")
					npac.Code = radius.AccessReject
					return npac
				}
				npac.AddAVP(radius.AVP{
					Type:  radius.AttributeType(radius.VendorSpecific),
					Value: sendKeyMsmpp,
				})
				npac.AddAVP(radius.AVP{
					Type:  radius.AttributeType(radius.VendorSpecific),
					Value: recvKeyMsmpp,
				})

				successPacket := radius.EapPacket{
					Identifier: eap.Identifier,
					Code:       radius.EapCodeSuccess,
				}
				npac.AddAVP(radius.AVP{
					Type:  radius.AttributeType(radius.EAPMessage),
					Value: successPacket.Encode(),
				})
				log.Printf("[Radius] Sending Access-Accept response to NAS '%s' for user '%s'", request.GetNASIdentifier(), request.GetUsername())
				npac.Code = radius.AccessAccept
				sessions.Remove(sessionId)
				return npac

			default:
				log.Printf("[MsCHAPv2] 💥 Invalid request OpCode %s", msChapV2Packet.OpCode().String())
				npac.Code = radius.AccessReject
				sessions.Remove(sessionId)
				return npac
			}

		case 13: // EAP-TLS
			sessionId, session, err := checkRadiusSession(request)
			if err != nil {
				log.Printf("[RADIUS] 💥 error checking client session: %s", err)
				npac.Code = radius.AccessReject
				return npac
			}
			eapState := session.EapTlsState

			isAck := false
			var tlsPacket []byte
			if len(eap.Data) == 1 && eap.Data[0] == 0 {
				isAck = true
				log.Printf("[EAP-TLS] received ACK")
			} else if len(eap.Data) < 5 {
				log.Printf("[EAP-TLS] 💥 received invalid record: too small (%d bytes), value %b", len(eap.Data), eap.Data)
				//npac.Code = radius.AccessReject
				// TODO: document why this reply
				npac.Code = radius.AccessChallenge
				npac.SetAVP(radius.AVP{
					Type:  radius.State,
					Value: []byte(sessionId),
				})
				eapTlsInitResponse := radius.EapPacket{
					Identifier: eap.Identifier + 1,
					Code:       radius.EapCodeSuccess,
					Type:       13,
					Data:       []byte(userName),
				}
				npac.AddAVP(radius.AVP{
					Type:  radius.AttributeType(radius.EAPMessage),
					Value: eapTlsInitResponse.Encode(),
				})
				return npac
			} else {
				tlsPacket = eap.Data[5:]
			}

			if eapState.Step == TlsStart && !isAck {
				conn, err := net.Dial("unix", r.handshakeSocketPath)
				if err != nil {
					log.Printf("[EAP-TLS] 💥 unable to connect to TLS handshake server: %s", err)
					npac.Code = radius.AccessReject
					return npac
				}

				written, err := conn.Write(tlsPacket)
				if err != nil {
					log.Printf("[EAP-TLS] 💥 unable to send ClientHello: %s", err)
					npac.Code = radius.AccessReject
					return npac
				}
				if written != len(tlsPacket) {
					log.Printf("[EAP-TLS] 💥 unable to write ClientHello to TLS server: only %d/%d written", written, len(tlsPacket))
					npac.Code = radius.AccessReject
					return npac
				}
				log.Printf("[EAP-TLS] step %v: received ClientHello, %d bytes", eapState.Step, written)

				reply := make([]byte, maxTlsRecordSize)
				read, err := conn.Read(reply)
				if err != nil {
					log.Printf("[EAP-TLS] 💥 unable to read ServerHello: %s", err)
					npac.Code = radius.AccessReject
					return npac
				}
				if read == len(reply) {
					log.Printf("[EAP-TLS] 💥 TLS ServerHello was %d bytes or greater. This is not supported. This probably indicates that your certificate chain is too long", read)
					npac.Code = radius.AccessReject
					return npac
				}
				log.Printf("[EAP-TLS] DEBUG: ServerHello is %d bytes", read)

				// The ServerHello is assumed to be too big to be sent in a single Radius packet due to the MTU size limit.
				// We'll split it into chunks of 1024 bytes.
				eapState.TlsBuffer = reply[:read]
				eapState.BufferPos = 0
				eapState.TlsServerConn = conn
				serverHello := tlsx.ServerHello{}
				err = serverHello.Unmarshal(eapState.TlsBuffer)
				if err != nil {
					log.Printf("[EAP-TLS] 💥 bogus ServerHello: %s", err)
				}
				cipher := serverHello.CipherSuite
				tlsVersion := tlsx.Version(serverHello.Vers).String()
				log.Printf("[EAP-TLS] ServerHello: selected %s, Cipher suite %s", tlsVersion, tlsx.CipherSuite(cipher).String())
			}

			if eapState.BufferPos == 0 || isAck {
				log.Printf("[EAP-TLS] DEBUG: current position in cached buffer of data waiting to be sent to client: %d/%d", eapState.BufferPos, len(eapState.TlsBuffer))
				npac.Code = radius.AccessChallenge
				npac.SetAVP(radius.AVP{
					Type:  radius.State,
					Value: []byte(sessionId),
				})

				maxAttrSize := 248 // max size of a Radius attribute data
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
						log.Printf("[EAP-TLS] Setting TLS record size of %d on first Radius EAP AVP", len(eapState.TlsBuffer))
						data = make([]byte, maxAttrSize+5)
						flagStr := bitString("11000000")
						flagByte := flagStr.AsByteSlice()
						data[0] = flagByte[0]
						binary.BigEndian.PutUint32(data[1:5], uint32(len(eapState.TlsBuffer)))
						copy(data[5:], eapState.TlsBuffer[pos:(pos+maxAttrSize)])

						radiusServHelloPacket := radius.EapPacket{
							Identifier: eapId,
							Code:       radius.EapCodeRequest,
							Type:       13,
							Data:       data,
						}
						eapResponseData = radiusServHelloPacket.Encode()
						binary.BigEndian.PutUint16(eapResponseData[2:4], uint16(thisEapPacketSize+eapHeaderSize+5))
					} else if packetRead == 0 {
						data = make([]byte, maxAttrSize+1)
						var flagStr bitString
						if addFragmentBit {
							flagStr = bitString("01000000")
						} else {
							flagStr = bitString("00000000")
						}
						flagByte := flagStr.AsByteSlice()
						data[0] = flagByte[0]
						binary.BigEndian.PutUint32(data[1:5], uint32(thisEapPacketSize))
						copy(data[1:], eapState.TlsBuffer[pos:(pos+maxAttrSize)])

						radiusServHelloPacket := radius.EapPacket{
							Identifier: eapId,
							Code:       radius.EapCodeRequest,
							Type:       13,
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
					//log.Printf("Pos=%d, Until=%d, maxAttrSize=%d, packetRead=%d, eapId=%d", pos, (pos + maxAttrSize), maxAttrSize, packetRead, eapId)
					pos = pos + maxAttrSize
					packetRead = packetRead + maxAttrSize
				}
				eapState.BufferPos += thisEapPacketSize
				if eapState.BufferPos == len(eapState.TlsBuffer) {
					eapState.Step = TlsServerHello
					log.Printf("[EAP-TLS] finished splitting ServerHello")
				}
				session.EapTlsState = eapState
				log.Printf("[EAP-TLS] step %v: sending ServerHello fragment, %d bytes", eapState.Step, thisEapPacketSize)
				return npac
			}

			tlsDataPos := 0

			// After sending the TLS ServerHello.
			// We should now have received either an error, or the client response including the client cert.
			if eapState.Step == TlsServerHello || eapState.Step == TlsClientKeyExchange {
				lengthIncluded := (eap.Data[0] & (1 << 7)) != 0
				hasMoreFragments := (eap.Data[0] & (1 << 6)) != 0

				if lengthIncluded && eapState.Step == TlsClientKeyExchange {
					log.Printf("[EAP-TLS] 💥 client wants to send a new TLS record while we are already waiting for one")
					npac.Code = radius.AccessReject
					return npac
				}
				if lengthIncluded {
					tlsDataPos += 4
					tlsRecordSize := binary.BigEndian.Uint32(eap.Data[1:5])
					log.Printf("[EAP-TLS] DEBUG: client wants to send a client_key_exchange TLS record of %d bytes", tlsRecordSize)
					if tlsRecordSize > maxTlsRecordSize {
						log.Printf("[EAP-TLS] 💥 client wants to send a TLS record of %d bytes, too big, rejecting", tlsRecordSize)
						npac.Code = radius.AccessReject
						return npac
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

				hasMoreFragments := (eap.Data[0] & (1 << 6)) != 0
				if hasMoreFragments {
					if eapState.BufferPos >= len(eapState.TlsBuffer) {
						log.Print("[EAP-TLS] 💥 client wants to send more TLS data than announced, rejecting")
						npac.Code = radius.AccessReject
						return npac
					}
					npac.SetAVP(radius.AVP{
						Type:  radius.State,
						Value: []byte(sessionId),
					})

					ackPacket := radius.EapPacket{
						Identifier: eap.Identifier + 1,
						Code:       radius.EapCodeRequest,
						Type:       13,
						Data:       []byte{0},
					}
					npac.Code = radius.AccessChallenge
					npac.AddAVP(radius.AVP{
						Type:  radius.AttributeType(radius.EAPMessage),
						Value: ackPacket.Encode(),
					})
					log.Printf("[EAP-TLS] DEBUG: more EAP fragments expected from client, sending ACK")
					return npac
				} else {
					log.Printf("[EAP-TLS] DEBUG: no more EAP fragments expected from client, received client_key_exchange, %d/%d bytes", eapState.BufferPos, len(eapState.TlsBuffer))
				}

				tlsPacket = eapState.TlsBuffer
				written, err := eapState.TlsServerConn.Write(tlsPacket)
				if err != nil {
					log.Printf("[EAP-TLS] 💥 unable to send client_key_exchange: %s", err)
					npac.Code = radius.AccessReject
					return npac
				}
				if written != len(tlsPacket) {
					log.Printf("[EAP-TLS] 💥 error sending client_key_exchange to TLS server: data size %d, but only wrote %d", len(tlsPacket), written)
					npac.Code = radius.AccessReject
					return npac
				}
				reply := make([]byte, 4*1024)
				read, err := eapState.TlsServerConn.Read(reply)
				if err != nil {
					log.Printf("[EAP-TLS] 💥 unable to read TLS server response to client_key_exchange : %s", err)
					npac.Code = radius.AccessReject
					return npac
				}
				log.Printf("[EAP-TLS] received client_key_exchange was %d bytes, TLS server response was %d bytes", written, read)
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
						Type:       13,
						Data:       reply[pos:until],
					}
					npac.AddAVP(radius.AVP{
						Type:  radius.AttributeType(radius.EAPMessage),
						Value: radiusServHelloPacket.Encode(),
					})
				}
				log.Printf("[EAP-TLS] sending TLS finished, %d bytes", read)
				eapState.Step = TlsAuthentication
				session.EapTlsState = eapState
				sessions.SetWithTTL(sessionId, session, sessionTimeout)
			} else if eapState.Step == TlsAuthentication {
				tlsAuthResponse := make([]byte, 2048)
				read, err := eapState.TlsServerConn.Read(tlsAuthResponse)
				// When the TLS authentication is successful, it will reply with 1024 bytes of dummy data
				// IF we receive less than that, then the TLS authentication failed.
				acceptRejectPacket := radius.EapPacket{
					Identifier: eap.Identifier + 1,
					Type:       13,
					Data:       []byte{0},
				}
				if err != nil || read < dummyTlsOkDataSize {
					log.Printf("[EAP-TLS] 💥 TLS server rejected client")
					npac.Code = radius.AccessReject
					acceptRejectPacket.Code = radius.EapCodeFailure
				} else {
					npac.Code = radius.AccessAccept
					acceptRejectPacket.Code = radius.EapCodeSuccess
					log.Printf("[EAP-TLS] client accepted")
				}
				npac.AddAVP(radius.AVP{
					Type:  radius.AttributeType(radius.EAPMessage),
					Value: acceptRejectPacket.Encode(),
				})
				eapState.TlsServerConn.Close()
				sessions.Remove(sessionId)
			}

			return npac

		default:
			log.Printf("[Radius] Received unsupported EAP packet type %s", eap.Type.String())
			npac.Code = radius.AccessReject
			return npac
		}

	case radius.AccessChallenge:
		fmt.Printf("********>>>>>>> Received AccessChallenge")
	case radius.AccountingRequest:
		// accounting start or end
		fmt.Printf("********>>>>>>> Received AccountingResponse")
		npac.Code = radius.AccountingResponse
	default:
		log.Printf("[RADIUS] received unsupported message type '%s'", request.Code.String())
		npac.Code = radius.AccessReject
		npac.AddAVP(radius.AVP{
			Type:  radius.ReplyMessage,
			Value: []byte(fmt.Sprintf("Unsupported message type '%s'", request.Code.String())),
		})
	}
	return npac
}

func (r *RadiusService) getTLSServerConfig() *tls.Config {
	serverCert, err := tls.LoadX509KeyPair(r.config.EAPTLSCertificatePath, r.config.EAPTLSKeyPath)
	if err != nil {
		log.Fatalf("[EAP-TLS] error getting VPN server certificate or key: %s", err)
	}

	var clientCertCAs *x509.CertPool
	clientCertCAs = x509.NewCertPool()
	clientsCaBytes, err := ioutil.ReadFile("/tmp/clientca.crt")
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
	log.Printf("[EAP-TLS] will accept client certificates signed by CA %s", cert.Subject.String())
	validityDays := cert.NotAfter.Sub(time.Now()).Hours() / 24
	if validityDays < 30 {
		log.Printf("WARNING: CA certificate expires in %f days", math.Round(validityDays))
	}
	return &tls.Config{
		MinVersion:                  tls.VersionTLS12,
		MaxVersion:                  tls.VersionTLS12,
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
		log.Printf("unable to generate random data for MS-CHAPv2 challenge: %s", err)
		npac.Code = radius.AccessReject
		return
	}

	sessionId, err := createSessionId()
	if err != nil {
		log.Printf("[EAP-TLS] 💥 unable to generate session ID: %s", err)
		npac.Code = radius.AccessReject
		return
	}

	session := &RadiusSession{
		Challenge: mschapV2Challenge,
	}

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
	return
}

func sendTLSRequest(userName string, eap *radius.EapPacket, npac *radius.Packet, request *radius.Packet) {
	npac.Code = radius.AccessChallenge

	// Session not supposed to exist at this point
	sessionId, err := createSessionId()
	if err != nil {
		log.Printf("[EAP-TLS] 💥 unable to generate session ID: %s", err)
		npac.Code = radius.AccessReject
		return
	}
	session := &RadiusSession{}

	npac.SetAVP(radius.AVP{
		Type:  radius.State,
		Value: []byte(sessionId),
	})

	b := make([]byte, 1)
	flagStr := bitString("00100000")
	flagByte := flagStr.AsByteSlice()
	b[0] = flagByte[0]
	eapTlsInitResponse := radius.EapPacket{
		Identifier: eap.Identifier + 1,
		Code:       radius.EapCodeRequest,
		Type:       13,
		Data:       b,
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

type bitString string

func (b bitString) AsByteSlice() []byte {
	var out []byte
	var str string

	for i := len(b); i > 0; i -= 8 {
		if i-8 < 0 {
			str = string(b[0:i])
		} else {
			str = string(b[i-8 : i])
		}
		v, err := strconv.ParseUint(str, 2, 8)
		if err != nil {
			panic(err)
		}
		out = append([]byte{byte(v)}, out...)
	}
	return out
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
		log.Printf("[RADIUS] DEBUG: received State/Session ID %v", sessionId)
		session, err := getSession(sessionId)
		return sessionId, session, err
	} else {
		return "", nil, fmt.Errorf("No State/Session ID")
	}
}