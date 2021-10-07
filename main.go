//go:generate pkger
package main

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
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ReneKroon/ttlcache/v2"
	"github.com/bronze1man/radius"
	"github.com/dreadl0ck/tlsx"
	"github.com/m-barthelemy/vpn-webauth/MSCHAPV2"

	//"github.com/bronze1man/radius/MSCHAPV2"

	"github.com/kelseyhightower/envconfig"
	"github.com/m-barthelemy/vpn-webauth/models"
	"github.com/m-barthelemy/vpn-webauth/routes"
	services "github.com/m-barthelemy/vpn-webauth/services"

	//"github.com/m-barthelemy/vpn-webauth/services/radius"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	var config models.Config
	config = config.New()

	err := envconfig.Process("", &config)
	if err != nil {
		log.Fatal(err.Error())
	}
	config.Verify()

	var db *gorm.DB
	var dbErr error

	switch strings.ToLower(config.DbType) {
	case "sqlite":
		db, dbErr = gorm.Open(sqlite.Open(config.DbDSN), &gorm.Config{})
	case "postgres":
		db, dbErr = gorm.Open(postgres.Open(config.DbDSN), &gorm.Config{})
	case "mysql":
		db, dbErr = gorm.Open(mysql.Open(config.DbDSN), &gorm.Config{})
	default:
		log.Fatalf("Unknown DbType '%s'", config.DbType)
	}
	if dbErr != nil {
		log.Fatalf("Failed to connect to database: %s", dbErr)
	}

	// Migrate the schema
	if err := db.AutoMigrate(&models.User{}); err != nil {
		log.Fatalf("Failed to run database migrations for User model: %s", err)
	}
	if err := db.AutoMigrate(&models.VpnSession{}); err != nil {
		log.Fatalf("Failed to run database migrations for VpnSession model: %s", err)
	}
	if err := db.AutoMigrate(&models.UserMFA{}); err != nil {
		log.Fatalf("Failed to run database migrations for UserMFA model: %s", err)
	}
	if err := db.AutoMigrate(&models.VPNConnection{}); err != nil {
		log.Fatalf("Failed to run database migrations for VPNConnection model: %s", err)
	}
	if err := db.AutoMigrate(&models.UserSubscription{}); err != nil {
		log.Fatalf("Failed to run database migrations for UserSubscription model: %s", err)
	}

	// Delete old VPN connections log entries
	userManager := services.NewUserManager(db, &config)
	if err := userManager.CleanupConnectionsLog(); err != nil {
		log.Printf("Could not delete old VPN connections log entries: %s", err.Error())
	}

	/*go func() {
		rad := radius.New(config.RadiusPort, config.RadiusSecret)
		rad.Start()
	}()*/

	// TLS "proxy" used for EAP-TLS handshake
	tmpfile, err := ioutil.TempFile("", "eap-tls-handshake")
	if err != nil {
		log.Fatalf("[EAP-TLS] failed to create temporary file for handshake server: %v", err)
	}
	socketPath := tmpfile.Name()
	os.Remove(socketPath)

	// Start a TLS listener
	log.Println("starting TLS handshake service...")
	handshakeServer, err := tls.Listen("unix", socketPath, getTLSServerConfig())
	if err != nil {
		log.Fatalf("[EAP-TLS] failed to bind unix socket %q for TLS handshake server: %v", socketPath, err)
	}

	// Start a background thread reading the conn
	go func() {
		for {
			conn, err := handshakeServer.Accept()
			if err != nil {
				log.Printf("[EAP-TLS] unable to accept handshake server client connection: %s", err)
				return
			}
			conn.Write([]byte("@"))
			//log.Printf("[EAP-TLS] TLS established")
			err = conn.Close()
			if err != nil {
				log.Printf("[EAP-TLS] unable to close handshake server client conn after successful TLS handshake: %s", err)
			}
		}
	}()

	s := radius.NewServer("0.0.0.0:5022", radiusSecret, &RadiusService{handshakeSocketPath: socketPath})
	cache.SetTTL(time.Duration(60 * time.Second))
	go func() {
		log.Println("Starting Radius listener...")
		err := s.ListenAndServe()
		if err != nil {
			log.Fatalf("Unable to start Radius listener: %s", err)
		}
	}()

	startServer(&config, routes.New(&config, db))
}

//test
type RadiusService struct {
	handshakeSocketPath string
}

const radiusSecret = "mamiemamiemamiem"

// [rfc3579] 4.3.3.  Dictionary Attacks: secret should be at least 16 characters
// TODO: require at least 24 chars
const userPassword = "mamie est conne"

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

type EapTlsStep uint

const (
	TlsStart       EapTlsStep = 0
	TlsServerHello EapTlsStep = 1
)

// TODO: protect/lock for concurrent access
var sessions = make(map[[32]byte]*RadiusSession)
var cache ttlcache.SimpleCache = ttlcache.NewCache()
var lock = sync.RWMutex{}

// Check https://github.com/keysonZZZ/kmg/blob/master/third/kmgRadius/Auth.go
// for EAP and MSCHAP challenge response
func (p *RadiusService) RadiusHandle(request *radius.Packet) *radius.Packet {
	fmt.Println("---------------------------------------------------------")
	log.Printf("[RADIUS] received packet: \n%s\n", request.String())
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
		// `request.GetEAPMessage()` crashes if there's no valid EAP message so we need to guard against that
		checkEapAvp := request.GetAVP(radius.EAPMessage)
		if len(checkEapAvp.Value) < 5 {
			log.Printf("[RADIUS] request contains an invalid EAP message (length < 5)")
			npac.Code = radius.AccessReject
			return npac
		}
		eap := request.GetEAPMessage()
		if eap == nil {
			log.Printf("[EAP] Received non-EAP request from %s (%s). Only EAP is supported.", request.ClientAddr, request.GetNASIdentifier())
			npac.Code = radius.AccessReject
			npac.AddAVP(radius.AVP{Type: radius.ReplyMessage, Value: []byte("only EAP is supported")})
			return npac
		}

		log.Printf("[EAP] Received message kind is EAP, type %s, code %s, identifier %d, data size %d", eap.Type.String(), eap.Code.String(), eap.Identifier, len(eap.Data))
		//log.Printf("[EAP] Packet: %s", eap.String())

		// [rfc3579] 3.2. Message-Authenticator. Required for EAP.
		messageAuthenticator := request.GetAVP(radius.MessageAuthenticator)
		if messageAuthenticator.Value == nil {
			log.Printf("[Radius] Received EAP packet without %s attribute, discarding", radius.MessageAuthenticator.String())
			return npac
		}
		// else, if we have a Message-Authenticator, it is automatically validated before service.RadiusHandle is called.

		// [rfc3579] 2.6.2. Role Reversal
		if eap.Code == radius.EapCodeRequest {
			log.Printf("[EAP] Received unsupported packet type %s", eap.Code.String())
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
			//sendMSCHAPv2Challenge(userName, eap, npac)
			sendTLSRequest(userName, eap, npac, request)
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
			//log.Printf("[MsCHAPv2] >>>> Successfully decoded msChapV2Packet: %s", msChapV2Packet.String())

			stateAVP := request.GetAVP(radius.State)
			sessionId := [32]byte{}
			if stateAVP != nil {
				copy(sessionId[:], stateAVP.Value)
				log.Printf("[MsCHAPv2] Received State/Session ID %v", sessionId)
			}

			switch msChapV2Packet.OpCode() {
			case MSCHAPV2.OpCodeResponse:
				if _, ok := sessions[sessionId]; !ok {
					log.Printf("Invalid State/Session ID %s", sessionId)
					npac.Code = radius.AccessReject
					return npac
				}

				sessions[sessionId].NTResponse = msChapV2Packet.(*MSCHAPV2.ResponsePacket).NTResponse

				npac.SetAVP(radius.AVP{
					Type:  radius.State,
					Value: sessionId[:],
				})

				successPacket := MSCHAPV2.ReplySuccessPacket(&MSCHAPV2.ReplySuccessPacketRequest{
					AuthenticatorChallenge: sessions[sessionId].Challenge,
					Response:               msChapV2Packet.(*MSCHAPV2.ResponsePacket),
					Username:               []byte(request.GetUsername()),
					Password:               []byte(userPassword),
					//Message:                "success",
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
				if _, ok := sessions[sessionId]; !ok {
					log.Printf("Invalid State/Session ID %s", sessionId)
					npac.Code = radius.AccessReject
					return npac
				}

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

				sendkey, recvKey := MSCHAPV2.MsCHAPV2GetSendAndRecvKey([]byte(userPassword), sessions[sessionId].NTResponse)
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
				return npac

			default:
				log.Printf("[MsCHAPv2] 💥 Invalid request OpCode %s", msChapV2Packet.OpCode().String())
				npac.Code = radius.AccessReject
				return npac
			}

		case 13: // EAP-TLS
			sessionId, err := CheckRadiusSession(request)
			if err != nil {
				log.Printf("[RADIUS] 💥 error checking client session: %s", err)
				npac.Code = radius.AccessReject
				return npac
			}
			eapState := sessions[*sessionId].EapTlsState

			isAck := false
			var tlsPacket []byte
			if len(eap.Data) == 1 && eap.Data[0] == 0 {
				isAck = true
				log.Printf("[EAP-TLS] received ACK")
			} else if len(eap.Data) < 5 {
				log.Printf("[EAP-TLS] 💥 received invalid record: too small (%d bytes), value %b", len(eap.Data), eap.Data)
				//npac.Code = radius.AccessReject
				npac.Code = radius.AccessChallenge
				npac.SetAVP(radius.AVP{
					Type:  radius.State,
					Value: sessionId[:],
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
				conn, err := net.Dial("unix", p.handshakeSocketPath)
				if err != nil {
					log.Printf("[EAP-TLS] 💥 unable to connect to TLS handshake server: %s", err)
					npac.Code = radius.AccessReject
					return npac
				}
				//defer conn.Close()
				debugLen := binary.BigEndian.Uint32(eap.Data[1:5])
				log.Printf("[EAP-TLS] DEBUG flag received from client ClientHello: %08b, TLS record length = %d, packet buffer size=%d", eap.Data[0], debugLen, len(tlsPacket))

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

				reply := make([]byte, 64*1024)
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
				serverHello := tlsx.ServerHello{}
				err = serverHello.Unmarshal(eapState.TlsBuffer)
				if err != nil {
					log.Printf("[EAP-TLS] 💥 bogus ServerHello: %s", err)
				}
				log.Printf("[EAP-TLS] ServerHello: %+v", serverHello)
				cipher := serverHello.CipherSuite
				tlsVersion := tlsx.Version(serverHello.Vers).String()
				log.Printf("[EAP-TLS] ServerHello: selected %s, Cipher suite %s", tlsVersion, tlsx.CipherSuite(cipher).String())
			}

			if eapState.BufferPos == 0 || isAck {
				log.Printf("[EAP-TLS] DEBUG: current position in cached buffer of data waiting to be sent to client: %d/%d", eapState.BufferPos, len(eapState.TlsBuffer))
				npac.Code = radius.AccessChallenge
				npac.SetAVP(radius.AVP{
					Type:  radius.State,
					Value: sessionId[:],
				})

				// TODO: also support splitting ServerHello into multiple Radius packets if > 4k
				maxAttrSize := 248 // max size of a Radius attribute data
				eapPacketMaxSize := 1012
				// Size of the DATA in the current EAP packet
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
						//flagStr := bitString("10000000")
						flagByte := flagStr.AsByteSlice()
						data[0] = flagByte[0]
						log.Printf("[EAP-TLS] DEBUG: preparing EAP Packet, first byte = %08b", data[0])
						binary.BigEndian.PutUint32(data[1:5], uint32(len(eapState.TlsBuffer)))
						//binary.BigEndian.PutUint32(data[1:5], uint32(thisEapPacketSize))
						copy(data[5:], eapState.TlsBuffer[pos:(pos+maxAttrSize)])

						radiusServHelloPacket := radius.EapPacket{
							Identifier: eapId,
							Code:       radius.EapCodeRequest,
							Type:       13,
							Data:       data, //reply[pos:until],
						}

						eapResponseData = radiusServHelloPacket.Encode()
						binary.BigEndian.PutUint16(eapResponseData[2:4], uint16(thisEapPacketSize+5))

					} else if packetRead == 0 {
						data = make([]byte, maxAttrSize+1)
						//data = make([]byte, maxAttrSize+5)
						var flagStr bitString
						if addFragmentBit {
							flagStr = bitString("01000000")
							//flagStr = bitString("11000000")
						} else {
							flagStr = bitString("00000000")
							//flagStr = bitString("10000000")
						}
						flagByte := flagStr.AsByteSlice()
						data[0] = flagByte[0]
						log.Printf("[EAP-TLS] DEBUG: preparing EAP Packet, first byte = %08b", data[0])
						//binary.BigEndian.PutUint32(data[1:5], uint32(thisEapPacketSize))
						//binary.BigEndian.PutUint32(data[1:5], uint32(len(eapState.TlsBuffer)))
						copy(data[1:], eapState.TlsBuffer[pos:(pos+maxAttrSize)])
						//copy(data[5:], eapState.TlsBuffer[pos:(pos+maxAttrSize)])

						radiusServHelloPacket := radius.EapPacket{
							Identifier: eapId,
							Code:       radius.EapCodeRequest,
							Type:       13,
							Data:       data, //reply[pos:until],
						}
						eapResponseData = radiusServHelloPacket.Encode()
						binary.BigEndian.PutUint16(eapResponseData[2:4], uint16(thisEapPacketSize+5))
						//eapResponseData = data

					} else {
						log.Printf("Adding EAP data without wrapping into EAP packet")
						/*data = make([]byte, until-pos+1)
						var flagStr bitString
						if addFragmentBit {
							flagStr = bitString("01000000")
						} else {
							flagStr = bitString("00000000")
						}
						flagByte := flagStr.AsByteSlice()
						data[0] = flagByte[0]
						copy(data[1:], reply[pos:until])
						eapResponseData = data*/
						data = make([]byte, maxAttrSize)
						copy(data, eapState.TlsBuffer[pos:(pos+maxAttrSize)])
						eapResponseData = data //eapState.TlsBuffer[pos:(pos + maxAttrSize)]
					}

					log.Printf("[EAP-TLS] DEBUG: copied data from %d to %d, radius attr data size=%d", pos, pos+maxAttrSize, len(eapResponseData))
					npac.AddAVP(radius.AVP{
						Type:  radius.AttributeType(radius.EAPMessage),
						Value: eapResponseData, //radiusServHelloPacket.Encode(),
					})
					log.Printf("Pos=%d, Until=%d, maxAttrSize=%d, packetRead=%d, eapId=%d", pos, (pos + maxAttrSize), maxAttrSize, packetRead, eapId)
					pos = pos + maxAttrSize
					packetRead = packetRead + maxAttrSize
				}
				eapState.BufferPos += thisEapPacketSize
				if eapState.BufferPos == len(eapState.TlsBuffer) {
					eapState.Step = TlsServerHello
					log.Printf("[EAP-TLS] finished splitting ServerHello")
				}
				sessions[*sessionId].EapTlsState = eapState
				log.Printf("[EAP-TLS] step %v: sending ServerHello, %d bytes", eapState.Step, thisEapPacketSize)
				return npac
			}

			if eapState.Step == TlsServerHello {
				// debug
				clientHello := tlsx.ClientHello{}
				err := clientHello.Unmarshal(tlsPacket)
				if err != nil {
					log.Printf("[EAP-TLS] 💥 unable to decode ClientHello: %s", err)
					npac.Code = radius.AccessReject
					return npac
				}
				log.Printf("[EAP-TLS] 💥 UNEXPECTED ClientHello %+v", clientHello.String())
				return npac
				// end debug

				// After sending the TLS ServerHello, we should receive either an error,
				//  or the client response including the client cert
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
				reply := make([]byte, 64*1024)
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
					Value: sessionId[:],
				})
				const maxAttrSize = 248 // max size of a Radius attribute data
				for pos := 0; pos < read; pos = pos + maxAttrSize {
					until := pos + maxAttrSize
					if read-pos < maxAttrSize {
						until = read
					}
					//log.Printf("Pos=%d, Until=%d", pos, until)
					radiusServHelloPacket := radius.EapPacket{
						Identifier: eap.Identifier,
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
			}
			return npac

			/*
				// We provide a very minimal, stripped-down implementation of EAP-TLS and TLS handshake.
				// - TLS is currently limited to version 1.2 only.
				// - No downgrade/fallback support. In practice, any recent client will be fine with this.
				// - Supported cipher suites is limited to a few known secure ones (as of 2021)
				// - Only supports RSA ciphers for now.
				log.Println("[Radius] Received EAP-TLS packet")
				supportedCiphers := []tlsx.CipherSuite{
					0xCC13, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
					0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
					0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
					0xC028, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
					0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
					0xC027, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
				}

				goPacketOpts := gopacket.DecodeOptions{
					SkipDecodeRecovery:       true,
					DecodeStreamsAsDatagrams: false,
				}
				eapData := request.GetEAPMessage().Data
				if len(eapData) < 5 {
					log.Printf("[EAP-TLS] invalid EAP TLS record: too small")
					npac.Code = radius.AccessReject
					return npac
				}

				tlsPacket := eapData[5:]
				if len(tlsPacket) < 5 {
					log.Printf("[EAP-TLS] invalid TLS record: too small")
					npac.Code = radius.AccessReject
					return npac
				}

				pkg := gopacket.NewPacket(tlsPacket, layers.LayerTypeTLS, goPacketOpts)
				if pkg.ErrorLayer() != nil {
					log.Printf("[EAP-TLS] invalid TLS record: %s", pkg.ErrorLayer().Error())
					npac.Code = radius.AccessReject
					return npac
				}
				tlsLayer := pkg.Layer(layers.LayerTypeTLS)
				if tlsLayer == nil {
					log.Printf("[EAP-TLS] invalid TLS record")
					npac.Code = radius.AccessReject
					return npac
				}

				tls, _ := tlsLayer.(*layers.TLS)
				if tls.Handshake != nil && len(tls.Handshake) > 0 && tls.Handshake[0].TLSRecordHeader.ContentType == layers.TLSHandshake {
					clientHello := tlsx.ClientHello{}
					err := clientHello.Unmarshal(tlsPacket)
					if err != nil {
						log.Printf("[EAP-TLS] unable to decode ClientHello: %s", err)
						npac.Code = radius.AccessReject
						return npac
					}
					log.Printf("[EAP-TLS] ClientHello %+v", clientHello.String())
					// TODO: This doesn't work for TLS 1.3. Fix when we imp,ement support for 1.3
					log.Printf("[EAP-TLS] received %s client handshake", clientHello.HandshakeVersion.String())

					if clientHello.HandshakeVersion < tlsx.VerTLS12 {
						log.Printf("[EAP-TLS] Client doesn't support %s", tlsx.VerTLS12.String())
						npac.Code = radius.AccessReject
						return npac
					}

					// [rfc5216] 2.4 During the EAP-TLS conversation the EAP peer and server MUST
					// NOT request or negotiate compression
					supportsNullCompression := false
					for _, compressionMethod := range clientHello.CompressMethods {
						if compressionMethod == 0 {
							supportsNullCompression = true
						}
					}
					if !supportsNullCompression {
						log.Printf("[EAP-TLS] Client doesn't support uncompressed connections")
						npac.Code = radius.AccessReject
						return npac
					}

					if clientHello.SessionIDLen == 0 || clientHello.SessionIDLen > 32 {
						log.Printf("[EAP-TLS] Client sent invalid Session ID (length %d)", clientHello.SessionIDLen)
						//npac.Code = radius.AccessReject
						//return npac
					}
					var cipher *tlsx.CipherSuite
					for _, ourCipher := range supportedCiphers {
						for _, clientCipher := range clientHello.CipherSuites {
							if ourCipher == clientCipher {
								cipher = &ourCipher
								break
							}
						}
						if cipher != nil {
							break
						}
					}
					if cipher == nil {
						log.Printf("[EAP-TLS] Client doesn't support any of our ciphers %v", supportedCiphers)
						npac.Code = radius.AccessReject
						return npac
					}
					log.Printf("[EAP-TLS] Will use cipher suite %s", cipher.String())
					serverHello := tlsx.ServerHello{
						SupportedVersion:             uint16(tlsx.VerTLS12),
						SecureRenegotiationSupported: false,
						TicketSupported:              false,
						OCSPStapling:                 false,
						SessionID:                    clientHello.SessionID,
						Random:                       make([]byte, 32),
						CompressionMethod:            0,
						CipherSuite:                  uint16(*cipher),
					}
					log.Printf("our ServerHello is %s", serverHello.String())
				}*/

			//log.Printf("££££££££££ tls=%+v", tls)
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

func getTLSServerConfig() *tls.Config {
	serverCert, err := tls.LoadX509KeyPair("/tmp/server.crt", "/tmp/server.key")
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
	//log.Printf("[EAP-TLS] will present ourselves as a TLS server with cert %s")
	log.Printf("[EAP-TLS] will accept client certificates signed by CA %s", cert.Subject.String())

	return &tls.Config{
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,

		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		/*CipherSuites: []uint16{
			//tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},*/
		Certificates: []tls.Certificate{
			serverCert,
		},
		ClientAuth:                  tls.RequireAndVerifyClientCert,
		ClientCAs:                   clientCertCAs,
		DynamicRecordSizingDisabled: true,
		//SessionTicketsDisabled: false,
		//Renegotiation:          tls.RenegotiateOnceAsClient,
		//NextProtos: ,
		//RootCAs: ,
	}
}

func CheckRadiusSession(request *radius.Packet) (*[32]byte, error) {
	sessionId := [32]byte{}
	stateAVP := request.GetAVP(radius.State)
	if stateAVP != nil {
		copy(sessionId[:], stateAVP.Value)
		log.Printf("[RADIUS] DEBUG: received State/Session ID %v", sessionId)
		if _, ok := sessions[sessionId]; !ok {
			return nil, fmt.Errorf("Invalid State/Session ID %s", sessionId)
		}
	} else {
		return nil, fmt.Errorf("No State/Session ID")
	}
	return &sessionId, nil
}
func sendMSCHAPv2Challenge(userName string, eap *radius.EapPacket, npac *radius.Packet) {
	mschapV2Challenge := [16]byte{}
	_, err := rand.Read(mschapV2Challenge[:])
	if err != nil {
		log.Printf("unable to generate random data for MS-CHAPv2 challenge: %s", err)
		npac.Code = radius.AccessReject
		return
	}
	sessionId := [32]byte{}
	_, err = rand.Read(sessionId[:])
	if err != nil {
		log.Printf("unable to generate random data for MS-CHAPv2 session ID: %s", err)
		npac.Code = radius.AccessReject
		return
	}

	sessions[sessionId] = &RadiusSession{
		Challenge: mschapV2Challenge,
	}

	npac.Code = radius.AccessChallenge
	npac.SetAVP(radius.AVP{
		Type:  radius.State,
		Value: sessionId[:],
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

	return
}

func sendTLSRequest(userName string, eap *radius.EapPacket, npac *radius.Packet, request *radius.Packet) {
	npac.Code = radius.AccessChallenge

	// Session not supposed to exist at this point
	var sessionId [32]byte
	_, err := rand.Read(sessionId[:])
	if err != nil {
		log.Printf("[EAP-TLS] 💥 unable to generate random data for session ID: %s", err)
		npac.Code = radius.AccessReject
		return
	}
	sessions[sessionId] = &RadiusSession{}

	npac.SetAVP(radius.AVP{
		Type:  radius.State,
		Value: sessionId[:],
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
	//npac.Identifier++
	sessions[sessionId].EapTlsState = EapTlsState{
		Step: TlsStart,
	}

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
	sessionId := [64]byte{}
	_, err := rand.Read(sessionId[:])
	if err != nil {
		return "", err
	}
	str := base64.RawURLEncoding.EncodeToString(sessionId[:])
	return str, nil
}
