//go:generate pkger
package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"

	"github.com/bronze1man/radius"
	"github.com/dreadl0ck/tlsx"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

	s := radius.NewServer("0.0.0.0:5022", radiusSecret, &RadiusService{})
	go func() {
		fmt.Println("Starting Radius listener...")
		err := s.ListenAndServe()
		if err != nil {
			log.Fatalf("Unable to start Radius listener: %s", err)
		}
	}()

	startServer(&config, routes.New(&config, db))
}

//test
type RadiusService struct{}

const radiusSecret = "mamiemamie"

// [rfc3579] 4.3.3.  Dictionary Attacks: secret should be at least 16 characters
// TODO: require at least 24 chars
const userPassword = "mamie est conne"

type RadiusSession struct {
	Challenge  [16]byte
	NTResponse [24]byte
}

// TODO: protect/lock for concurrent access
// could also be using https://github.com/orcaman/concurrent-map
var sessions = make(map[[18]byte]*RadiusSession)
var lock = sync.RWMutex{}

// Check https://github.com/keysonZZZ/kmg/blob/master/third/kmgRadius/Auth.go
// for EAP and MSCHAP challenge response
func (p *RadiusService) RadiusHandle(request *radius.Packet) *radius.Packet {
	fmt.Println("---------------------------------------------------------")
	log.Printf("[Authenticate] %s\n", request.String())
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
		eap := request.GetEAPMessage()
		if eap == nil {
			log.Printf("[EAP] Received non-EAP request from %s (%s). Only EAP is supported.", request.ClientAddr, request.GetNASIdentifier())
			npac.Code = radius.AccessReject
			npac.AddAVP(radius.AVP{Type: radius.ReplyMessage, Value: []byte("only EAP is supported")})
			return npac
		}

		log.Printf("[EAP] Received message kind is EAP, type %s, identifier %d, data size %d", eap.Type.String(), eap.Identifier, len(eap.Data))
		log.Printf("[EAP] Packet: %s", eap.String())

		// [rfc3579] 3.2.  Message-Authenticator
		messageAuthenticator := request.GetAVP(radius.MessageAuthenticator)
		if messageAuthenticator.Value == nil {
			log.Printf("[Radius] Received EAP packet without %s attribute, discarding", radius.MessageAuthenticator.String())
			return npac
		}
		// if we have a Message-Authenticator, it is automatically validated before service.RadiusHandle is called.

		// [rfc3579] 2.6.2.  Role Reversal
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
			log.Printf("[EAP] Sending MSCHAPv2 challenge as a response to EAP identity request")
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
			sessionId := [18]byte{}
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
			// We provide a very minimal, stripped-down implementation of EAP-TLS and TLS handshake.
			// - TLS is currently limited to version 1.2 only.
			// - No downgrade/fallback support. In practice, any recent client will be fine with this.
			// - Supported cipher suites is limited to a few known secure ones (as of 2021)
			// - Only supports RSA ciphers for now.
			// - TLS compression is not supported
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
					npac.Code = radius.AccessReject
					return npac
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
					SupportedVersion:  uint16(tlsx.VerTLS12),
					SessionID:         clientHello.SessionID,
					Random:            make([]byte, 32),
					CompressionMethod: 0,
					CipherSuite:       uint16(*cipher),
				}

			}

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
		npac.Code = radius.AccessAccept
	}
	return npac
}

func sendMSCHAPv2Challenge(userName string, eap *radius.EapPacket, npac *radius.Packet) {
	mschapV2Challenge := [16]byte{}
	_, err := rand.Read(mschapV2Challenge[:])
	if err != nil {
		log.Printf("unable to generate random data for MS-CHAPv2 challenge: %s", err)
		npac.Code = radius.AccessReject
		//return npac
		return
	}
	sessionId := [18]byte{}
	_, err = rand.Read(sessionId[:])
	if err != nil {
		log.Printf("unable to generate random data for MS-CHAPv2 session ID: %s", err)
		npac.Code = radius.AccessReject
		//return npac
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

	//return npac
	return
}

// https://datatracker.ietf.org/doc/html/rfc5216#page-6
// https://datatracker.ietf.org/doc/html/rfc5216#section-2.1.1
/*
US                          VPN Client
   -------------------     -------------
                           <- EAP-Request/
                           Identity
   EAP-Response/
   Identity (MyID) ->
                           <- EAP-Request/
                           EAP-Type=EAP-TLS
                           (TLS Start)
   EAP-Response/
   EAP-Type=EAP-TLS
   (TLS client_hello)->
                           <- EAP-Request/
                           EAP-Type=EAP-TLS
                           (TLS server_hello,
                             TLS certificate,
                    [TLS server_key_exchange,]
                     TLS certificate_request,
                        TLS server_hello_done)
   EAP-Response/
   EAP-Type=EAP-TLS
   (TLS certificate,
    TLS client_key_exchange,
    TLS certificate_verify,
    TLS change_cipher_spec,
    TLS finished) ->
                           <- EAP-Request/
                           EAP-Type=EAP-TLS
                           (TLS change_cipher_spec,
                            TLS finished)
   EAP-Response/
   EAP-Type=EAP-TLS ->
                           <- EAP-Success
*/
func sendTLSRequest(userName string, eap *radius.EapPacket, npac *radius.Packet, request *radius.Packet) {
	npac.Code = radius.AccessChallenge

	sessionId := [18]byte{}

	var hasSession bool = false
	stateAVP := request.GetAVP(radius.State)
	if stateAVP != nil {
		copy(sessionId[:], stateAVP.Value)
		log.Printf("[MsCHAPv2] Received State/Session ID %v", sessionId)
		if _, ok := sessions[sessionId]; !ok {
			log.Printf("Invalid State/Session ID %s", sessionId)
			npac.Code = radius.AccessReject
			return
		}
		hasSession = true
	} else {
		_, err := rand.Read(sessionId[:])
		if err != nil {
			log.Printf("unable to generate random data for MS-CHAPv2 session ID: %s", err)
			npac.Code = radius.AccessReject
			return
		}
		sessions[sessionId] = &RadiusSession{}
	}

	npac.SetAVP(radius.AVP{
		Type:  radius.State,
		Value: sessionId[:],
	})

	if !hasSession {
		eapTlsInitResponse := radius.EapPacket{
			Identifier: eap.Identifier,
			Code:       radius.EapCodeRequest,
			Type:       13, //radius.EapTypeIdentity,
			Data:       []byte(userName),
		}
		npac.AddAVP(radius.AVP{
			Type:  radius.AttributeType(radius.EAPMessage),
			Value: eapTlsInitResponse.Encode(),
		})
	} else {
		log.Println(">>> EAP DATA:", request.GetEAPMessage().Data)
		b := make([]byte, 1)
		var b13 byte = 13
		b[0] = b13

		flagStr := bitString("00100000")
		flagByte := flagStr.AsByteSlice()
		data := append(b, flagByte...)
		eapTlsInitResponse := radius.EapPacket{
			Identifier: eap.Identifier,
			Code:       radius.EapCodeRequest,
			Type:       13, //radius.EapTypeIdentity,
			Data:       data,
		}
		npac.AddAVP(radius.AVP{
			Type:  radius.AttributeType(radius.EAPMessage),
			Value: eapTlsInitResponse.Encode(),
		})
	}

	/*challengeEAPPacket := radius.EapPacket{
		Identifier: eap.Identifier,
		Code:       radius.EapCodeRequest,
		Type:       13, //radius.EapTypeIdentity,
		Data:       []byte{},
	}

	npac.AddAVP(radius.AVP{
		Type:  radius.AttributeType(radius.EAPMessage),
		Value: challengeEAPPacket.Encode(),
	})*/

	//return npac
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
