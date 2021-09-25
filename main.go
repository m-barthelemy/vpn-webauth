//go:generate pkger
package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/bronze1man/radius"
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

	s := radius.NewServer("0.0.0.0:5022", "mamie", radiusService{})
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	errChan := make(chan error)
	go func() {
		fmt.Println("waiting for packets...")
		err := s.ListenAndServe()
		if err != nil {
			errChan <- err
		}
	}()
	select {
	case <-signalChan:
		log.Println("stopping server...")
		s.Stop()
	case err := <-errChan:
		log.Println("[ERR] %v", err.Error())
	}

	startServer(&config, routes.New(&config, db))

}

//test
type radiusService struct{}

// TODO: protect/lock for concurrent access
var sessions = make(map[[18]byte][16]byte)

// Check https://github.com/keysonZZZ/kmg/blob/master/third/kmgRadius/Auth.go
// for EAP and MSCHAP challenge response
func (p radiusService) RadiusHandle(request *radius.Packet) *radius.Packet {
	/*eap := request.GetEAPMessage()
	if eap != nil {
		log.Printf("Message kind is EAP, type %s, identifier %d, data size %d", eap.Type.String(), eap.Identifier, len(eap.Data))
		log.Printf("EAP Packet: %s", eap.String()) 

	}*/
	
	// A pretty print of the request.
	log.Printf("---------------------------------------------------------")
	log.Printf("[Authenticate] %s\n", request.String())
	npac := request.Reply()
	switch request.Code {
	case radius.AccessRequest:
		eap := request.GetEAPMessage()
		if eap == nil {
			log.Printf("Received non-EAP request from %s (%s). Only EAP is supported.", request.ClientAddr, request.GetNASIdentifier())
			npac.Code = radius.AccessReject
			npac.AddAVP(radius.AVP{Type: radius.ReplyMessage, Value: []byte("only EAP is supported")})
			return npac
		}
		
		log.Printf("[ >>>>>>>> EAP Begin] Message kind is EAP, type %s, identifier %d, data size %d", eap.Type.String(), eap.Identifier, len(eap.Data))
		log.Printf("EAP Packet: %s", eap.String())
		switch eap.Type {
		case radius.EapTypeIdentity:
			//mschapV2Challenge := make([]byte, 16)
			mschapV2Challenge := [16]byte{}
			_, err := rand.Read(mschapV2Challenge[:])
			if err != nil {
				log.Fatalf("unable to generate random data for MS-CHAPv2 challenge: %s", err)
				npac.Code = radius.AccessReject
				return npac
			}
			sessionId := [18]byte{} //make([]byte, 18)
			_, err = rand.Read(sessionId[:])
			if err != nil {
				log.Fatalf("unable to generate random data for MS-CHAPv2 session ID: %s", err)
				npac.Code = radius.AccessReject
				return npac
			}
			sessions[sessionId] = mschapV2Challenge
			// TODO: store session ID

			npac.Code = radius.AccessChallenge
			npac.SetAVP(radius.AVP{
				Type:  radius.State,
				Value: sessionId[:],
			})

			challengeP := MSCHAPV2.ChallengePacket{
				Identifier: eap.Identifier,
				Challenge:  mschapV2Challenge,
				Name:       request.GetUsername(),
			}
			/*challengeP := radius.MsChapV2Packet{
				OpCode: radius.MsChapV2OpCodeChallenge,
				Data:   mschapV2Challenge,
				//Eap:    eap,
			}*/
			//challengeP.
			challengeEAPPacket := radius.EapPacket{
				Identifier: eap.Identifier,
				Code:       radius.EapCodeRequest,
				Type:       radius.EapTypeMSCHAPV2,
				//Data:       challengeP.Data,
				Data: challengeP.Encode(),
			}

			npac.AddAVP(radius.AVP{
				Type:  radius.AttributeType(radius.EAPMessage),
				Value: challengeEAPPacket.Encode(),
			})
			log.Printf("Sending MSCHAPv2 challenge as a response to EAP identity request")
			return npac

		case radius.EapTypeMSCHAPV2:
			mschapv2, err := radius.MsChapV2PacketFromEap(eap)
			if err != nil {
				log.Fatalf("[MsCHAPv2] unable to parse expected EAP packet as MS-CHAPv2")
			}
			log.Printf("[MsCHAPv2] Received '%s' OpCode", mschapv2.OpCode.String())
			//log.Printf("[MsCHAPv2] Packet dump: %s", mschapv2.String())
			if mschapv2.OpCode != radius.MsChapV2OpCodeResponse {
				log.Fatalf("[MsCHAPv2] Invalid request: expected %s, but got %s", radius.MsChapV2OpCodeResponse.String(), mschapv2.OpCode.String())
				npac.Code = radius.AccessReject
				return npac
			}

			log.Printf("[MsCHAPv2] RESPONSE!!!!")
			stateAVP := request.GetAVP(radius.State)

			sessionId := [18]byte{}
			copy(stateAVP.Value, sessionId[:])
			//sessionId = stateAVP.Value[:]
			// TODO: Check and validate session
			log.Printf("[MsCHAPv2] State AVP value is %s, State/Session ID is %s, challenge: %s", stateAVP.Value, sessionId, sessions[sessionId])

			msChapV2Packet, err := MSCHAPV2.Decode(eap.Data)
			if err != nil {
				log.Fatalf("[MsCHAPv2] unable to decode packet: %s", err)
				npac.Code = radius.AccessReject
				return npac
			}
			log.Printf(">>>> Successfully decoded msChapV2Packet: %s", msChapV2Packet.String())
			//radius.MSCHAPV2Packet
			//msChapV2Packet := eap.(*radius.MSCHAPV2Packet).MSCHAPV2
			
			//nTResponse := msChapV2Packet.(*MSCHAPV2.ResponsePacket).NTResponse

			// DEBUG
			var fakeChallenge [16]byte
			for k, v := range sessions {
				log.Printf("SESSIONS: key %s, value %s", k, v)
				fakeChallenge = v
			}
			log.Printf("SESSIONS: FAKECHALLENGE = %s", fakeChallenge)

			successPacket := MSCHAPV2.ReplySuccessPacket(&MSCHAPV2.ReplySuccessPacketRequest{
				AuthenticatorChallenge: fakeChallenge, //sessions[sessionId],
				Response:               msChapV2Packet.(*MSCHAPV2.ResponsePacket),
				Username:               []byte(request.GetUsername()),
				Password:               []byte("mamie"),
				Message:                "success",
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

			log.Printf("Sending Access-Challenge again in response to radius.EapTypeMSCHAPV2 Response")
			npac.Code = radius.AccessAccept
			//npac.Code = radius.AccessChallenge
			return npac
		default:
			log.Fatalf("•••••• Received unsupported EAP packet type %s", eap.Type.String())
			npac.Code = radius.AccessReject
			return npac
		}
		/*mschapv2, err := radius.MsChapV2PacketFromEap(eap)
		if err != nil {
			log.Printf("EAP packet is not MS-CHAPv2")
		}*/

		// check username and password
		if request.GetUsername() == "matthieu.barthelemy" { //&& request.GetPassword() == "a" {
			log.Printf("Username valid")
			//npac.Code = radius.AccessAccept
			//npac.Code = radius.AccessChallenge

			//request.SetAVP()
			//eap := npac.GetEAPMessage()
			//log.Printf("EAP authentication type %s", eap.String())
			// add Vendor-specific attribute - Vendor Cisco (code 9) Attribute h323-remote-address (code 23)
			//npac.AddVSA(radius.VSA{Vendor: 9, Type: 23, Value: []byte("10.20.30.40")})
			//npac.AddAVP(radius.AVP{Type: radius.ReplyMessage, Value: []byte("Welcome!")})
		} else {
			npac.Code = radius.AccessReject
			npac.AddAVP(radius.AVP{Type: radius.ReplyMessage, Value: []byte("you dick!")})
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
